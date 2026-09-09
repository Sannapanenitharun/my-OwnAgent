package pricing

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AWS Price List Bulk API.
//
// WHY THE BULK API AND NOT THE QUERY API. AWS publishes prices two ways. The
// Query API (api.pricing.us-east-1.amazonaws.com) answers filtered lookups and
// is the obvious fit -- but it requires SigV4 request signing and IAM
// credentials, which means every deployment needs a pricing:GetProducts policy
// before it can show a number. The Bulk API is a plain unauthenticated HTTPS
// GET. It costs a much larger download and buys a component that works with no
// credentials, no IAM policy, and no AWS account at all.
//
// THE FILE IS 300 MB, so it is streamed and filtered, never held. A region's
// price list contains every instance type crossed with every operating system,
// tenancy, licence model and purchase option -- roughly 1.5 million rows to
// yield a few hundred usable rates.
//
// THE FILTER IS THE WHOLE CORRECTNESS STORY. Eight fields must match, and
// getting any one wrong returns a real price for the wrong thing, which is far
// worse than returning nothing. A first attempt at this matched "m5.large" and
// "Linux" as substrings and returned $0.128/hr -- the price of a THREE-YEAR
// RESERVED instance running "Linux with SQL Server Web". The right answer was
// $0.096. It was wrong by a third, in the plausible direction, and looked
// entirely fine.
const awsPriceListBase = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws"

// AWSRegionURL is the CSV price list for one region.
func AWSRegionURL(region string) string {
	return fmt.Sprintf("%s/AmazonEC2/current/%s/index.csv", awsPriceListBase, region)
}

// Column names in the AWS price list CSV. They are looked up by NAME rather
// than by position: the file carries 93 columns and AWS adds more over time, so
// a hardcoded index is a silent mis-read waiting for the next publication.
const (
	colSKU          = "SKU"
	colTermType     = "TermType"
	colUnit         = "Unit"
	colPricePerUnit = "PricePerUnit"
	colCurrency     = "Currency"
	colProductFam   = "Product Family"
	colInstanceType = "Instance Type"
	colTenancy      = "Tenancy"
	colOS           = "Operating System"
	colLicense      = "License Model"
	colPreInstalled = "Pre Installed S/W"
	colCapacity     = "CapacityStatus"
	colVCPU         = "vCPU"
	colMemory       = "Memory"
)

// The eight values that together mean "the plain on-demand hourly price of a
// Linux instance", and nothing else.
const (
	wantTermType     = "OnDemand"
	wantProductFam   = "Compute Instance"
	wantOS           = "Linux"
	wantTenancy      = "Shared"              // not Dedicated or Host
	wantLicense      = "No License required" // not a bundled Windows/RHEL licence
	wantPreInstalled = "NA"                  // not SQL Server et al
	wantCapacity     = "Used"                // not an unused capacity reservation
	wantUnit         = "Hrs"
	wantCurrency     = "USD"
)

// Bounds. The input is 300 MB of somebody else's data.
const (
	// maxPriceListRows caps the scan. A region file holds roughly 1.5M rows;
	// this is generous enough not to truncate a real file and finite enough
	// that a malformed or hostile stream cannot spin forever.
	maxPriceListRows = 8 << 20

	// maxRatesPerCatalog caps what is retained. AWS publishes a few hundred
	// instance types per region.
	maxRatesPerCatalog = 8192

	// maxCSVFieldBytes bounds one field. PriceDescription is the longest and
	// runs to a couple of hundred characters.
	maxCSVFieldBytes = 64 << 10
)

// FetchAWSRegion downloads and filters the price list for one region.
//
// The caller owns the deadline. This transfers hundreds of megabytes and a
// short timeout will simply fail; a sensible ctx allows several minutes.
func FetchAWSRegion(ctx context.Context, hc *http.Client, region string) (*Catalog, error) {
	region = strings.TrimSpace(region)
	if region == "" {
		return nil, fmt.Errorf("pricing: empty region")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, AWSRegionURL(region), nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A wrong region name yields 403 rather than 404, which reads as a
		// permissions problem and is not one.
		return nil, fmt.Errorf("pricing: %s returned %s (check the region name)",
			AWSRegionURL(region), resp.Status)
	}
	return ParseAWSPriceList(resp.Body, region)
}

// ParseAWSPriceList streams a price list CSV and returns the on-demand Linux
// rates in it.
//
// Memory stays flat regardless of input size: one row is held at a time and
// only matching rows are retained.
func ParseAWSPriceList(r io.Reader, region string) (*Catalog, error) {
	cr := csv.NewReader(r)
	// The file opens with five two-column metadata lines before a 93-column
	// header, so a fixed field count would reject it on line one.
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	cr.LazyQuotes = true

	cat := &Catalog{
		Provider: "aws",
		Region:   region,
		Fetched:  time.Now().UTC(),
		Rates:    map[string]Rate{},
	}

	var idx map[string]int
	rows := 0
	duplicates := 0

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed line late in a 300 MB file should not discard the
			// rates already recovered from it.
			if len(cat.Rates) > 0 {
				break
			}
			return nil, fmt.Errorf("pricing: parsing %s price list: %w", region, err)
		}
		rows++
		if rows > maxPriceListRows {
			break
		}

		if idx == nil {
			// Metadata lines come first; the publication date is on one of
			// them and is worth keeping.
			if len(rec) == 2 && rec[0] == "Publication Date" {
				if t, perr := time.Parse(time.RFC3339, rec[1]); perr == nil {
					cat.Published = t.UTC()
				}
				continue
			}
			if looksLikeHeader(rec) {
				idx = make(map[string]int, len(rec))
				for i, name := range rec {
					idx[name] = i
				}
			}
			continue
		}

		get := func(name string) string {
			i, ok := idx[name]
			if !ok || i >= len(rec) {
				return ""
			}
			v := rec[i]
			if len(v) > maxCSVFieldBytes {
				return ""
			}
			return v
		}

		if get(colTermType) != wantTermType ||
			get(colProductFam) != wantProductFam ||
			get(colOS) != wantOS ||
			get(colTenancy) != wantTenancy ||
			get(colLicense) != wantLicense ||
			get(colPreInstalled) != wantPreInstalled ||
			get(colCapacity) != wantCapacity ||
			get(colUnit) != wantUnit ||
			get(colCurrency) != wantCurrency {
			continue
		}

		itype := strings.TrimSpace(get(colInstanceType))
		if itype == "" {
			continue
		}
		price, perr := strconv.ParseFloat(strings.TrimSpace(get(colPricePerUnit)), 64)
		if perr != nil || price <= 0 {
			// A zero on-demand rate is not a free instance, it is a row this
			// filter should not have matched. Costing something at zero is
			// worse than having no rate for it, because zero looks like an
			// answer.
			continue
		}
		if _, seen := cat.Rates[itype]; seen {
			// After a correct filter each instance type appears once. More
			// than once means the filter admitted something it should not,
			// so it is counted rather than silently overwritten.
			duplicates++
			continue
		}
		if len(cat.Rates) >= maxRatesPerCatalog {
			break
		}
		cat.Rates[itype] = Rate{
			Provider:     "aws",
			Region:       region,
			InstanceType: itype,
			USDPerHour:   price,
			VCPU:         parseVCPU(get(colVCPU)),
			MemoryGiB:    parseMemoryGiB(get(colMemory)),
		}
	}

	if idx == nil {
		return nil, fmt.Errorf("pricing: no header row in %s price list", region)
	}
	if len(cat.Rates) == 0 {
		return nil, fmt.Errorf("pricing: %s price list yielded no on-demand Linux rates from %d rows", region, rows)
	}
	if duplicates > 0 {
		return cat, fmt.Errorf("pricing: %s price list had %d duplicate instance types after filtering; rates may be wrong", region, duplicates)
	}
	return cat, nil
}

// looksLikeHeader identifies the header row by the columns it CONTAINS rather
// than by what sits in position zero.
//
// The first version of this asked whether rec[0] == "SKU", which is positional
// detection sitting directly beneath a comment claiming the parser is not
// positional. AWS has only ever appended columns, so it would probably have
// held -- but "probably" is what the rest of this file is written to avoid, and
// a header that is not recognised means no rates at all.
func looksLikeHeader(rec []string) bool {
	if len(rec) < 10 {
		return false
	}
	found := 0
	for _, name := range rec {
		switch name {
		case colSKU, colTermType, colPricePerUnit, colInstanceType:
			found++
		}
	}
	return found == 4
}

// parseVCPU reads the vCPU column, which is a plain integer or empty.
func parseVCPU(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseMemoryGiB reads the Memory column, which is written "8 GiB", sometimes
// "NA", and occasionally with a thousands separator ("1,024 GiB").
func parseMemoryGiB(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "NA" {
		return 0
	}
	s = strings.ReplaceAll(s, ",", "")
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
