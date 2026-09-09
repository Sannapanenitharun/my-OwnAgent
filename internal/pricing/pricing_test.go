package pricing

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"
)

func sampleCatalog(t *testing.T) *Catalog {
	t.Helper()
	f, err := os.Open("testdata/aws_price_sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cat, err := ParseAWSPriceList(f, "us-east-1")
	if err != nil {
		t.Fatalf("ParseAWSPriceList: %v", err)
	}
	return cat
}

// TestTheFilterPicksTheOnDemandLinuxRate is the test this package exists for.
//
// testdata holds real rows from the live AWS price list, including four decoys
// that are all m5.large: a 3-year Reserved rate at $0.053, another at $0.128, a
// $0.00 all-upfront row, and a $1393 upfront FEE whose unit is "Quantity"
// rather than "Hrs". A filter that is wrong in any of eight fields returns one
// of those, and every one of them looks like a plausible hourly price.
//
// The correct answer is $0.096, which is what AWS publishes for m5.large
// on-demand Linux in us-east-1.
func TestTheFilterPicksTheOnDemandLinuxRate(t *testing.T) {
	cat := sampleCatalog(t)

	r, ok := cat.Lookup("m5.large")
	if !ok {
		t.Fatal("m5.large not found")
	}
	if r.USDPerHour != 0.096 {
		t.Errorf("m5.large = $%.4f/hr, want $0.0960", r.USDPerHour)
		switch r.USDPerHour {
		case 0.128, 0.053:
			t.Error("  ^ that is a RESERVED rate: the TermType filter is not applied")
		case 1393:
			t.Error("  ^ that is an upfront FEE: the Unit filter is not applied")
		case 0:
			t.Error("  ^ that is an all-upfront row: zero prices are not being rejected")
		}
	}
	if r.VCPU != 2 || r.MemoryGiB != 8 {
		t.Errorf("m5.large shape = %d vCPU / %g GiB, want 2 / 8", r.VCPU, r.MemoryGiB)
	}
	if r.Region != "us-east-1" || r.Provider != "aws" {
		t.Errorf("rate = %+v", r)
	}
}

func TestEveryRateInTheSample(t *testing.T) {
	cat := sampleCatalog(t)
	want := map[string]float64{
		"m5.large":  0.096,
		"m5.xlarge": 0.192,
		"c5.xlarge": 0.170,
		"t3.medium": 0.0416,
		"t3.micro":  0.0104,
	}
	for itype, price := range want {
		got, ok := cat.Lookup(itype)
		if !ok {
			t.Errorf("%s missing from catalog", itype)
			continue
		}
		if got.USDPerHour != price {
			t.Errorf("%s = $%.4f, want $%.4f", itype, got.USDPerHour, price)
		}
	}
	if len(cat.Rates) != len(want) {
		t.Errorf("catalog holds %d rates, want %d (%v) -- a decoy row was accepted",
			len(cat.Rates), len(want), cat.InstanceTypes())
	}
}

// TestPublicationDateIsRead. A stale price list and a stale fetch are different
// problems, so both timestamps are kept.
func TestPublicationDateIsRead(t *testing.T) {
	cat := sampleCatalog(t)
	want := time.Date(2026, 9, 9, 0, 46, 5, 0, time.UTC)
	if !cat.Published.Equal(want) {
		t.Errorf("Published = %v, want %v", cat.Published, want)
	}
	if cat.Fetched.IsZero() {
		t.Error("Fetched was not stamped")
	}
}

// TestColumnsAreFoundByNameNotPosition. The file carries 93 columns and AWS
// adds more over time; a hardcoded index becomes a silent mis-read at the next
// publication.
func TestColumnsAreFoundByNameNotPosition(t *testing.T) {
	body, err := os.ReadFile("testdata/aws_price_sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	in := csv.NewReader(strings.NewReader(string(body)))
	in.FieldsPerRecord = -1
	in.LazyQuotes = true
	recs, err := in.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	// Insert a new leading column into every row, exactly as a new AWS field
	// would arrive. Every index shifts by one; nothing about the data changes.
	var buf strings.Builder
	w := csv.NewWriter(&buf)
	for i, rec := range recs {
		lead := "whatever"
		if len(rec) > 10 {
			lead = "NewAWSColumn"
		}
		if i < 5 {
			lead = "meta"
		}
		if err := w.Write(append([]string{lead}, rec...)); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()

	cat, err := ParseAWSPriceList(strings.NewReader(buf.String()), "us-east-1")
	if err != nil {
		t.Fatalf("a new leading column broke the parser: %v", err)
	}
	if r, ok := cat.Lookup("m5.large"); !ok || r.USDPerHour != 0.096 {
		t.Errorf("after inserting a column, m5.large = %+v (ok=%v), want $0.0960", r, ok)
	}
}

// TestBadInputFailsLoudly. An empty catalog returned with no error would show
// as "$0.00" everywhere downstream, which reads as free rather than unknown.
func TestBadInputFailsLoudly(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"no header":        "\"FormatVersion\",\"v1.0\"\n\"OfferCode\",\"AmazonEC2\"\n",
		"header no rows":   "\"SKU\",\"TermType\",\"Unit\",\"PricePerUnit\"\n",
		"nothing matching": "\"SKU\",\"TermType\",\"Unit\",\"PricePerUnit\"\n\"X\",\"Reserved\",\"Hrs\",\"1.0\"\n",
	}
	for name, body := range cases {
		if _, err := ParseAWSPriceList(strings.NewReader(body), "us-east-1"); err == nil {
			t.Errorf("%s: parsed without error; an empty catalog must be an error, not $0.00", name)
		}
	}
}

func TestParseMemoryGiB(t *testing.T) {
	cases := map[string]float64{
		"8 GiB":     8,
		"1,024 GiB": 1024,
		"0.5 GiB":   0.5,
		"NA":        0,
		"":          0,
		"garbage":   0,
	}
	for in, want := range cases {
		if got := parseMemoryGiB(in); got != want {
			t.Errorf("parseMemoryGiB(%q) = %g, want %g", in, got, want)
		}
	}
}

func TestParseVCPU(t *testing.T) {
	cases := map[string]int{"2": 2, "96": 96, "": 0, "NA": 0, "-1": 0}
	for in, want := range cases {
		if got := parseVCPU(in); got != want {
			t.Errorf("parseVCPU(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSetLookup(t *testing.T) {
	s := NewSet()
	if _, ok := s.Lookup("us-east-1", "m5.large"); ok {
		t.Error("an empty set returned a rate")
	}
	s.Put(sampleCatalog(t))
	if r, ok := s.Lookup("us-east-1", "m5.large"); !ok || r.USDPerHour != 0.096 {
		t.Errorf("lookup = %+v ok=%v", r, ok)
	}
	// A region we have no catalog for must miss, not fall back to another
	// region's prices -- eu-west-1 is dearer than us-east-1 and silently
	// substituting one for the other is a wrong number that looks right.
	if _, ok := s.Lookup("eu-west-1", "m5.large"); ok {
		t.Error("a missing region returned a rate from a different region")
	}
	if got := s.Regions(); len(got) != 1 || got[0] != "us-east-1" {
		t.Errorf("Regions() = %v", got)
	}
}

func TestNilSafety(t *testing.T) {
	var c *Catalog
	if _, ok := c.Lookup("m5.large"); ok {
		t.Error("nil catalog returned a rate")
	}
	if c.Age(time.Now()) != 0 || c.InstanceTypes() != nil {
		t.Error("nil catalog misbehaved")
	}
	var s *Set
	if _, ok := s.Lookup("us-east-1", "m5.large"); ok {
		t.Error("nil set returned a rate")
	}
}

func TestAWSRegionURL(t *testing.T) {
	got := AWSRegionURL("eu-west-2")
	want := "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/eu-west-2/index.csv"
	if got != want {
		t.Errorf("AWSRegionURL = %q", got)
	}
}
