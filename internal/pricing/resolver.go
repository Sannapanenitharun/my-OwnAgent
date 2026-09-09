package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver answers rate lookups, fetching and caching price lists as needed.
//
// THE CENTRAL RULE: A LOOKUP NEVER BLOCKS ON A DOWNLOAD. Fetching a region's
// price list transfers 300 MB and takes minutes. Doing that inside a request
// that is rendering a page would hang the page, and doing it once per lookup
// would hang it repeatedly. So Rate() answers only from what is already in
// memory or on disk, and a miss SCHEDULES a fetch and reports "no rate yet".
// The cost of that is a first render with no prices on it. The alternative is
// a first render that never arrives.
//
// A price list changes rarely -- AWS republishes monthly at most -- so a cache
// measured in days is not a compromise, it is the correct refresh rate.
type Resolver struct {
	dir    string
	hc     *http.Client
	maxAge time.Duration
	now    func() time.Time

	// fetch is the price-list retrieval, injectable so the resolver's caching,
	// scheduling and failure behaviour can be tested without moving 300 MB.
	fetch func(context.Context, *http.Client, string) (*Catalog, error)

	mu      sync.Mutex
	set     *Set
	pending map[string]bool
	// failed records regions whose fetch failed, so a permanently bad region
	// name does not schedule a 300 MB download on every page render.
	failed map[string]time.Time
	errs   map[string]string
}

const (
	// defaultMaxAge is how long a cached price list is trusted. Providers
	// republish monthly; a fortnight keeps prices current without re-fetching
	// hundreds of megabytes for a number that has not moved.
	defaultMaxAge = 14 * 24 * time.Hour

	// retryAfterFailure throttles retries of a region that failed. Long
	// enough that a typo in a region name is not a repeated download,
	// short enough that a transient outage heals within an hour.
	retryAfterFailure = 30 * time.Minute

	// maxCachedRegions bounds the resolver. A fleet spans a handful of
	// regions; anything beyond this is a misconfiguration, not a deployment.
	maxCachedRegions = 32
)

// NewResolver creates a resolver caching under dir. An empty dir disables the
// disk cache and keeps catalogs in memory only.
func NewResolver(dir string, hc *http.Client) *Resolver {
	if hc == nil {
		// A generous timeout: this transfers hundreds of megabytes.
		hc = &http.Client{Timeout: 15 * time.Minute}
	}
	return &Resolver{
		dir:     strings.TrimSpace(dir),
		hc:      hc,
		fetch:   FetchAWSRegion,
		maxAge:  defaultMaxAge,
		now:     time.Now,
		set:     NewSet(),
		pending: map[string]bool{},
		failed:  map[string]time.Time{},
		errs:    map[string]string{},
	}
}

// Rate returns the hourly rate for a region and instance type.
//
// It never blocks. A miss schedules a background fetch and returns false; the
// caller shows "no estimate" and gets a number on a later render.
func (r *Resolver) Rate(ctx context.Context, region, instanceType string) (Rate, bool) {
	region = strings.TrimSpace(region)
	instanceType = strings.TrimSpace(instanceType)
	if region == "" || instanceType == "" {
		return Rate{}, false
	}

	r.mu.Lock()
	cat, have := r.set.Catalog(region)
	fresh := have && cat.Age(r.now()) < r.maxAge
	r.mu.Unlock()

	if fresh {
		return cat.Lookup(instanceType)
	}
	if !have && r.loadFromDisk(region) {
		r.mu.Lock()
		cat, have = r.set.Catalog(region)
		r.mu.Unlock()
		if have && cat.Age(r.now()) < r.maxAge {
			return cat.Lookup(instanceType)
		}
	}

	r.schedule(region)
	if have {
		// Stale beats nothing: last month's list price is a better estimate
		// than no estimate, and the refresh is already running.
		return cat.Lookup(instanceType)
	}
	return Rate{}, false
}

// schedule starts one background fetch per region, at most.
//
// It takes no context on purpose. The obvious signature accepts the caller's
// context, and the caller is an HTTP request that finishes in milliseconds
// while this download runs for minutes -- so inheriting it would cancel every
// fetch the instant the page finished rendering, forever.
func (r *Resolver) schedule(region string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[region] {
		return
	}
	if at, bad := r.failed[region]; bad && r.now().Sub(at) < retryAfterFailure {
		return
	}
	if len(r.set.byRegion) >= maxCachedRegions {
		return
	}
	r.pending[region] = true

	go func() {
		// Deliberately NOT the caller's context: that context belongs to an
		// HTTP request that will be long finished before this download is,
		// and inheriting it would cancel every fetch on the first page load.
		fctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		cat, err := r.fetch(fctx, r.hc, region)

		r.mu.Lock()
		delete(r.pending, region)
		if err != nil || cat == nil {
			r.failed[region] = r.now()
			if err != nil {
				r.errs[region] = err.Error()
			}
			r.mu.Unlock()
			return
		}
		delete(r.failed, region)
		delete(r.errs, region)
		r.set.Put(cat)
		r.mu.Unlock()

		r.saveToDisk(cat)
	}()
}

// Status reports what the resolver holds, for the operator who is looking at a
// blank price column and needs to know whether it is fetching, failed, or
// simply has no rate for that instance type.
type Status struct {
	Region    string    `json:"region"`
	Rates     int       `json:"rates"`
	Published time.Time `json:"published,omitempty"`
	Fetched   time.Time `json:"fetched,omitempty"`
	Fetching  bool      `json:"fetching,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Stale     bool      `json:"stale,omitempty"`
}

func (r *Resolver) Status() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := map[string]bool{}
	var out []Status
	for _, region := range r.set.Regions() {
		cat, _ := r.set.Catalog(region)
		seen[region] = true
		out = append(out, Status{
			Region:    region,
			Rates:     len(cat.Rates),
			Published: cat.Published,
			Fetched:   cat.Fetched,
			Fetching:  r.pending[region],
			LastError: r.errs[region],
			Stale:     cat.Age(r.now()) >= r.maxAge,
		})
	}
	for region := range r.pending {
		if !seen[region] {
			out = append(out, Status{Region: region, Fetching: true})
			seen[region] = true
		}
	}
	for region, msg := range r.errs {
		if !seen[region] {
			out = append(out, Status{Region: region, LastError: msg})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Region < out[j].Region })
	return out
}

// --- disk cache ---

func (r *Resolver) cachePath(region string) string {
	if r.dir == "" {
		return ""
	}
	// The region reaches this from telemetry, so it is attacker-influenced and
	// must never become a path traversal. Only the shape a region name
	// actually has is admitted.
	if !safeRegionName(region) {
		return ""
	}
	return filepath.Join(r.dir, "pricing-aws-"+region+".json")
}

// safeRegionName admits only lowercase letters, digits and hyphens.
func safeRegionName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func (r *Resolver) loadFromDisk(region string) bool {
	path := r.cachePath(region)
	if path == "" {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var cat Catalog
	if err := json.Unmarshal(body, &cat); err != nil || len(cat.Rates) == 0 {
		return false
	}
	if cat.Region != region {
		// A cache file naming one region and containing another would price
		// every host in the fleet wrongly and consistently.
		return false
	}
	r.mu.Lock()
	r.set.Put(&cat)
	r.mu.Unlock()
	return true
}

func (r *Resolver) saveToDisk(cat *Catalog) {
	path := r.cachePath(cat.Region)
	if path == "" {
		return
	}
	body, err := json.Marshal(cat)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	// Written to a temporary file and renamed, so a crash mid-write leaves the
	// previous catalog intact rather than a truncated one that parses to
	// nothing and prices everything at zero.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// Put installs a catalog directly. Used by tests and by an operator supplying
// their own rates rather than fetching.
func (r *Resolver) Put(cat *Catalog) error {
	if cat == nil || cat.Region == "" || len(cat.Rates) == 0 {
		return fmt.Errorf("pricing: refusing an empty catalog")
	}
	r.mu.Lock()
	r.set.Put(cat)
	delete(r.failed, cat.Region)
	delete(r.errs, cat.Region)
	r.mu.Unlock()
	return nil
}
