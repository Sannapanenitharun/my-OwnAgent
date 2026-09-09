// Package pricing turns a cloud provider's published price list into rates the
// fleet can multiply against observed usage.
//
// WHAT THIS IS AND IS NOT. These are LIST prices, fetched from the provider's
// public price list. They are not an invoice. A host covered by a Reserved
// Instance, a Savings Plan, Spot pricing or an enterprise discount costs a
// different amount -- frequently less than half -- and nothing in a public
// price list can know that. Every number derived from this package is an
// ESTIMATE and must be presented as one.
//
// It is still worth having, for a reason worth stating plainly: the ALLOCATION
// is correct even when the RATE is not. If two containers split a host 70/30 by
// measured usage, that ratio holds whatever the host actually cost. An estimate
// answers "which workload is expensive" correctly while answering "what is the
// bill" only approximately, and the first question is the one an engineer can
// act on.
package pricing

import (
	"sort"
	"strings"
	"time"
)

// Rate is the price of one billable resource shape, per hour.
type Rate struct {
	Provider     string  `json:"provider"`
	Region       string  `json:"region"`
	InstanceType string  `json:"instance_type"`
	USDPerHour   float64 `json:"usd_per_hour"`

	// VCPU and MemoryGiB come from the same price-list row. They are kept
	// because a cost split needs to know the shape of the thing being split,
	// and reading them here avoids a second source that could disagree.
	VCPU      int     `json:"vcpu,omitempty"`
	MemoryGiB float64 `json:"memory_gib,omitempty"`
}

// Catalog is the set of rates for one provider region.
//
// One catalog per region, because that is how the provider publishes them and
// because a fleet usually spans few enough regions that fetching per region is
// cheaper than fetching the world.
type Catalog struct {
	Provider string `json:"provider"`
	Region   string `json:"region"`

	// Published is the provider's own publication date for the price list.
	// Fetched is when we retrieved it. They differ, and an operator debugging
	// a surprising number needs both: a stale fetch and a stale publication
	// are different problems.
	Published time.Time `json:"published"`
	Fetched   time.Time `json:"fetched"`

	// Rates is keyed by instance type.
	Rates map[string]Rate `json:"rates"`
}

// Lookup returns the rate for an instance type.
func (c *Catalog) Lookup(instanceType string) (Rate, bool) {
	if c == nil || len(c.Rates) == 0 {
		return Rate{}, false
	}
	r, ok := c.Rates[strings.TrimSpace(instanceType)]
	return r, ok
}

// Age reports how long ago the catalog was fetched.
func (c *Catalog) Age(now time.Time) time.Duration {
	if c == nil || c.Fetched.IsZero() {
		return 0
	}
	return now.Sub(c.Fetched)
}

// InstanceTypes lists what the catalog covers, sorted. Used for reporting
// rather than lookup.
func (c *Catalog) InstanceTypes() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Rates))
	for k := range c.Rates {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Set holds catalogs for the regions a fleet actually uses.
//
// It is deliberately not a cache with eviction: a fleet spans a handful of
// regions, each catalog is a few hundred kilobytes once filtered, and evicting
// one would mean re-downloading hundreds of megabytes to answer a lookup.
type Set struct {
	byRegion map[string]*Catalog
}

func NewSet() *Set { return &Set{byRegion: map[string]*Catalog{}} }

func (s *Set) Put(c *Catalog) {
	if s == nil || c == nil || c.Region == "" {
		return
	}
	if s.byRegion == nil {
		s.byRegion = map[string]*Catalog{}
	}
	s.byRegion[c.Region] = c
}

func (s *Set) Catalog(region string) (*Catalog, bool) {
	if s == nil || s.byRegion == nil {
		return nil, false
	}
	c, ok := s.byRegion[region]
	return c, ok
}

// Lookup finds a rate for a region and instance type.
func (s *Set) Lookup(region, instanceType string) (Rate, bool) {
	c, ok := s.Catalog(region)
	if !ok {
		return Rate{}, false
	}
	return c.Lookup(instanceType)
}

// Regions lists the regions held, sorted.
func (s *Set) Regions() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byRegion))
	for k := range s.byRegion {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
