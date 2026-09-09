package fleet

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/pricing"
)

// Cost estimation.
//
// EVERY NUMBER HERE IS AN ESTIMATE, and the types say so in a field rather than
// only in a comment. The rate comes from the provider's published LIST price. A
// host covered by a Reserved Instance, a Savings Plan, Spot pricing or an
// enterprise agreement costs something else -- often half. Nothing available to
// an agent can know which.
//
// WHAT IS STILL TRUE. The ALLOCATION does not depend on the rate being right.
// If two containers divide a host 70/30 by measured consumption, that ratio
// holds whatever the host actually cost. So this answers "which workload is
// expensive" correctly while answering "what is the bill" only approximately,
// and the first is the question an engineer can act on. The second belongs to a
// billing export, which is a different feed and a different project.

// RateSource supplies hourly rates. An interface so the store depends on the
// shape of a lookup rather than on the machinery that fetches 300 MB CSVs, and
// so tests can hand it fixed prices.
type RateSource interface {
	Rate(ctx context.Context, region, instanceType string) (pricing.Rate, bool)
}

// The CPU/memory weighting used to divide a host's cost between its workloads.
//
// A machine's price is one number covering cores, memory, the hypervisor slot
// and everything else; splitting it requires deciding how much of that price
// each resource represents, and there is no ground truth for that. Datadog
// publishes 60/40 for standard instances and 95/3/2 where a GPU is present, so
// this uses their ratio rather than inventing a different arbitrary one --
// being consistent with a documented practice is worth more than being
// privately clever.
const (
	cpuCostWeight    = 0.60
	memoryCostWeight = 0.40
)

// maxWorkloadsCosted bounds the per-container breakdown.
const maxWorkloadsCosted = 200

// HostCost is the estimated cost of one host and how it divides.
type HostCost struct {
	Region       string `json:"region,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`

	// Known is false when no rate could be found. The remaining fields are
	// then zero, and a caller MUST distinguish that from "this host is free".
	Known bool `json:"known"`

	// Estimate is always true. It is a field rather than a comment so that
	// anything rendering this has to carry it.
	Estimate bool   `json:"estimate"`
	Basis    string `json:"basis,omitempty"`

	USDPerHour  float64 `json:"usd_per_hour"`
	USDPerDay   float64 `json:"usd_per_day"`
	USDPerMonth float64 `json:"usd_per_month"`

	// Allocated is the share attributed to workloads; Idle is the remainder.
	// Idle is the number worth acting on: it is what the host costs to run
	// nothing.
	AllocatedUSDPerHour float64 `json:"allocated_usd_per_hour"`
	IdleUSDPerHour      float64 `json:"idle_usd_per_hour"`
	IdlePercent         float64 `json:"idle_percent"`

	Workloads []WorkloadCost `json:"workloads,omitempty"`

	// Unit is the cost per business unit, when a denominator is configured
	// and present.
	Unit *UnitCost `json:"unit,omitempty"`
}

// WorkloadCost is one container's share of its host.
type WorkloadCost struct {
	ContainerID string  `json:"container_id"`
	CPUCores    float64 `json:"cpu_cores"`
	MemoryBytes float64 `json:"memory_bytes"`
	Share       float64 `json:"share"`
	USDPerHour  float64 `json:"usd_per_hour"`
	USDPerDay   float64 `json:"usd_per_day"`
}

// UnitCost is cost divided by a business denominator.
type UnitCost struct {
	Metric string `json:"metric"`

	// Kind distinguishes the two things a denominator can be, because they
	// mean different things and the difference is not visible in the number.
	//
	//	"rate"  a counter: units happening per hour -> cost per unit
	//	"level" a gauge: units existing right now  -> cost per unit per hour
	Kind string `json:"kind"`

	Units      float64 `json:"units"`
	USDPerUnit float64 `json:"usd_per_unit"`
	Estimate   bool    `json:"estimate"`

	// Window is how much history the rate was derived over. A rate computed
	// across two samples a few seconds apart is far noisier than one across an
	// hour, and the reader cannot tell without this.
	WindowSeconds float64 `json:"window_seconds,omitempty"`
}

// costFor computes the estimate for one host. The caller holds s.mu.
//
// It returns nil rather than a zero HostCost when the host is not on a cloud
// instance we can price at all: an empty panel is honest, a panel of zeros is
// not.
func (s *Store) costFor(ctx context.Context, h *host, now time.Time) *HostCost {
	if s.rates == nil || h == nil {
		return nil
	}
	region := strings.TrimSpace(h.resource["cloud.region"])
	itype := strings.TrimSpace(h.resource["host.type"])
	if region == "" || itype == "" {
		// Not an instance whose shape we know. A bare-metal host or a laptop
		// has no list price and inventing one would be worse than silence.
		return nil
	}

	out := &HostCost{
		Region:       region,
		InstanceType: itype,
		Estimate:     true,
	}
	rate, ok := s.rates.Rate(ctx, region, itype)
	if !ok {
		// The rate may simply not have been fetched yet. Reporting the shape
		// with Known=false lets the UI say "fetching" instead of "$0.00".
		return out
	}
	out.Known = true
	out.Basis = "aws price list (on-demand list price)"
	out.USDPerHour = rate.USDPerHour
	out.USDPerDay = rate.USDPerHour * 24
	out.USDPerMonth = rate.USDPerHour * 730 // the conventional billing month

	out.Workloads, out.AllocatedUSDPerHour = s.splitLocked(h, rate.USDPerHour)
	out.IdleUSDPerHour = out.USDPerHour - out.AllocatedUSDPerHour
	if out.IdleUSDPerHour < 0 {
		// Containers can exceed the host's nominal capacity in short windows
		// -- CPU accounting is sampled, memory includes cache. Clamping keeps
		// idle meaningful rather than reporting a negative cost.
		out.IdleUSDPerHour = 0
	}
	if out.USDPerHour > 0 {
		out.IdlePercent = out.IdleUSDPerHour / out.USDPerHour * 100
	}

	out.Unit = s.unitCostLocked(h, out.USDPerHour, now)
	return out
}

// splitLocked divides an hourly rate between the containers on a host.
//
// The share is measured against the host's CAPACITY, not against the sum of
// the containers. That is the whole point: dividing by the sum would always
// total 100% and idle would never appear, which is exactly the number an
// operator is looking for.
func (s *Store) splitLocked(h *host, usdPerHour float64) ([]WorkloadCost, float64) {
	hostCores, okCores := seriesValue(h, "host.cpu.count", "", "")
	hostMem, okMem := seriesValue(h, "host.memory.total_bytes", "", "")
	if !okCores || !okMem || hostCores <= 0 || hostMem <= 0 {
		return nil, 0
	}

	type acc struct {
		cpu float64
		mem float64
	}
	byContainer := map[string]*acc{}
	for _, ser := range h.series {
		id := ser.attrs["container_id"]
		if id == "" {
			continue
		}
		a := byContainer[id]
		if a == nil {
			if len(byContainer) >= maxWorkloadsCosted {
				continue
			}
			a = &acc{}
			byContainer[id] = a
		}
		switch ser.name {
		case "container.instance.cpu_utilization":
			// Cores, not percent: the collector reports utilisation against
			// ONE cpu, so 0.5 is half a core and 2.0 is two of them.
			a.cpu = ser.value
		case "container.instance.memory_bytes":
			a.mem = ser.value
		}
	}
	if len(byContainer) == 0 {
		return nil, 0
	}

	out := make([]WorkloadCost, 0, len(byContainer))
	total := 0.0
	for id, a := range byContainer {
		cpuFrac := a.cpu / hostCores
		memFrac := a.mem / hostMem
		share := cpuCostWeight*cpuFrac + memoryCostWeight*memFrac
		if share <= 0 {
			continue
		}
		if share > 1 {
			share = 1
		}
		cost := usdPerHour * share
		total += share
		out = append(out, WorkloadCost{
			ContainerID: id,
			CPUCores:    a.cpu,
			MemoryBytes: a.mem,
			Share:       share,
			USDPerHour:  cost,
			USDPerDay:   cost * 24,
		})
	}
	if total > 1 {
		total = 1
	}
	// Dearest first: the reason to open this panel is to find what to fix.
	sort.Slice(out, func(i, j int) bool {
		if out[i].USDPerHour != out[j].USDPerHour {
			return out[i].USDPerHour > out[j].USDPerHour
		}
		return out[i].ContainerID < out[j].ContainerID
	})
	return out, usdPerHour * total
}

// unitCostLocked divides the host's hourly cost by a business denominator.
func (s *Store) unitCostLocked(h *host, usdPerHour float64, now time.Time) *UnitCost {
	name := strings.TrimSpace(s.unitMetric)
	if name == "" || usdPerHour <= 0 {
		return nil
	}
	var found *series
	for _, ser := range h.series {
		if ser.name == name {
			found = ser
			break
		}
	}
	if found == nil {
		return nil
	}

	out := &UnitCost{Metric: name, Estimate: true}
	if found.counter {
		// A counter's value is cumulative and meaningless as a denominator:
		// dividing an hourly cost by every order since boot answers nothing.
		// The rate has to come from the history ring.
		units, window, ok := counterRatePerHour(found, now)
		if !ok {
			return nil
		}
		out.Kind = "rate"
		out.Units = units
		out.WindowSeconds = window
	} else {
		// A gauge is a level -- "tenants right now" -- so the quotient is a
		// cost per unit PER HOUR, which is a different quantity and is
		// labelled as one.
		if found.value <= 0 {
			return nil
		}
		out.Kind = "level"
		out.Units = found.value
	}
	if out.Units <= 0 {
		return nil
	}
	out.USDPerUnit = usdPerHour / out.Units
	return out
}

// counterRatePerHour derives units-per-hour from a counter's history.
//
// Counters reset when the process that owns them restarts, and a reset makes
// the delta negative. Reporting a negative rate -- or an enormous positive one
// on the sample after -- would be worse than reporting nothing.
func counterRatePerHour(ser *series, now time.Time) (perHour, windowSeconds float64, ok bool) {
	if ser == nil || len(ser.history) < 2 {
		return 0, 0, false
	}
	first := ser.history[0]
	last := ser.history[len(ser.history)-1]
	window := last.Time.Sub(first.Time).Seconds()
	if window <= 0 {
		return 0, 0, false
	}
	delta := last.Value - first.Value
	if delta < 0 {
		return 0, 0, false // counter reset
	}
	_ = now
	return delta / window * 3600, window, true
}

// seriesValue reads one series value by name, optionally filtered on one
// attribute.
func seriesValue(h *host, name, attrKey, attrVal string) (float64, bool) {
	return findSeries(h, name, attrKey, attrVal)
}
