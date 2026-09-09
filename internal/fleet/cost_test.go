package fleet

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/pricing"
)

// fixedRates is a RateSource that answers from a table, so the cost maths can
// be tested without any pricing machinery.
type fixedRates map[string]float64 // "region/type" -> usd per hour

func (f fixedRates) Rate(_ context.Context, region, itype string) (pricing.Rate, bool) {
	v, ok := f[region+"/"+itype]
	if !ok {
		return pricing.Rate{}, false
	}
	return pricing.Rate{
		Provider: "aws", Region: region, InstanceType: itype, USDPerHour: v,
	}, true
}

// costHost builds a store holding one priced host with the given series.
func costHost(t *testing.T, rates RateSource, resource map[string]string, metrics map[string]float64, containers map[string][2]float64) *Store {
	t.Helper()
	s := New(Limits{
		Hosts: 8, SeriesPerHost: 500, HistorySeries: 64,
		HistorySeriesExtra: 64, HistoryPoints: 64,
		LogsPerHost: 8, SpansPerHost: 8, StaleAfter: time.Minute,
	})
	s.SetRates(rates)

	// Built with the same rings a host gets through Ingest; summarise reads
	// them unconditionally, as it may, because every real host has them.
	h := &host{
		name:      "i-123",
		hostID:    "i-123",
		resource:  resource,
		series:    map[string]*series{},
		entities:  map[string]*entity{},
		relations: map[string]*relation{},
		logs:      newLogRing(8),
		spans:     newSpanRing(8),
		firstSeen: time.Now(),
		lastSeen:  time.Now(),
	}
	for name, v := range metrics {
		h.series[name] = &series{name: name, value: v, attrs: map[string]string{}}
	}
	for id, cm := range containers {
		h.series["cpu/"+id] = &series{
			name:  "container.instance.cpu_utilization",
			value: cm[0],
			attrs: map[string]string{"container_id": id},
		}
		h.series["mem/"+id] = &series{
			name:  "container.instance.memory_bytes",
			value: cm[1],
			attrs: map[string]string{"container_id": id},
		}
	}
	s.hosts["i-123"] = h
	return s
}

func close2(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestHostCostFromTheRate is the base case: a priced instance shape.
func TestHostCostFromTheRate(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)

	c := s.costFor(context.Background(), s.hosts["i-123"], time.Now())
	if c == nil || !c.Known {
		t.Fatalf("cost = %+v, want a known rate", c)
	}
	if !close2(c.USDPerHour, 0.096) {
		t.Errorf("hourly = %v, want 0.096", c.USDPerHour)
	}
	if !close2(c.USDPerDay, 0.096*24) || !close2(c.USDPerMonth, 0.096*730) {
		t.Errorf("day/month = %v / %v", c.USDPerDay, c.USDPerMonth)
	}
	if !c.Estimate {
		t.Error("Estimate must always be true; these are list prices")
	}
	// With no containers, the entire host is idle. That is the honest answer
	// and it is the number worth acting on.
	if !close2(c.IdleUSDPerHour, 0.096) || !close2(c.IdlePercent, 100) {
		t.Errorf("idle = $%v (%v%%), want the whole host", c.IdleUSDPerHour, c.IdlePercent)
	}
}

// TestTheSplitIsAgainstCapacityNotAgainstTheOtherContainers.
//
// Dividing by the sum of the containers would always total 100% and idle would
// never appear -- which is precisely the number an operator opens this panel to
// find.
func TestTheSplitIsAgainstCapacityNotAgainstTheOtherContainers(t *testing.T) {
	const cores, mem = 4.0, float64(16 << 30)
	s := costHost(t,
		fixedRates{"us-east-1/m5.xlarge": 0.192},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.xlarge"},
		map[string]float64{"host.cpu.count": cores, "host.memory.total_bytes": mem},
		map[string][2]float64{
			// One core of four, a quarter of memory: a quarter of the host.
			"aaa": {1.0, mem / 4},
			// Half a core, an eighth of memory.
			"bbb": {0.5, mem / 8},
		})

	c := s.costFor(context.Background(), s.hosts["i-123"], time.Now())
	if c == nil || !c.Known {
		t.Fatal("no cost")
	}
	if len(c.Workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(c.Workloads))
	}

	// share = 0.60*(cores/hostCores) + 0.40*(mem/hostMem)
	wantA := 0.60*(1.0/cores) + 0.40*0.25  // 0.15 + 0.10 = 0.25
	wantB := 0.60*(0.5/cores) + 0.40*0.125 // 0.075 + 0.05 = 0.125
	if !close2(c.Workloads[0].Share, wantA) {
		t.Errorf("first share = %v, want %v", c.Workloads[0].Share, wantA)
	}
	if !close2(c.Workloads[1].Share, wantB) {
		t.Errorf("second share = %v, want %v", c.Workloads[1].Share, wantB)
	}
	// Dearest first, so the panel opens on what to fix.
	if c.Workloads[0].ContainerID != "aaa" {
		t.Errorf("workloads are not sorted by cost: %+v", c.Workloads)
	}

	allocated := 0.192 * (wantA + wantB)
	if !close2(c.AllocatedUSDPerHour, allocated) {
		t.Errorf("allocated = %v, want %v", c.AllocatedUSDPerHour, allocated)
	}
	// The shares total 0.375, so 62.5% of this host is paid for and idle.
	if !close2(c.IdleUSDPerHour, 0.192-allocated) {
		t.Errorf("idle = %v, want %v", c.IdleUSDPerHour, 0.192-allocated)
	}
	if math.Abs(c.IdlePercent-62.5) > 0.001 {
		t.Errorf("idle = %v%%, want 62.5%%", c.IdlePercent)
	}
}

// TestOverCommitDoesNotProduceNegativeIdle. CPU is sampled and memory includes
// cache, so containers can briefly appear to exceed the host.
func TestOverCommitDoesNotProduceNegativeIdle(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		map[string][2]float64{
			"hog": {8.0, float64(32 << 30)}, // four times the machine
		})

	c := s.costFor(context.Background(), s.hosts["i-123"], time.Now())
	if c.IdleUSDPerHour < 0 {
		t.Errorf("idle = %v, must never be negative", c.IdleUSDPerHour)
	}
	if c.AllocatedUSDPerHour > c.USDPerHour+1e-9 {
		t.Errorf("allocated %v exceeds the host's own cost %v", c.AllocatedUSDPerHour, c.USDPerHour)
	}
}

// TestAnUnpriceableHostIsNilNotZero. A panel of zeros reads as "this is free",
// which is a lie; an absent panel reads as "unknown", which is true.
func TestAnUnpriceableHostIsNilNotZero(t *testing.T) {
	// No region or instance type: a laptop, or bare metal.
	s := costHost(t, fixedRates{}, map[string]string{}, nil, nil)
	if c := s.costFor(context.Background(), s.hosts["i-123"], time.Now()); c != nil {
		t.Errorf("cost = %+v, want nil for a host with no instance shape", c)
	}

	// No rate source configured at all.
	s2 := costHost(t, nil,
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"}, nil, nil)
	if c := s2.costFor(context.Background(), s2.hosts["i-123"], time.Now()); c != nil {
		t.Errorf("cost = %+v, want nil when no rates are configured", c)
	}
}

// TestAMissingRateReportsTheShapeNotAPrice. The rate may simply not have been
// downloaded yet, and "fetching" is a different message from "$0.00".
func TestAMissingRateReportsTheShapeNotAPrice(t *testing.T) {
	s := costHost(t,
		fixedRates{}, // knows nothing
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)

	c := s.costFor(context.Background(), s.hosts["i-123"], time.Now())
	if c == nil {
		t.Fatal("cost = nil; the shape is known even when the price is not")
	}
	if c.Known {
		t.Error("Known = true with no rate available")
	}
	if c.USDPerHour != 0 || c.InstanceType != "m5.large" {
		t.Errorf("cost = %+v, want the shape with no price", c)
	}
}

// TestUnitCostFromACounter. A counter's VALUE is cumulative and useless as a
// denominator; the rate has to come from its history.
func TestUnitCostFromACounter(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)
	s.SetUnitMetric("orders.processed")

	now := time.Now()
	h := s.hosts["i-123"]
	// 1200 orders over 30 minutes = 2400/hour.
	h.series["orders"] = &series{
		name:    "orders.processed",
		counter: true,
		value:   5200,
		attrs:   map[string]string{},
		history: []Sample{
			{Time: now.Add(-30 * time.Minute), Value: 4000},
			{Time: now, Value: 5200},
		},
	}

	c := s.costFor(context.Background(), h, now)
	if c == nil || c.Unit == nil {
		t.Fatalf("no unit cost: %+v", c)
	}
	u := c.Unit
	if u.Kind != "rate" {
		t.Errorf("kind = %q, want rate for a counter", u.Kind)
	}
	if !close2(u.Units, 2400) {
		t.Errorf("units/hr = %v, want 2400 (1200 over half an hour)", u.Units)
	}
	if !close2(u.USDPerUnit, 0.096/2400) {
		t.Errorf("usd per unit = %v, want %v", u.USDPerUnit, 0.096/2400)
	}
	if !close2(u.WindowSeconds, 1800) {
		t.Errorf("window = %v, want 1800", u.WindowSeconds)
	}
	// The cumulative value must never be used as the denominator: 0.096/5200
	// is a plausible-looking number and a meaningless one.
	if close2(u.USDPerUnit, 0.096/5200) {
		t.Error("the cumulative counter value was used as the denominator")
	}
}

// TestACounterResetProducesNoUnitCost. A restart makes the delta negative, and
// the sample after it makes the rate enormous. Both are worse than silence.
func TestACounterResetProducesNoUnitCost(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)
	s.SetUnitMetric("orders.processed")

	now := time.Now()
	h := s.hosts["i-123"]
	h.series["orders"] = &series{
		name: "orders.processed", counter: true, value: 12, attrs: map[string]string{},
		history: []Sample{
			{Time: now.Add(-10 * time.Minute), Value: 90000},
			{Time: now, Value: 12}, // the process restarted
		},
	}
	c := s.costFor(context.Background(), h, now)
	if c.Unit != nil {
		t.Errorf("unit cost = %+v across a counter reset, want none", c.Unit)
	}
}

// TestUnitCostFromAGaugeIsPerHour. A gauge is a level -- "tenants right now" --
// so the quotient is a cost per unit PER HOUR, a different quantity.
func TestUnitCostFromAGaugeIsPerHour(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)
	s.SetUnitMetric("tenants.active")

	h := s.hosts["i-123"]
	h.series["tenants"] = &series{
		name: "tenants.active", counter: false, value: 24, attrs: map[string]string{},
	}
	c := s.costFor(context.Background(), h, time.Now())
	if c.Unit == nil {
		t.Fatal("no unit cost from a gauge")
	}
	if c.Unit.Kind != "level" {
		t.Errorf("kind = %q, want level for a gauge", c.Unit.Kind)
	}
	if !close2(c.Unit.USDPerUnit, 0.096/24) {
		t.Errorf("usd per tenant-hour = %v", c.Unit.USDPerUnit)
	}
}

// TestNoDenominatorMeansNoUnitCost. Nothing in infrastructure telemetry knows
// which counter represents the business, so an unset unit metric must produce
// nothing rather than a guess.
func TestNoDenominatorMeansNoUnitCost(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)
	c := s.costFor(context.Background(), s.hosts["i-123"], time.Now())
	if c.Unit != nil {
		t.Errorf("unit cost = %+v with no denominator configured", c.Unit)
	}
}

// TestCostAppearsInTheFleetSummary wires the whole thing through the view the
// page actually polls.
func TestCostAppearsInTheFleetSummary(t *testing.T) {
	s := costHost(t,
		fixedRates{"us-east-1/m5.large": 0.096},
		map[string]string{"cloud.region": "us-east-1", "host.type": "m5.large"},
		map[string]float64{"host.cpu.count": 2, "host.memory.total_bytes": 8 << 30},
		nil)

	f := s.Fleet()
	if len(f.Hosts) != 1 {
		t.Fatalf("fleet has %d hosts", len(f.Hosts))
	}
	if f.Hosts[0].Cost == nil || !close2(f.Hosts[0].Cost.USDPerHour, 0.096) {
		t.Errorf("summary cost = %+v", f.Hosts[0].Cost)
	}
}
