package fleet

import (
	"fmt"
	"testing"
	"time"
)

// appMetric builds a metrics batch carrying one application series, the shape
// the OTLP decoder produces: an arbitrary name with the sender's own labels.
func appMetric(host, name string, v float64, attrs map[string]string) []byte {
	a := "{"
	first := true
	for k, val := range attrs {
		if !first {
			a += ","
		}
		a += fmt.Sprintf("%q:%q", k, val)
		first = false
	}
	a += "}"
	return []byte(fmt.Sprintf(
		`{"schema":"obsagent.v1","signal":"metrics","host":%q,"resource":{"host.id":%q},`+
			`"metrics":{"gauges":[{"name":%q,"value":%v,"attributes":%s}]}}`,
		host, host, name, v, a))
}

// TestApplicationSeriesAreCharted is the point of the change. An application
// metric arrived, was stored, showed a current value, and could never be
// drawn -- so "request latency is climbing" was a fact the store held and
// could not show.
func TestApplicationSeriesAreCharted(t *testing.T) {
	s := New(Limits{})
	for i := 0; i < 5; i++ {
		body := appMetric("h1", "http.server.duration", float64(i), map[string]string{"service.name": "checkout"})
		if err := s.Ingest("metrics", body); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, _ := s.Host("h1")
	m, ok := seriesNamed(d, "http.server.duration")
	if !ok {
		t.Fatal("the application series is not in the store at all")
	}
	if len(m.History) < 2 {
		t.Fatalf("history = %d points; an application metric still cannot be charted", len(m.History))
	}
}

// TestASeriesMustReportTwiceBeforeItIsCharted is the cardinality guard.
//
// A label unique per request -- an order ID in a route, a request ID -- makes
// every series a one-off. First-come budgeting would let one burst take every
// slot and hold it until the staleness sweep, starving the recurring series
// that are actually worth drawing.
func TestASeriesMustReportTwiceBeforeItIsCharted(t *testing.T) {
	s := New(Limits{})
	body := appMetric("h1", "http.server.duration", 1, map[string]string{"order.id": "once"})
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h1")
	m, ok := seriesNamed(d, "http.server.duration")
	if !ok {
		t.Fatal("the series should still be stored, just not charted")
	}
	if len(m.History) != 0 {
		t.Errorf("a series seen once earned a history ring (%d points)", len(m.History))
	}
}

// TestOneOffSeriesCannotExhaustTheChartBudget puts the guard under the load it
// exists for: a thousand unique label sets, none of which repeats.
func TestOneOffSeriesCannotExhaustTheChartBudget(t *testing.T) {
	s := New(Limits{})
	for i := 0; i < 1000; i++ {
		body := appMetric("h1", "http.server.duration", 1, map[string]string{"request.id": fmt.Sprint(i)})
		if err := s.Ingest("metrics", body); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	spent := s.hosts["h1"].historyExtra
	s.mu.Unlock()
	if spent != 0 {
		t.Errorf("unique-per-request series consumed %d chart slots; the guard did not hold", spent)
	}

	// And a genuinely recurring series still gets one afterwards.
	for i := 0; i < 3; i++ {
		if err := s.Ingest("metrics", appMetric("h1", "queue.depth", float64(i), nil)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h1")
	m, _ := seriesNamed(d, "queue.depth")
	if len(m.History) < 2 {
		t.Errorf("a recurring series was starved by the one-off burst: %d points", len(m.History))
	}
}

// TestApplicationMetricsCannotBlankTheHostCharts is the reason there are two
// budgets rather than one bigger one. "The CPU chart went blank because a
// service got chatty" is a bad trade at any size.
func TestApplicationMetricsCannotBlankTheHostCharts(t *testing.T) {
	s := New(Limits{HistorySeriesExtra: 4})

	// Fill and overflow the application budget.
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("app.metric.%d", i)
		for r := 0; r < 2; r++ {
			if err := s.Ingest("metrics", appMetric("h1", name, float64(r), nil)); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Host series arriving afterwards must still chart.
	for i := 0; i < 3; i++ {
		body := appMetric("h1", "host.cpu.utilization", float64(i), map[string]string{"state": "user"})
		if err := s.Ingest("metrics", body); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h1")
	m, ok := seriesNamed(d, "host.cpu.utilization")
	if !ok || len(m.History) < 2 {
		t.Fatalf("the host CPU chart lost its history to application metrics: found=%v points=%d", ok, len(m.History))
	}

	s.mu.Lock()
	extra := s.hosts["h1"].historyExtra
	s.mu.Unlock()
	if extra > 4 {
		t.Errorf("application charts overran their budget: %d of 4", extra)
	}
}

// TestARetiredApplicationSeriesReturnsItsSlot. A service is undeployed and its
// series stops. Without reclaiming, the ring holds a slot forever and
// eventually crowds out what is still running -- and the slot must go back to
// the budget it came from, or the two counters drift and the caps stop meaning
// anything.
func TestARetiredApplicationSeriesReturnsItsSlot(t *testing.T) {
	s := New(Limits{})
	now := s.now()
	s.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if err := s.Ingest("metrics", appMetric("h1", "queue.depth", float64(i), nil)); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	before := s.hosts["h1"].historyExtra
	s.mu.Unlock()
	if before != 1 {
		t.Fatalf("historyExtra = %d after one charted application series, want 1", before)
	}

	// Silence past the staleness window, then force a sweep.
	now = now.Add(2 * s.limits.SeriesStaleAfter)
	s.mu.Lock()
	s.pruneSeriesLocked(s.hosts["h1"], s.now())
	after := s.hosts["h1"].historyExtra
	s.mu.Unlock()

	if after != 0 {
		t.Errorf("historyExtra = %d after the series was retired, want 0 -- the slot leaked", after)
	}
}

// TestProcessAndCumulativeNetworkStayUncharted. Widening the answer must not
// quietly readmit the two exclusions that had real reasons: process.* is keyed
// per executable, and the container network counters are cumulative totals
// that make a poor chart in any case.
func TestProcessAndCumulativeNetworkStayUncharted(t *testing.T) {
	for _, name := range []string{
		"process.cpu.utilization",
		"process.memory.rss",
		"container.instance.network.rx_bytes",
		"container.instance.network.tx_bytes",
	} {
		if got := chartClassOf(name); got != chartNone {
			t.Errorf("chartClassOf(%q) = %v, want chartNone", name, got)
		}
	}
	for _, name := range []string{"host.cpu.utilization", "container.instance.memory_bytes"} {
		if got := chartClassOf(name); got != chartCore {
			t.Errorf("chartClassOf(%q) = %v, want chartCore", name, got)
		}
	}
	for _, name := range []string{"http.server.duration", "httpcheck.latency_seconds", "agent.export.success"} {
		if got := chartClassOf(name); got != chartExtra {
			t.Errorf("chartClassOf(%q) = %v, want chartExtra", name, got)
		}
	}
}
