package fleet

import (
	"fmt"
	"testing"
	"time"
)

// containerMetrics builds a metrics batch carrying one per-container series.
func containerMetrics(host, metric, containerID string, v float64) []byte {
	return []byte(fmt.Sprintf(
		`{"schema":"obsagent.v1","signal":"metrics","host":%q,"resource":{"host.id":%q},`+
			`"metrics":{"gauges":[{"name":%q,"value":%v,"attributes":{"container_id":%q}}]}}`,
		host, host, metric, v, containerID))
}

func seriesNamed(d Detail, name string) (SeriesView, bool) {
	for _, m := range d.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return SeriesView{}, false
}

// TestContainerSeriesAreCharted is the point of the change. The per-container
// panel draws CPU and memory over time, and a series with no sample ring can
// only ever render as a single point.
func TestContainerSeriesAreCharted(t *testing.T) {
	s := New(Limits{})
	for i := 0; i < 5; i++ {
		if err := s.Ingest("metrics", containerMetrics("h1", "container.instance.memory_bytes", "abc123", float64(i))); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, ok := s.Host("h1")
	if !ok {
		t.Fatal("host missing")
	}
	m, ok := seriesNamed(d, "container.instance.memory_bytes")
	if !ok {
		t.Fatal("container series not found")
	}
	if len(m.History) != 5 {
		t.Errorf("history = %d points, want 5: the chart has nothing to draw", len(m.History))
	}
}

// TestProcessSeriesAreNotCharted keeps the exclusion that made the original
// rule right: process.* is keyed per executable, so a host running hundreds of
// programs would carry a sample ring for each, for charts nothing draws.
func TestProcessSeriesAreNotCharted(t *testing.T) {
	s := New(Limits{})
	for i := 0; i < 5; i++ {
		if err := s.Ingest("metrics", metricsBody("h1", []string{"process.memory_bytes"}, float64(i))); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, _ := s.Host("h1")
	if m, ok := seriesNamed(d, "process.memory_bytes"); ok && len(m.History) > 0 {
		t.Errorf("process series kept %d history points", len(m.History))
	}
}

// TestDeadContainerReleasesItsHistorySlot is what makes charting an unbounded
// key safe. Without it every container the host ever ran would hold a slot in
// the history cap forever, and the containers still running would eventually
// be the ones refused.
func TestDeadContainerReleasesItsHistorySlot(t *testing.T) {
	now := time.Now()
	s := New(Limits{})
	s.now = func() time.Time { return now }

	if err := s.Ingest("metrics", containerMetrics("h1", "container.instance.memory_bytes", "gone", 1)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	s.mu.Lock()
	h := s.hosts["h1"]
	before := h.historySeries
	s.mu.Unlock()
	if before != 1 {
		t.Fatalf("historySeries = %d after one charted series, want 1", before)
	}

	now = now.Add(2 * s.limits.SeriesStaleAfter)
	s.mu.Lock()
	s.pruneSeriesLocked(h, now)
	after, n := h.historySeries, len(h.series)
	s.mu.Unlock()

	if n != 0 {
		t.Errorf("series = %d, want the stale container series reclaimed", n)
	}
	if after != 0 {
		t.Errorf("historySeries = %d after pruning, want 0: the counter leaked", after)
	}
}

// TestHostChartsSurvivePruning is the other half. host.* series are the charts
// the overview draws; reclaiming one on a brief reporting gap would punch a
// hole an operator reads as an outage.
func TestHostChartsSurvivePruning(t *testing.T) {
	now := time.Now()
	s := New(Limits{})
	s.now = func() time.Time { return now }
	if err := s.Ingest("metrics", metricsBody("h1", []string{"host.cpu.utilization"}, 0.5)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	now = now.Add(2 * s.limits.SeriesStaleAfter)
	s.mu.Lock()
	h := s.hosts["h1"]
	s.pruneSeriesLocked(h, now)
	n := len(h.series)
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("host series = %d, want the charted host series kept", n)
	}
}

// TestHistoryCapIsEnforced. The counter replaced an O(n) scan, so it has to be
// right or the cap silently stops working.
func TestHistoryCapIsEnforced(t *testing.T) {
	s := New(Limits{HistorySeries: 3})
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("c%02d", i)
		if err := s.Ingest("metrics", containerMetrics("h1", "container.instance.memory_bytes", id, 1)); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	s.mu.Lock()
	h := s.hosts["h1"]
	charted := 0
	for _, ser := range h.series {
		if len(ser.history) > 0 {
			charted++
		}
	}
	count := h.historySeries
	s.mu.Unlock()
	if charted != 3 {
		t.Errorf("charted series = %d, want the cap of 3", charted)
	}
	if count != charted {
		t.Errorf("historySeries = %d but %d series actually hold history", count, charted)
	}
}
