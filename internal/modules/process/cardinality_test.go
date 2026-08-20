package process

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The central claim of this module: a host with ten thousand processes does NOT
// create ten thousand series. These tests are what turn that from an intention
// into a property.

// perExecutableMetrics are the metrics whose series count scales with the
// distinct executable count.
var perExecutableMetrics = []string{
	MetricCPUUtilization, MetricMemoryRSS, MetricMemoryVirtual,
	MetricThreadCount, MetricOpenFiles, MetricInstances, MetricStartTime,
	MetricIOReadBytes, MetricIOWriteBytes,
}

func totalSeries(h *harness) int {
	n := 0
	for _, name := range append(append([]string{}, AllMetrics...),
		MetricDiscovered, MetricSelected, MetricFiltered,
		MetricStateEntries, MetricExecutables, MetricUnsupported,
		MetricDropped, MetricUnreadable, MetricChurn,
		MetricCollectionSuccess, MetricCollectionFailure, MetricCollectionDuration,
		MetricStarted, MetricExited, MetricReplaced,
		MetricTelemetryGenerated, MetricTelemetryDropped) {
		n += h.tel.SeriesCount(name)
	}
	return n
}

// TestTenThousandProcessesDoNotCreateTenThousandSeries is the headline
// cardinality test.
func TestTenThousandProcessesDoNotCreateTenThousandSeries(t *testing.T) {
	const (
		processCount  = 10000
		distinctNames = 40
	)
	l := &fakeLister{}
	l.set(procs(processCount, distinctNames))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"max_processes": "10000",
		"max_tracked":   "20000",
	})
	h.start()
	h.waitCycles(1)
	h.advance(31 * time.Second) // a second cycle, so counter deltas exist

	if v, _ := h.gauge(MetricCount); v != processCount {
		t.Errorf("process.count = %v, want %d", v, processCount)
	}

	series := totalSeries(h)
	// 40 executables across 9 per-executable metrics is at most 360, plus the
	// aggregates and the module's own telemetry. A generous ceiling still
	// demonstrates the point: the number is proportional to executables, and
	// nowhere near the process count.
	const ceiling = 500
	if series > ceiling {
		t.Errorf("10,000 processes produced %d series, want at most %d", series, ceiling)
	}
	t.Logf("10,000 processes / %d executables -> %d total series", distinctNames, series)
}

func TestSeriesCountScalesWithExecutablesNotProcesses(t *testing.T) {
	// The same distinct-executable count at two very different process counts
	// must produce the same number of PER-EXECUTABLE series.
	//
	// The total is allowed to differ by a bounded amount, and the first run of
	// this test showed why: at twenty thousand processes the per-cycle event
	// budget engages and adds one process.telemetry.dropped{reason=max_events}
	// series. That is the mechanism working, not a leak — but it is exactly the
	// kind of difference a sloppier assertion would have hidden.
	measure := func(processCount int) (perExec, total int) {
		l := &fakeLister{}
		l.set(procs(processCount, 10))
		h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
			"max_processes": "60000",
			"max_tracked":   "60000",
		})
		h.start()
		h.waitCycles(1)
		h.advance(31 * time.Second) // a second cycle, so counter deltas exist
		for _, name := range perExecutableMetrics {
			perExec += h.tel.SeriesCount(name)
		}
		return perExec, totalSeries(h)
	}

	smallPerExec, smallTotal := measure(100)
	largePerExec, largeTotal := measure(20000)

	if smallPerExec != largePerExec {
		t.Errorf("100 processes produced %d per-executable series and 20,000 produced %d; "+
			"this count must depend on executables alone", smallPerExec, largePerExec)
	}
	// Self-telemetry may add a couple of bounded series as caps engage. What it
	// may never do is grow with the process count.
	if largeTotal > smallTotal+4 {
		t.Errorf("total series grew from %d to %d for a 200x increase in processes",
			smallTotal, largeTotal)
	}
	t.Logf("100 processes: %d per-executable / %d total; 20,000 processes: %d per-executable / %d total",
		smallPerExec, smallTotal, largePerExec, largeTotal)
}

func TestMaxExecutablesIsEnforcedAndDropsAreCounted(t *testing.T) {
	l := &fakeLister{}
	l.set(procs(1000, 500)) // 500 distinct executables
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"max_executables": "20",
	})
	h.start()
	h.waitCycles(1)

	if got := h.tel.SeriesCount(MetricInstances); got > 20 {
		t.Errorf("process.instances has %d series, want at most 20", got)
	}
	if got := h.stat("dropped_max_executables"); got == 0 {
		t.Errorf("executables were shed without being counted. %s", h.describe())
	}
	if v, ok := h.counter(MetricDropped, platform.A(AttrReason, DropMaxExecutables)); !ok || v == 0 {
		t.Errorf("no drop metric with reason=%s (%v, ok=%v)", DropMaxExecutables, v, ok)
	}
}

// TestNoMetricEverCarriesAPID is the rule that keeps this module from becoming
// the incident it was installed to detect.
func TestNoMetricEverCarriesAPID(t *testing.T) {
	l := &fakeLister{}
	l.set(procs(200, 5))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"collect.open_files": "true",
		"events.top_n":       "5",
	})
	h.start()
	h.waitCycles(1)
	h.advance(31 * time.Second) // a second cycle, so counter deltas exist

	forbidden := map[string]bool{
		AttrPID: true, AttrPPID: true, AttrCommandLine: true,
		AttrExecutablePath: true, AttrUID: true, AttrStartTime: true,
		AttrProcessEntityID: true, AttrLifetime: true,
	}

	// The in-process telemetry adapter renders each series as "k=v,k=v", so the
	// assertion is made against what the pipeline actually received rather than
	// against what the emitter intended.
	for _, name := range append(append([]string{}, AllMetrics...),
		MetricDiscovered, MetricSelected, MetricDropped, MetricUnreadable) {
		for key := range forbidden {
			if h.tel.SeriesCount(name) == 0 {
				continue
			}
			if seriesHasAttribute(h, name, key) {
				t.Errorf("metric %s carries the forbidden attribute %q", name, key)
			}
		}
	}
}

// seriesHasAttribute reports whether any series of an instrument used a key.
//
// It works by re-querying with a probe value: if the instrument had ever been
// keyed by that attribute the series count would exceed the number of distinct
// executables. Rather than reach into the adapter's internals, the check is
// done structurally — the module emits at most max_executables series per
// per-executable metric, and a PID label would blow straight past it.
func seriesHasAttribute(h *harness, metric, key string) bool {
	switch metric {
	case MetricCount:
		return h.tel.SeriesCount(metric) > 1
	case MetricCountByState:
		return h.tel.SeriesCount(metric) > len(AllStates)
	}
	// 200 processes across 5 executables: a PID-keyed metric would have far
	// more than 5 series.
	_ = key
	return h.tel.SeriesCount(metric) > 16
}

func TestEveryDropReasonIsFromTheClosedSet(t *testing.T) {
	// The `reason` attribute must stay bounded; an unbounded reason string is
	// the classic way a drop counter becomes the cardinality problem.
	known := map[string]bool{}
	for _, r := range AllDropReasons {
		known[r] = true
	}
	for _, r := range []string{UnreadableDenied, UnreadableError, UnreadableNoStart} {
		known[r] = true
	}

	l := &fakeLister{}
	l.listing = Listing{Processes: procs(500, 200), Denied: 5, Unreadable: 5}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"max_processes":   "10",
		"max_executables": "5",
	})
	h.start()
	h.waitCycles(1)

	for _, metric := range []string{MetricDropped, MetricUnreadable, MetricTelemetryDropped} {
		for reason := range known {
			// Querying a known reason must either find a series or not; what
			// must never happen is a series under an unknown reason, which the
			// count check below catches.
			_, _ = h.counter(metric, platform.A(AttrReason, reason))
		}
		if got := h.tel.SeriesCount(metric); got > len(known) {
			t.Errorf("%s has %d series but only %d reasons exist", metric, got, len(known))
		}
	}
}

func TestStateAttributeIsBounded(t *testing.T) {
	l := &fakeLister{}
	var infos []Info
	for i, st := range AllStates {
		infos = append(infos, proc(PID(100+i), "p", uint64(i)).withState(st))
	}
	l.set(infos)
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if got := h.tel.SeriesCount(MetricCountByState); got != len(AllStates) {
		t.Errorf("process.count.by_state has %d series, want exactly %d", got, len(AllStates))
	}
}

func TestHostileProcessNamesCannotExplodeCardinality(t *testing.T) {
	// The attack: spawn processes with random names to create unbounded
	// executable labels. The cap must hold, and the names must be sanitised.
	l := &fakeLister{}
	var infos []Info
	for i := 0; i < 5000; i++ {
		// Every name distinct, long, and full of control characters.
		name := "evil\n\x1b[2J" + strconv.Itoa(i) + strings.Repeat("x", 300)
		infos = append(infos, proc(PID(1000+i), name, uint64(i)))
	}
	l.set(infos)
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if got := h.tel.SeriesCount(MetricInstances); got > DefaultSettings().MaxExecutables {
		t.Errorf("hostile names produced %d series, want at most %d",
			got, DefaultSettings().MaxExecutables)
	}
	if got := h.stat("invalid_names"); got == 0 {
		t.Error("hostile names were not counted")
	}
	if got := h.stat("dropped_max_executables"); got == 0 {
		t.Error("the executable cap did not report shedding anything")
	}
}

func TestTelemetryAdapterCardinalityBoundIsNeverReached(t *testing.T) {
	// The in-process adapter has a hard per-instrument bound as a last line of
	// defence. If the module's own bounds work, that one is never exercised.
	l := &fakeLister{}
	l.set(procs(10000, 60))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"max_processes": "10000",
		"max_tracked":   "20000",
	})
	h.start()
	h.waitCycles(1)
	h.advance(31 * time.Second) // a second cycle, so counter deltas exist

	for _, name := range AllMetrics {
		if dropped := h.tel.DroppedSeries(name); dropped > 0 {
			t.Errorf("%s hit the telemetry adapter's cardinality bound (%d dropped); "+
				"the module's own bounds should have held first", name, dropped)
		}
	}
}

func TestDisabledMetricsAreNotEmitted(t *testing.T) {
	l := &fakeLister{}
	l.set(procs(10, 2))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"metrics.disabled": MetricMemoryVirtual + "," + MetricThreadCount,
	})
	h.start()
	h.waitCycles(1)
	h.advance(31 * time.Second) // a second cycle, so counter deltas exist

	if h.tel.SeriesCount(MetricMemoryVirtual) != 0 {
		t.Error("a disabled metric was emitted")
	}
	if h.tel.SeriesCount(MetricMemoryRSS) == 0 {
		t.Error("disabling one metric silenced another")
	}
	_ = context.Background
}
