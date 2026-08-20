package process

import (
	"runtime"
	"testing"
	"time"
)

// The mandatory Phase 3 scenario: ten thousand processes, five thousand killed
// and five thousand started, repeatedly. Nothing may grow without bound.

// churnSet replaces half the process table each cycle, mimicking a build farm
// or a container host draining and refilling.
func churnSet(generation, total, replace, distinctNames int) []Info {
	out := make([]Info, 0, total)
	stable := total - replace
	for i := 0; i < stable; i++ {
		out = append(out, proc(PID(1000+i), "stable"+itoa(i%distinctNames), uint64(i)))
	}
	for i := 0; i < replace; i++ {
		// Fresh PIDs and fresh start stamps every generation.
		pid := PID(100000 + generation*replace + i)
		out = append(out, proc(pid, "worker"+itoa(i%distinctNames), uint64(generation*1000+i)))
	}
	return out
}

// TestChurnDoesNotLeakAnything is the phase's headline stability test.
func TestChurnDoesNotLeakAnything(t *testing.T) {
	if testing.Short() {
		t.Skip("churn test is slow")
	}

	const (
		total   = 10000
		replace = 5000
		names   = 30
		cycles  = 12
		warmup  = 3
	)

	l := &fakeLister{}
	l.set(churnSet(0, total, replace, names))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"interval":           "1s",
		"collection.timeout": "900ms",
		"max_processes":      "1000",
		"max_tracked":        "16384",
		"exit_retention":     "10s",
	})
	h.start()
	h.waitCycles(1)

	var (
		baselineGoroutines int
		baselineHeap       uint64
		baselineState      int
		baselineSeries     int
	)

	for gen := 1; gen <= cycles; gen++ {
		l.set(churnSet(gen, total, replace, names))
		h.advance(2 * time.Second)

		if gen == warmup {
			runtime.GC()
			baselineGoroutines = runtime.NumGoroutine()
			baselineHeap = heapInUse()
			baselineState = int(h.mod.Statistics(h.t.Context()).Gauges["state_entries"])
			baselineSeries = totalSeries(h)
		}
	}

	runtime.GC()
	stats := h.mod.Statistics(h.t.Context())

	// 1. GOROUTINES. The module owns one collection goroutine regardless of how
	//    many processes churn through it.
	if got := runtime.NumGoroutine(); got > baselineGoroutines+2 {
		t.Errorf("goroutines grew from %d to %d across %d churn cycles",
			baselineGoroutines, got, cycles-warmup)
	}

	// 2. STATE. Five thousand processes exit every cycle; their state must be
	//    released, not accumulated.
	stateEntries := int(stats.Gauges["state_entries"])
	if stateEntries > total+100 {
		t.Errorf("state entries = %d after %d generations, want about %d",
			stateEntries, cycles, total)
	}
	if baselineState > 0 && stateEntries > baselineState*2 {
		t.Errorf("state entries grew from %d to %d; that is a leak", baselineState, stateEntries)
	}

	// 3. SERIES. The executable set is constant, so the series count must be
	//    too — even though 60,000 distinct process instances have been observed.
	if series := totalSeries(h); series > baselineSeries {
		t.Errorf("series grew from %d to %d under pure process churn",
			baselineSeries, series)
	}

	// 4. HEAP. Some growth is expected from Go's allocator; unbounded growth is
	//    not. A doubling across nine cycles would be the leak signature.
	if heap := heapInUse(); baselineHeap > 0 && heap > baselineHeap*2 {
		t.Errorf("heap grew from %d to %d bytes across %d churn cycles",
			baselineHeap, heap, cycles-warmup)
	}

	// 5. The churn actually happened — otherwise this test proves nothing.
	if stats.Counters["started_total"] < int64(replace*(cycles-1)) {
		t.Fatalf("only %d starts recorded; the scenario did not churn",
			stats.Counters["started_total"])
	}
	t.Logf("after %d generations: %d starts, %d exits, %d state entries, %d series, heap %d KiB",
		cycles, stats.Counters["started_total"], stats.Counters["exited_total"],
		stateEntries, totalSeries(h), heapInUse()/1024)
}

func heapInUse() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// TestChurnStormIsSummarisedNotStreamed proves the event budget holds.
func TestChurnStormIsSummarisedNotStreamed(t *testing.T) {
	l := &fakeLister{}
	l.set(churnSet(0, 5000, 5000, 20))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"interval":             "1s",
		"collection.timeout":   "900ms",
		"max_events_per_cycle": "50",
		"max_processes":        "5000",
	})
	h.start()
	h.waitCycles(1)

	l.set(churnSet(1, 5000, 5000, 20))
	h.advance(2 * time.Second)

	lifecycle := len(h.events(EventStarted)) + len(h.events(EventExited))
	// Two cycles at a 50-event budget.
	if lifecycle > 110 {
		t.Errorf("%d lifecycle events emitted under a 50-per-cycle budget", lifecycle)
	}

	// And the summary must carry the totals the individual events could not.
	summaries := h.events(EventChurn)
	if len(summaries) == 0 {
		t.Fatal("no churn summary was emitted during a churn storm")
	}
	last := summaries[len(summaries)-1]
	started, ok := eventAttr(last, "started")
	if !ok || started == "0" {
		t.Errorf("churn summary reports started=%q; it must carry the true total", started)
	}
	suppressed, ok := eventAttr(last, "events_suppressed")
	if !ok || suppressed == "0" {
		t.Errorf("churn summary reports events_suppressed=%q; it must explain the missing events",
			suppressed)
	}
	t.Logf("churn storm: %d lifecycle events emitted, summary says started=%s suppressed=%s",
		lifecycle, started, suppressed)
}

func TestRepeatedPIDReuseUnderChurnStaysCorrect(t *testing.T) {
	// A busy Linux host cycles through pid_max in minutes. Every reuse must be
	// detected; none may silently inherit a counter baseline.
	l := &fakeLister{}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"interval": "1s", "collection.timeout": "900ms"})

	const pidSpace = 200
	makeGen := func(gen int) []Info {
		out := make([]Info, 0, pidSpace)
		for i := 0; i < pidSpace; i++ {
			// The same PIDs every generation, different start stamps: exactly
			// what PID exhaustion and recycling looks like.
			out = append(out, proc(PID(1000+i), "worker", uint64(gen*10000+i)).
				withCPU(uint64(gen)*uint64(time.Second)))
		}
		return out
	}

	l.set(makeGen(0))
	h.start()
	h.waitCycles(1)

	const generations = 15
	for gen := 1; gen < generations; gen++ {
		l.set(makeGen(gen))
		h.advance(2 * time.Second)
	}

	stats := h.mod.Statistics(h.t.Context())
	wantReplacements := int64(pidSpace * (generations - 1))
	if got := stats.Counters["replaced_total"]; got != wantReplacements {
		t.Errorf("replacements = %d, want %d: every PID reuse must be detected",
			got, wantReplacements)
	}
	if got := int(stats.Gauges["state_entries"]); got != pidSpace {
		t.Errorf("state entries = %d after %d PID recycles, want %d",
			got, generations, pidSpace)
	}
}

func TestShortLivedProcessesDoNotAccumulateState(t *testing.T) {
	// Every process is new every cycle and nothing survives.
	l := &fakeLister{}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"interval":           "1s",
		"collection.timeout": "900ms",
		"exit_retention":     "1s",
	})
	l.set(churnSet(0, 500, 500, 5))
	h.start()
	h.waitCycles(1)

	for gen := 1; gen < 20; gen++ {
		l.set(churnSet(gen, 500, 500, 5))
		h.advance(2 * time.Second)
	}

	if got := int(h.mod.Statistics(h.t.Context()).Gauges["state_entries"]); got > 600 {
		t.Errorf("state entries = %d after 20 full replacements, want about 500", got)
	}
}
