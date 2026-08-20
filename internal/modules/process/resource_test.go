package process

import (
	"context"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The module's central resource claim: its cost is independent of how many
// processes exist. These tests are what make that measurable rather than
// asserted.

func goroutineDelta(t *testing.T, fn func()) int {
	t.Helper()
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	fn()
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	return runtime.NumGoroutine() - before
}

// TestGoroutineCountIsIndependentOfProcessCount is the "no goroutine per
// process" rule, measured.
func TestGoroutineCountIsIndependentOfProcessCount(t *testing.T) {
	measure := func(processCount int) int {
		var mod *Module
		delta := goroutineDelta(t, func() {
			l := &fakeLister{}
			l.set(procs(processCount, 20))
			h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
				"max_processes": "60000",
				"max_tracked":   "60000",
			})
			h.start()
			h.waitCycles(1)
			h.advance(31 * time.Second)
			mod = h.mod
		})
		_ = mod
		return delta
	}

	small := measure(10)
	large := measure(20000)

	// One collection goroutine, plus at most a transient guard goroutine that
	// has not yet been reaped.
	if small > 3 {
		t.Errorf("10 processes added %d goroutines, want at most 3", small)
	}
	if large > small+1 {
		t.Errorf("20,000 processes added %d goroutines against %d for 10; "+
			"the count must not scale with the process table", large, small)
	}
	t.Logf("goroutines added: 10 processes -> %d, 20,000 processes -> %d", small, large)
}

func TestNoTimerPerProcess(t *testing.T) {
	// The fake clock counts armed timers directly, so "no timer per process" is
	// checked rather than argued.
	l := &fakeLister{}
	l.set(procs(5000, 20))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"max_processes": "5000",
		"max_tracked":   "10000",
	})
	h.start()
	h.waitCycles(1)
	h.clock.BlockUntil(1)

	if got := h.clock.Waiters(); got > 2 {
		t.Errorf("%d timers armed with 5,000 processes; the module must use one", got)
	}
}

func TestStoppedModuleLeavesNothingBehind(t *testing.T) {
	delta := goroutineDelta(t, func() {
		l := &fakeLister{}
		l.set(procs(1000, 20))
		h := newHarness(t, fullSet(l, newFakeDetail()), nil)
		h.start()
		h.waitCycles(1)
		if err := h.mod.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	})
	if delta > 1 {
		t.Errorf("a stopped module left %d goroutines behind", delta)
	}
}

func TestMemoryPerTrackedProcessIsBounded(t *testing.T) {
	// The module retains two things per process, and they are bounded by
	// different limits, so the test measures them separately rather than
	// reporting one number nobody can act on:
	//
	//	tracked state   one struct plus a map entry, bounded by max_tracked
	//	observation slab one struct, sized to the OBSERVED process count
	//
	// The slab is retained deliberately: allocating observations per process
	// per cycle cost 17 MB of garbage per cycle at fifty thousand processes.
	// Trading that for resident memory is the right call for a long-running
	// agent, but only if the resident side is measured — which is what this is.
	const n = 20000

	s := newStore()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	s.reconcile(procs(n, 50), testBoot, at(0), 4, n*2, testRetention)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if s.entries() != n {
		t.Fatalf("entries = %d, want %d", s.entries(), n)
	}

	retained := after.HeapAlloc - before.HeapAlloc
	perProcess := retained / n
	slabPerProcess := uint64(unsafe.Sizeof(observation{}))
	trackedPerProcess := uint64(unsafe.Sizeof(tracked{}))

	t.Logf("%d processes: %d KiB retained = %d B/process "+
		"(observation slab %d B, tracked struct %d B, remainder %d B of map and pointer overhead)",
		n, retained/1024, perProcess, slabPerProcess, trackedPerProcess,
		perProcess-slabPerProcess-trackedPerProcess)

	// The ceiling that matters operationally: at the default max_tracked of
	// 16384 the state table must stay in single-digit megabytes, and a
	// fifty-thousand-process host must stay inside the 10-20 MB budget.
	const ceiling = 600
	if perProcess > ceiling {
		t.Errorf("%d bytes per tracked process, above the %d-byte design ceiling",
			perProcess, ceiling)
	}
	if projected := perProcess * uint64(DefaultSettings().MaxTracked); projected > 12<<20 {
		t.Errorf("at the default max_tracked of %d this is %d MiB, above the budget",
			DefaultSettings().MaxTracked, projected>>20)
	}
}

func TestDetailReadsHappenOnlyForSelectedProcesses(t *testing.T) {
	// The whole cost model rests on this: expensive reads must not happen for
	// processes that were already discarded.
	l := &fakeLister{}
	l.set(procs(1000, 20))
	d := newFakeDetail()
	h := newHarness(t, fullSet(l, d), map[string]string{
		"max_processes":           "10",
		"collect.open_files":      "true",
		"collect.executable_path": "true",
		"collect.command_line":    "true",
	})
	h.start()
	h.waitCycles(1)

	ioC, fileC, pathC, cmdC := d.counts()
	for name, got := range map[string]int{"io": ioC, "files": fileC, "path": pathC, "cmdline": cmdC} {
		if got > 10 {
			t.Errorf("%d %s reads for 1,000 processes with max_processes=10; "+
				"expensive reads must follow selection", got, name)
		}
		if got == 0 {
			t.Errorf("no %s reads happened at all", name)
		}
	}
	t.Logf("1,000 processes, max_processes=10: io=%d files=%d path=%d cmdline=%d",
		ioC, fileC, pathC, cmdC)
}

func TestPIDPreFilterAvoidsPerProcessWork(t *testing.T) {
	// include.pids is the one filter that can run before any per-process read,
	// which is why it is worth having despite seeing only the PID.
	l := &fakeLister{}
	l.set(procs(1000, 20))
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"include.pids": "1000-1009",
	})
	h.start()
	h.waitCycles(1)

	l.mu.Lock()
	accept := l.lastOpts.Accept
	l.mu.Unlock()
	if accept == nil {
		t.Fatal("the PID pre-filter was not passed to the reader")
	}
	if accept(5000) {
		t.Error("the pre-filter admitted a PID outside include.pids")
	}
	if !accept(1005) {
		t.Error("the pre-filter rejected a PID inside include.pids")
	}
	if v, _ := h.gauge(MetricCount); v != 10 {
		t.Errorf("process.count = %v, want 10", v)
	}
}

func TestUserReadIsOptedIntoNotAlwaysPaid(t *testing.T) {
	// On Linux the UID costs an extra stat(2) per process. At fifty thousand
	// processes that is fifty thousand syscalls for a field most deployments
	// never filter on.
	l := &fakeLister{}
	l.set(procs(10, 2))
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	l.mu.Lock()
	want := l.lastOpts.WantUser
	l.mu.Unlock()
	if want {
		t.Error("the reader was asked for user identity even though collect.user is off by default")
	}
}

func TestCollectionCycleAllocationsAreProportionalNotQuadratic(t *testing.T) {
	// Allocation per process must be a small constant. A per-process map, or a
	// string built per process per metric, would show up here as a step change.
	measure := func(n int) uint64 {
		s := newStore()
		infos := procs(n, 30)
		s.reconcile(infos, testBoot, at(0), 4, n*2, testRetention)

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		s.reconcile(infos, testBoot, at(30), 4, n*2, testRetention)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / uint64(n)
	}

	small := measure(1000)
	large := measure(20000)
	t.Logf("steady-state reconcile: %d bytes/process at 1,000; %d bytes/process at 20,000",
		small, large)

	if large > small*2 && large > 400 {
		t.Errorf("allocation per process grew from %d to %d bytes between 1,000 and 20,000 processes",
			small, large)
	}
}

func TestSelfTelemetryCarriesOnlyTheHostEntity(t *testing.T) {
	// The module's own metrics must never gain a per-process dimension.
	l := &fakeLister{}
	l.set(procs(500, 10))
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	entity := platform.A(AttrEntityID, testEntity)
	for _, name := range []string{MetricDiscovered, MetricSelected, MetricFiltered,
		MetricStateEntries, MetricExecutables} {
		if _, ok := h.tel.GaugeValue(name, entity); !ok {
			t.Errorf("%s was not emitted with exactly the host entity attribute", name)
		}
		if got := h.tel.SeriesCount(name); got != 1 {
			t.Errorf("%s has %d series, want exactly 1", name, got)
		}
	}
}
