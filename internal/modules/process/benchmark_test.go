package process

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/clockfake"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// Benchmarks at the four scales the module claims to support. The point is not
// a single number but the SHAPE: cost must be linear in process count, and the
// per-process constant must be small enough that a fifty-thousand-process host
// spends a fraction of one core-second per interval.

var benchScales = []struct {
	name string
	n    int
}{
	{"100", 100},
	{"1K", 1000},
	{"10K", 10000},
	{"50K", 50000},
}

// nopTelemetry terminates telemetry immediately, so benchmarks measure the
// module rather than the in-memory adapter's map operations.
type nopTelemetry struct{}

func (nopTelemetry) Counter(string) platform.Counter     { return nopInstrument{} }
func (nopTelemetry) Gauge(string) platform.Gauge         { return nopInstrument{} }
func (nopTelemetry) Histogram(string) platform.Histogram { return nopInstrument{} }
func (nopTelemetry) Emit(platform.Event)                 {}
func (nopTelemetry) EmitLog(platform.LogRecord)          {}
func (nopTelemetry) IngestTraces(platform.TracePayload)  {}

type nopInstrument struct{}

func (nopInstrument) Add(int64, ...platform.Attr)       {}
func (nopInstrument) Set(float64, ...platform.Attr)     {}
func (nopInstrument) Observe(float64, ...platform.Attr) {}

// benchModule builds a started module wired to discarding telemetry.
func benchModule(b *testing.B, l *fakeLister, settings map[string]string) *Module {
	b.Helper()
	m := NewWithSet(fullSet(l, newFakeDetail()))
	h := module.Host{
		ID:            ID,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Telemetry:     nopTelemetry{},
		Clock:         clockfake.New(time.Time{}),
		Identity:      inproc.NewIdentity("a", "t", "ent-host-1"),
		Diagnostics:   diagnostics.Scoped(string(ID), diagnostics.NewRecorder(64)),
		Config:        config.ModuleConfig{Enabled: true, Settings: settings},
		Authorize:     func(context.Context, platform.Permission) error { return nil },
		ReportFailure: func(error) {},
	}
	// Start would launch the collection goroutine; the benchmarks drive
	// runCycle directly so that they measure collection rather than scheduling.
	m.settings, _ = ParseSettings(h.Config)
	m.host = h
	m.inst = newInstruments(h.Telemetry)
	m.em = newEmitter(m.inst, m.settings)
	m.res = newResolver(h.Identity)
	m.res.setHostEntity("ent-host-1")
	m.em.setEntity("ent-host-1")
	m.entityID = "ent-host-1"
	m.selfAttr = []platform.Attr{platform.A(AttrEntityID, "ent-host-1")}
	m.bootID = "boot-bench"
	b.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m
}

func benchSettings(n int) map[string]string {
	return map[string]string{
		"max_processes":   "1000",
		"max_executables": "128",
		"max_tracked":     "100000",
	}
}

// BenchmarkFullCollection is the headline number: one complete cycle at each
// scale, with the default configuration.
func BenchmarkFullCollection(b *testing.B) {
	for _, sc := range benchScales {
		b.Run(sc.name, func(b *testing.B) {
			l := &fakeLister{}
			l.set(procs(sc.n, 60))
			m := benchModule(b, l, benchSettings(sc.n))

			ctx := b.Context()
			// One warm-up cycle so the state table is populated and the
			// measured cycles are steady-state rather than first-contact.
			if _, err := m.runCycle(ctx, time.Unix(0, 0)); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.runCycle(ctx, time.Unix(int64(i+1)*30, 0)); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(sc.n), "ns/process")
		})
	}
}

// BenchmarkEnumerationAndReconcile isolates the part whose cost is linear in
// the process count, from the part bounded by max_processes.
func BenchmarkReconcile(b *testing.B) {
	for _, sc := range benchScales {
		b.Run(sc.name, func(b *testing.B) {
			infos := procs(sc.n, 60)
			s := newStore()
			s.reconcile(infos, "boot", time.Unix(0, 0), 8, 100000, time.Minute)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.reconcile(infos, "boot", time.Unix(int64(i+1)*30, 0), 8, 100000, time.Minute)
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(sc.n), "ns/process")
		})
	}
}

// BenchmarkFilteredCollection shows what an operator buys by narrowing the
// filters: the expensive stages shrink while enumeration does not.
func BenchmarkFilteredCollection(b *testing.B) {
	for _, sc := range benchScales {
		b.Run(sc.name, func(b *testing.B) {
			l := &fakeLister{}
			l.set(procs(sc.n, 60))
			m := benchModule(b, l, map[string]string{
				"max_processes": "1000",
				"max_tracked":   "100000",
				"include.names": "proc1",
			})
			ctx := b.Context()
			m.runCycle(ctx, time.Unix(0, 0))

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.runCycle(ctx, time.Unix(int64(i+1)*30, 0)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkHighChurn measures the worst realistic case: half the process table
// replaced every cycle, which is where lifecycle bookkeeping and event budgets
// are actually exercised.
func BenchmarkHighChurn(b *testing.B) {
	for _, sc := range []struct {
		name string
		n    int
	}{{"1K", 1000}, {"10K", 10000}} {
		b.Run(sc.name, func(b *testing.B) {
			l := &fakeLister{}
			l.set(churnSet(0, sc.n, sc.n/2, 60))
			m := benchModule(b, l, benchSettings(sc.n))
			ctx := b.Context()
			m.runCycle(ctx, time.Unix(0, 0))

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				l.set(churnSet(i+1, sc.n, sc.n/2, 60))
				b.StartTimer()
				if _, err := m.runCycle(ctx, time.Unix(int64(i+1)*30, 0)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRollup isolates the aggregation that turns N processes into at most
// max_executables series.
func BenchmarkRollup(b *testing.B) {
	for _, sc := range benchScales {
		b.Run(sc.name, func(b *testing.B) {
			s := newStore()
			obs, _, _ := s.reconcile(procs(sc.n, 60), "boot", time.Unix(0, 0), 8, 100000, time.Minute)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := rollupBy(obs)
				selectExecutables(r, 128)
			}
		})
	}
}

// BenchmarkSelection measures the deterministic sort that enforces
// max_processes.
func BenchmarkSelection(b *testing.B) {
	for _, sc := range benchScales {
		b.Run(sc.name, func(b *testing.B) {
			s := newStore()
			obs, _, _ := s.reconcile(procs(sc.n, 60), "boot", time.Unix(0, 0), 8, 100000, time.Minute)
			settings := DefaultSettings()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				settings.selectProcesses(obs)
			}
		})
	}
}

// BenchmarkParseStat is the per-process Linux hot path. At fifty thousand
// processes this runs fifty thousand times per cycle, so its constant is the
// one that decides whether the module is affordable on a large Linux host.
func BenchmarkParseStat(b *testing.B) {
	line := []byte(realStatLine)
	var fields [][]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if _, fields, err = parseStat(line, 4096, fields); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSanitiseName(b *testing.B) {
	b.Run("clean", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sanitiseName("nginx")
		}
	})
	b.Run("hostile", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sanitiseName("evil\n\x1b[2Jname\x00with\tcontrol")
		}
	})
}

// BenchmarkEntityResolution measures the cost when every process is new, which
// is the worst case the cache is designed to avoid in steady state.
func BenchmarkEntityResolution(b *testing.B) {
	id := inproc.NewIdentity("a", "t", "ent-host-1")
	r := newResolver(id)
	r.setHostEntity("ent-host-1")
	key := InstanceKey{Boot: "boot", PID: 1234, Start: 5678, HasStart: true}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := r.resolve(b.Context(), key, "nginx"); !ok {
			b.Fatal("resolution failed")
		}
	}
}

// TestStateTableFootprintAtScale reports the real retained memory of the state
// table at each scale, so the documentation can quote measurements.
func TestStateTableFootprintAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("footprint measurement is slow")
	}
	for _, sc := range benchScales {
		s := newStore()
		infos := procs(sc.n, 60)

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		s.reconcile(infos, "boot", time.Unix(0, 0), 8, 100000, time.Minute)

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		// Guarded subtraction: at small n the GC can free more than the store
		// allocated, and an unsigned underflow reports eighteen petabytes.
		var retained uint64
		if after.HeapAlloc > before.HeapAlloc {
			retained = after.HeapAlloc - before.HeapAlloc
		}
		t.Logf("%-4s processes: %d entries, %6d KiB retained, %4d bytes/process",
			sc.name, s.entries(), retained/1024, retained/uint64(sc.n))
	}
}
