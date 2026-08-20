package supervisor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// benchModuleSet builds a module set shaped like the finished agent: a
// scrubber, the otel engine on top of it, discovery, and the seven collectors.
// Benchmarking a realistic graph matters — startup cost is dominated by
// dependency ordering, not by module count alone.
func benchModuleSet() ([]module.Module, map[string]config.ModuleConfig) {
	specs := []struct {
		id   string
		deps []module.ID
	}{
		{"secret-scrubber", nil},
		{"otel-engine", []module.ID{"secret-scrubber"}},
		{"discovery", []module.ID{"otel-engine"}},
		{"host", []module.ID{"otel-engine", "discovery"}},
		{"process", []module.ID{"otel-engine", "discovery"}},
		{"logs", []module.ID{"otel-engine"}},
		{"network", []module.ID{"otel-engine", "discovery"}},
		{"ebpf", []module.ID{"otel-engine"}},
		{"security", []module.ID{"otel-engine", "discovery"}},
		{"profiler", []module.ID{"otel-engine"}},
		{"updater", nil},
	}

	mods := make([]module.Module, 0, len(specs))
	cfgModules := make(map[string]config.ModuleConfig, len(specs))
	for _, s := range specs {
		mods = append(mods, newTestModule(s.id, s.deps...))
		cfgModules[s.id] = config.ModuleConfig{Enabled: true}
	}
	return mods, cfgModules
}

func newBenchSupervisor(b *testing.B) (*Supervisor, []module.Module) {
	b.Helper()
	mods, cfgModules := benchModuleSet()
	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = cfgModules

	sup, err := New(Options{
		Config: cfg,
		Ports: platform.Ports{
			Runtime:   inproc.NewCapabilityRuntime(),
			Telemetry: inproc.NewTelemetry(),
			Identity:  inproc.NewIdentity("agent", "tenant", "host"),
			Clock:     platform.NewSystemClock(),
		},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Diagnostics: diagnostics.NewRecorder(cfg.Agent.DiagnosticsRetention),
	})
	if err != nil {
		b.Fatal(err)
	}
	for _, m := range mods {
		if err := sup.Register(m); err != nil {
			b.Fatal(err)
		}
	}
	return sup, mods
}

// BenchmarkStartupToRunning measures the supervisor's contribution to agent
// startup: dependency resolution, capability admission and module start for a
// full eleven-module graph. The target is a sub-second agent start, and this is
// the part of it the supervisor owns.
func BenchmarkStartupToRunning(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sup, _ := newBenchSupervisor(b)
		b.StartTimer()

		if err := sup.Start(ctx); err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		if err := sup.Shutdown(ctx); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// BenchmarkShutdown measures graceful shutdown of the same graph.
func BenchmarkShutdown(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sup, _ := newBenchSupervisor(b)
		if err := sup.Start(ctx); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if err := sup.Shutdown(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHealthAggregate measures the cost of the health path. It runs on
// every probe cycle and on every operator query, so it must stay cheap and, in
// particular, must not allocate per module per call in a way that grows with
// fleet-wide polling.
func BenchmarkHealthAggregate(b *testing.B) {
	ctx := context.Background()
	sup, _ := newBenchSupervisor(b)
	if err := sup.Start(ctx); err != nil {
		b.Fatal(err)
	}
	defer func() { _ = sup.Shutdown(ctx) }()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sup.Health()
	}
}

// BenchmarkSnapshot measures the full diagnostics surface.
func BenchmarkSnapshot(b *testing.B) {
	ctx := context.Background()
	sup, _ := newBenchSupervisor(b)
	if err := sup.Start(ctx); err != nil {
		b.Fatal(err)
	}
	defer func() { _ = sup.Shutdown(ctx) }()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sup.Snapshot(ctx)
	}
}

// BenchmarkResolveGraph isolates dependency resolution.
func BenchmarkResolveGraph(b *testing.B) {
	mods, _ := benchModuleSet()
	manifests := make(map[module.ID]module.Manifest, len(mods))
	for _, m := range mods {
		mf := m.Manifest()
		manifests[mf.ID] = mf
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Resolve(manifests); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveGraphLarge checks that resolution does not degrade badly as
// the module count grows well past what the agent will ship, so that adding
// capabilities later is never gated on this code path.
func BenchmarkResolveGraphLarge(b *testing.B) {
	const n = 500
	manifests := make(map[module.ID]module.Manifest, n)
	for i := 0; i < n; i++ {
		id := module.ID(fmt.Sprintf("m%03d", i))
		mf := module.Manifest{ID: id, Version: "1.0.0"}
		if i > 0 {
			mf.Dependencies = []module.ID{module.ID(fmt.Sprintf("m%03d", i-1))}
		}
		manifests[id] = mf
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Resolve(manifests); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSteadyStateResourceFootprint reports the supervisor's idle cost.
//
// It is a test rather than a benchmark because the interesting number is a
// level, not a rate: how much memory and how many goroutines a fully started
// agent holds while doing nothing. The assertions are deliberately loose
// ceilings that catch a regression in kind (an unbounded queue, a goroutine per
// module per tick) rather than pinning an exact number that would fail on a
// different machine.
func TestSteadyStateResourceFootprint(t *testing.T) {
	ctx := context.Background()
	mods, cfgModules := benchModuleSet()
	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = cfgModules
	cfg.Agent.HealthInterval = config.D(10 * time.Millisecond)
	cfg.Agent.HealthProbeTimeout = config.D(10 * time.Millisecond)

	baselineGoroutines := runtime.NumGoroutine()

	sup, err := New(Options{
		Config: cfg,
		Ports: platform.Ports{
			Runtime:   inproc.NewCapabilityRuntime(),
			Telemetry: inproc.NewTelemetry(),
			Identity:  inproc.NewIdentity("agent", "tenant", "host"),
			Clock:     platform.NewSystemClock(),
		},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Diagnostics: diagnostics.NewRecorder(cfg.Agent.DiagnosticsRetention),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mods {
		if err := sup.Register(m); err != nil {
			t.Fatal(err)
		}
	}

	start := time.Now()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	startup := time.Since(start)

	// Let several probe cycles run, which is where a per-tick goroutine leak
	// would show up.
	time.Sleep(250 * time.Millisecond)

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapMB := float64(ms.HeapAlloc) / (1 << 20)
	goroutines := runtime.NumGoroutine()

	t.Logf("supervisor steady state: startup=%v heap=%.2f MiB goroutines=%d (baseline %d) modules=%d",
		startup, heapMB, goroutines, baselineGoroutines, len(mods))

	if err := sup.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// One control loop, plus at most one in-flight operation per module. If
	// probes accumulated, this would be in the hundreds after 25 cycles.
	if maxGoroutines := baselineGoroutines + len(mods) + 8; goroutines > maxGoroutines {
		t.Errorf("goroutines = %d, want at most %d; probes or ops are accumulating",
			goroutines, maxGoroutines)
	}
	if startup > time.Second {
		t.Errorf("supervisor startup took %v, exceeding the sub-second target", startup)
	}

	// After shutdown the control loop must be gone.
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > baselineGoroutines+4 {
		t.Errorf("goroutines after shutdown = %d, baseline %d; shutdown leaked", after, baselineGoroutines)
	}
}
