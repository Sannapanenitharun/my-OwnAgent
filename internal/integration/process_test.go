package integration

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/modules/host"
	"github.com/obsagent/observability-agent/internal/modules/process"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
	"github.com/obsagent/observability-agent/internal/supervisor"
)

// The real supervisor, the real process module, the real operating system.
// Everything below runs against the machine executing the test.

type procRig struct {
	t     *testing.T
	sup   *supervisor.Supervisor
	tel   *inproc.Telemetry
	rt    *inproc.CapabilityRuntime
	diags *diagnostics.Recorder
	mod   *process.Module
}

func newProcRig(t *testing.T, mc config.ModuleConfig, grant bool, extra ...module.Module) *procRig {
	t.Helper()

	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = map[string]config.ModuleConfig{string(process.ID): mc}
	cfg.Agent.HealthInterval = config.D(time.Second)
	cfg.Agent.HealthProbeTimeout = config.D(time.Second)

	tel := inproc.NewTelemetry()
	rt := inproc.NewCapabilityRuntime()
	if grant {
		rt.Grant(string(process.ID), process.PermissionRead)
	}
	diags := diagnostics.NewRecorder(512)

	sup, err := supervisor.New(supervisor.Options{
		Config: cfg,
		Ports: platform.Ports{
			Runtime:   rt,
			Telemetry: tel,
			Identity:  inproc.NewIdentity("agent-1", "tenant-1", "ent-host-1"),
			Clock:     platform.NewSystemClock(),
		},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Diagnostics: diags,
	})
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}

	mod := process.New()
	if err := sup.Register(mod); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, m := range extra {
		if err := sup.Register(m); err != nil {
			t.Fatalf("register: %v", err)
		}
	}

	r := &procRig{t: t, sup: sup, tel: tel, rt: rt, diags: diags, mod: mod}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = sup.Shutdown(ctx)
	})
	return r
}

func procEnabled(settings map[string]string) config.ModuleConfig {
	return config.ModuleConfig{Enabled: true, Settings: settings}
}

// waitCycles blocks until n collection cycles have COMPLETED.
//
// This exists because waiting on a proxy signal — the first metric, the first
// event — races with the rest of the cycle: aggregates are emitted at the top,
// rollups in the middle, top-N events at the end. Three tests were written
// against a proxy and three of them flaked on a loaded machine. The cycle
// counter is the only signal that means "everything this cycle produces has
// been produced".
func (r *procRig) waitCycles(n int64) {
	r.t.Helper()
	eventually(r.t, "process collection cycles", func() bool {
		return r.mod.Statistics(context.Background()).Counters["cycles"] >= n
	})
}

// TestProcessModuleProducesRealTelemetryUnderTheSupervisor is the Phase 3
// acceptance test: the agent, as shipped, collects real process telemetry from
// the machine running it.
func TestProcessModuleProducesRealTelemetryUnderTheSupervisor(t *testing.T) {
	r := newProcRig(t, procEnabled(nil), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if st, _ := r.sup.State(process.ID); st != module.StateRunning {
		t.Fatalf("module state = %v, want running", st)
	}

	r.waitCycles(1)

	entity := platform.A(process.AttrEntityID, "ent-host-1")
	count, ok := r.tel.GaugeValue(process.MetricCount, entity)
	if !ok {
		t.Fatal("process.count was not bound to the host entity")
	}
	// Tiny CI containers (and some sandboxes) legitimately run only a handful
	// of processes; require at least this test process and one peer.
	if count < 2 {
		t.Errorf("process.count = %v; expected at least this process and one other", count)
	}

	// Per-executable rollups must exist and must be bounded.
	n := r.tel.SeriesCount(process.MetricInstances)
	if n == 0 {
		t.Error("no per-executable rollups were emitted")
	}
	if n > 128 {
		t.Errorf("%d executable series, above the default max_executables of 128", n)
	}

	t.Logf("%s: process.count=%v, %d executable series",
		runtime.GOOS, count, r.tel.SeriesCount(process.MetricInstances))
}

func TestProcessModuleWithoutPermissionNeverRuns(t *testing.T) {
	// Fail closed: a module that is not admitted never has its code run.
	r := newProcRig(t, procEnabled(nil), false)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	eventually(t, "the module to be refused", func() bool {
		st, _ := r.sup.State(process.ID)
		return st != module.StateRunning
	})
	if _, ok := r.tel.GaugeValue(process.MetricCount,
		platform.A(process.AttrEntityID, "ent-host-1")); ok {
		t.Error("an unauthorized module emitted telemetry")
	}
}

func TestDisabledProcessModuleDoesNothingAtAll(t *testing.T) {
	before := runtime.NumGoroutine()

	r := newProcRig(t, config.ModuleConfig{Enabled: false}, true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if _, ok := r.tel.GaugeValue(process.MetricCount,
		platform.A(process.AttrEntityID, "ent-host-1")); ok {
		t.Error("a disabled module collected telemetry")
	}
	if got := runtime.NumGoroutine(); got > before+6 {
		t.Errorf("goroutines went from %d to %d with the module disabled", before, got)
	}
	agg := r.sup.Health()
	if _, ok := agg.Component(string(process.ID)); ok {
		t.Error("a disabled module appears in health aggregation")
	}
}

// TestHostAndProcessModulesCoexist proves the two collectors are genuinely
// independent: both run, neither can see the other, and their telemetry does
// not collide.
func TestHostAndProcessModulesCoexist(t *testing.T) {
	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = map[string]config.ModuleConfig{
		string(host.ID):    {Enabled: true},
		string(process.ID): {Enabled: true},
	}
	cfg.Agent.HealthInterval = config.D(time.Second)
	cfg.Agent.HealthProbeTimeout = config.D(time.Second)

	tel := inproc.NewTelemetry()
	rt := inproc.NewCapabilityRuntime()
	rt.Grant(string(host.ID), host.PermissionRead)
	rt.Grant(string(process.ID), process.PermissionRead)

	sup, err := supervisor.New(supervisor.Options{
		Config: cfg,
		Ports: platform.Ports{
			Runtime:   rt,
			Telemetry: tel,
			Identity:  inproc.NewIdentity("agent-1", "tenant-1", "ent-host-1"),
			Clock:     platform.NewSystemClock(),
		},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Diagnostics: diagnostics.NewRecorder(512),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Register(host.New()); err != nil {
		t.Fatal(err)
	}
	if err := sup.Register(process.New()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = sup.Shutdown(ctx)
	})

	if err := sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	entity := platform.A("entity.id", "ent-host-1")
	eventually(t, "both modules to emit", func() bool {
		_, h := tel.GaugeValue(host.MetricMemoryTotal, entity)
		_, p := tel.GaugeValue(process.MetricCount, entity)
		return h && p
	})

	// Both are running, and both report their own health independently.
	agg := sup.Health()
	if len(agg.Components) != 2 {
		t.Fatalf("health has %d components, want 2", len(agg.Components))
	}
	for _, c := range agg.Components {
		if c.Report.Status == health.Unhealthy {
			t.Errorf("module %s is unhealthy: %s", c.ID, c.Report.Message)
		}
	}
}

// TestProcessModuleSurvivesConfigurationReload exercises the real reload
// transaction through the supervisor.
func TestProcessModuleSurvivesConfigurationReload(t *testing.T) {
	r := newProcRig(t, procEnabled(nil), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.waitCycles(1)

	// A valid reload applies.
	cfg := config.Default()
	cfg.Revision = 2
	cfg.Modules = map[string]config.ModuleConfig{
		string(process.ID): procEnabled(map[string]string{"max_executables": "16"}),
	}
	if err := r.sup.Reload(t.Context(), cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if st, _ := r.sup.State(process.ID); st != module.StateRunning {
		t.Errorf("module state after reload = %v, want running", st)
	}

	// An invalid reload is rejected whole, and the module keeps running.
	bad := config.Default()
	bad.Revision = 3
	bad.Modules = map[string]config.ModuleConfig{
		string(process.ID): procEnabled(map[string]string{"max_processes": "not-a-number"}),
	}
	if err := r.sup.Reload(t.Context(), bad); err == nil {
		t.Fatal("an invalid configuration was accepted")
	}
	if st, _ := r.sup.State(process.ID); st != module.StateRunning {
		t.Errorf("module state after a rejected reload = %v, want running", st)
	}
	r.waitCycles(1)
}

// TestProcessModuleShutsDownCleanly checks the whole stop path under the real
// supervisor, including that no goroutine outlives it.
func TestProcessModuleShutsDownCleanly(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	r := newProcRig(t, procEnabled(map[string]string{
		"interval":           "1s",
		"collection.timeout": "900ms",
	}), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.waitCycles(1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := r.sup.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines went from %d to %d across a full start/stop cycle", before, after)
	}
}

// TestProcessTelemetryFlowsThroughTheExistingPortOnly asserts the module built
// no pipeline of its own.
func TestProcessTelemetryFlowsThroughTheExistingPortOnly(t *testing.T) {
	r := newProcRig(t, procEnabled(map[string]string{"events.top_n": "3"}), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.waitCycles(1)

	// Metrics AND events both arrive at the same platform.Telemetry port.
	if _, ok := r.tel.GaugeValue(process.MetricCount,
		platform.A(process.AttrEntityID, "ent-host-1")); !ok {
		t.Fatal("no metrics reached the telemetry port")
	}

	var lifecycle, top int
	for _, ev := range r.tel.Events() {
		switch ev.Name {
		case process.EventStarted, process.EventExited, process.EventReplaced, process.EventChurn:
			lifecycle++
		case process.EventTop:
			top++
		}
	}
	if lifecycle == 0 {
		t.Error("no lifecycle events reached the telemetry port")
	}
	if top == 0 {
		t.Error("events.top_n was configured but produced nothing")
	}
	if top > 3 {
		t.Errorf("%d top-N events emitted with events.top_n=3", top)
	}
	t.Logf("events through the platform port: %d lifecycle, %d top-N", lifecycle, top)
}
