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
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
	"github.com/obsagent/observability-agent/internal/supervisor"
)

type rig struct {
	t     *testing.T
	sup   *supervisor.Supervisor
	tel   *inproc.Telemetry
	rt    *inproc.CapabilityRuntime
	diags *diagnostics.Recorder
	mod   *host.Module
}

func newRig(t *testing.T, mc config.ModuleConfig, grant bool) *rig {
	t.Helper()

	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = map[string]config.ModuleConfig{string(host.ID): mc}
	cfg.Agent.HealthInterval = config.D(time.Second)
	cfg.Agent.HealthProbeTimeout = config.D(time.Second)

	tel := inproc.NewTelemetry()
	rt := inproc.NewCapabilityRuntime()
	if grant {
		rt.Grant(string(host.ID), host.PermissionRead)
	}
	diags := diagnostics.NewRecorder(256)

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

	mod := host.New()
	if err := sup.Register(mod); err != nil {
		t.Fatalf("register: %v", err)
	}

	r := &rig{t: t, sup: sup, tel: tel, rt: rt, diags: diags, mod: mod}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = sup.Shutdown(ctx)
	})
	return r
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func enabled() config.ModuleConfig  { return config.ModuleConfig{Enabled: true} }
func disabled() config.ModuleConfig { return config.ModuleConfig{Enabled: false} }

// TestHostModuleProducesRealTelemetryUnderTheSupervisor is the end-to-end
// acceptance test for Stage 2: the agent, as shipped, collects real host
// telemetry from the machine running the test.
func TestHostModuleProducesRealTelemetryUnderTheSupervisor(t *testing.T) {
	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if st, _ := r.sup.State(host.ID); st != module.StateRunning {
		t.Fatalf("module state = %v, want running", st)
	}

	entity := platform.A(host.AttrEntityID, "ent-host-1")
	eventually(t, "memory telemetry bound to the host entity", func() bool {
		_, ok := r.tel.GaugeValue(host.MetricMemoryTotal, entity)
		return ok
	})

	total, _ := r.tel.GaugeValue(host.MetricMemoryTotal, entity)
	if total < 64<<20 {
		t.Fatalf("total memory %v is implausible", total)
	}
	if _, ok := r.tel.GaugeValue(host.MetricCPUCount, entity, platform.A(host.AttrType, "logical")); !ok {
		t.Fatal("CPU count was not emitted")
	}
	// host.info is collected by the OS source, which the run loop reaches AFTER
	// memory in the same cycle. Asserting on it immediately after waiting for
	// memory therefore races, and on a loaded machine it loses — which is
	// exactly how this presented: a test that passed alone and failed in a full
	// run. Waiting for the thing being asserted removes the assumption about
	// intra-cycle ordering rather than relying on it.
	eventually(t, "host.info emitted as a single labelled series", func() bool {
		_, ok := r.tel.GaugeValue(host.MetricInfo,
			entity,
			platform.A(host.AttrInfoOS, runtime.GOOS),
			platform.A(host.AttrInfoPlatform, hostPlatform(t, r)),
			platform.A(host.AttrInfoVersion, hostVersion(t, r)),
			platform.A(host.AttrInfoKernel, hostKernel(t, r)),
			platform.A(host.AttrInfoArch, runtime.GOARCH),
		)
		return ok
	})
}

// hostPlatform/hostVersion/hostKernel read back what the module reported, so
// the assertion above checks the shape of host.info without hardcoding values
// that differ per machine.
func hostPlatform(t *testing.T, r *rig) string { return infoAttr(t, r, host.AttrInfoPlatform) }
func hostVersion(t *testing.T, r *rig) string  { return infoAttr(t, r, host.AttrInfoVersion) }
func hostKernel(t *testing.T, r *rig) string   { return infoAttr(t, r, host.AttrInfoKernel) }

func infoAttr(t *testing.T, r *rig, key string) string {
	t.Helper()
	set := host.NewSet()
	if set.OS == nil {
		return ""
	}
	info, err := set.OS.ReadOS(t.Context())
	if err != nil {
		return ""
	}
	switch key {
	case host.AttrInfoPlatform:
		return info.Platform
	case host.AttrInfoVersion:
		return info.PlatformVersion
	case host.AttrInfoKernel:
		return info.KernelVersion
	}
	return ""
}

func TestAgentHealthReflectsPlatformCapabilityGaps(t *testing.T) {
	// On Windows two of seven sources are unavailable by design, and on macOS
	// three are. That must read as degraded, never as failure — otherwise
	// every host in a mixed fleet reports a broken agent.
	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	eventually(t, "the first health probe", func() bool {
		c, ok := r.sup.Health().Component(string(host.ID))
		return ok && c.Report.Status != health.Unknown
	})

	c, _ := r.sup.Health().Component(string(host.ID))
	set := host.NewSet()
	complete := len(set.Available()) == len(host.AllSources)

	switch {
	case complete && c.Report.Status != health.Healthy:
		t.Fatalf("all sources available but health = %v: %s", c.Report.Status, c.Report.Message)
	case !complete && c.Report.Status != health.Degraded:
		t.Fatalf("%d/%d sources available but health = %v: %s",
			len(set.Available()), len(host.AllSources), c.Report.Status, c.Report.Message)
	}
	t.Logf("%d/%d sources available on %s: health=%v (%s)",
		len(set.Available()), len(host.AllSources), runtime.GOOS, c.Report.Status, c.Report.Message)
}

func TestUnsupportedSourcesAppearAsCapabilitiesAndDiagnostics(t *testing.T) {
	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	snap := r.sup.Snapshot(t.Context())
	var status supervisor.ModuleStatus
	for _, m := range snap.Modules {
		if m.ID == host.ID {
			status = m
		}
	}
	if len(status.Capabilities) != len(host.AllSources) {
		t.Fatalf("reported %d capabilities, want %d", len(status.Capabilities), len(host.AllSources))
	}
	for _, c := range status.Capabilities {
		if !c.Available && c.Reason == "" {
			t.Errorf("capability %q is unavailable with no reason", c.Name)
		}
	}

	set := host.NewSet()
	if len(set.Available()) < len(host.AllSources) {
		var found bool
		for _, rec := range r.diags.BySource(string(host.ID)) {
			if rec.Code == diagnostics.CodeUnsupported {
				found = true
			}
		}
		if !found {
			t.Error("no unsupported diagnostic was recorded for an absent source")
		}
	}
}

func TestDisabledModuleDoesNothingAtAll(t *testing.T) {
	// The requirement is zero collection goroutines, zero timers, zero work.
	before := runtime.NumGoroutine()

	r := newRig(t, disabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	if st, _ := r.sup.State(host.ID); st != module.StateDisabled {
		t.Fatalf("state = %v, want disabled", st)
	}
	time.Sleep(100 * time.Millisecond)

	if after := runtime.NumGoroutine(); after > before+3 {
		t.Fatalf("a disabled module added goroutines: %d -> %d", before, after)
	}
	if r.tel.SeriesCount(host.MetricMemoryTotal) != 0 {
		t.Fatal("a disabled module emitted telemetry")
	}
	if r.rt.ActiveCount() != 0 {
		t.Fatal("a disabled module holds a capability admission")
	}
	// And it is excluded from health entirely: an operator who turned it off
	// did not ask to be told the agent is degraded because it is off.
	if _, ok := r.sup.Health().Component(string(host.ID)); ok {
		t.Fatal("a disabled module appeared in the health aggregate")
	}
}

func TestDeniedPermissionStopsTheModuleNotTheAgent(t *testing.T) {
	r := newRig(t, enabled(), false) // no grant
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatalf("the agent must start even when a module is refused: %v", err)
	}

	st, _ := r.sup.State(host.ID)
	if st == module.StateRunning {
		t.Fatal("a module with no permission grant is running")
	}
	if r.tel.SeriesCount(host.MetricMemoryTotal) != 0 {
		t.Fatal("a refused module collected telemetry")
	}
	// The module is optional by default, so the agent degrades rather than
	// failing.
	if got := r.sup.Health().Status; got == health.Healthy {
		t.Fatal("agent reports healthy while its only module is refused")
	}
}

func TestConfigurationReloadRetunesTheModuleInPlace(t *testing.T) {
	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "initial collection", func() bool {
		_, ok := r.tel.GaugeValue(host.MetricMemoryTotal, platform.A(host.AttrEntityID, "ent-host-1"))
		return ok
	})

	next := config.Default()
	next.Revision = 2
	next.Agent.HealthInterval = config.D(time.Second)
	next.Agent.HealthProbeTimeout = config.D(time.Second)
	next.Modules = map[string]config.ModuleConfig{
		string(host.ID): {Enabled: true, Settings: map[string]string{
			"interval.cpu":     "30s",
			"metrics.disabled": host.MetricMemoryUtilization,
		}},
	}
	if err := r.sup.Reload(t.Context(), next); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if st, _ := r.sup.State(host.ID); st != module.StateRunning {
		t.Fatalf("module state after reload = %v, want running (it must not restart)", st)
	}
	if r.sup.Snapshot(t.Context()).ConfigRevision != 2 {
		t.Fatal("configuration revision did not advance")
	}
}

func TestRejectedReloadLeavesTheModuleUntouched(t *testing.T) {
	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	bad := config.Default()
	bad.Revision = 2
	bad.Modules = map[string]config.ModuleConfig{
		string(host.ID): {Enabled: true, Settings: map[string]string{"interval.cpu": "1ms"}},
	}
	if err := r.sup.Reload(t.Context(), bad); err == nil {
		t.Fatal("a sub-second interval must be rejected by the module during prepare")
	}

	if st, _ := r.sup.State(host.ID); st != module.StateRunning {
		t.Fatalf("state = %v; a rejected reload must change nothing", st)
	}
	if r.sup.Snapshot(t.Context()).ConfigRevision != 1 {
		t.Fatal("a rejected reload advanced the configuration revision")
	}
}

func TestEnablingAndDisablingThroughReload(t *testing.T) {
	r := newRig(t, disabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.sup.State(host.ID); st != module.StateDisabled {
		t.Fatalf("state = %v, want disabled", st)
	}

	on := config.Default()
	on.Revision = 2
	on.Modules = map[string]config.ModuleConfig{string(host.ID): enabled()}
	if err := r.sup.Reload(t.Context(), on); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if st, _ := r.sup.State(host.ID); st != module.StateRunning {
		t.Fatalf("state = %v after enabling, want running", st)
	}
	eventually(t, "telemetry after enabling", func() bool {
		_, ok := r.tel.GaugeValue(host.MetricMemoryTotal, platform.A(host.AttrEntityID, "ent-host-1"))
		return ok
	})

	off := config.Default()
	off.Revision = 3
	off.Modules = map[string]config.ModuleConfig{string(host.ID): disabled()}
	if err := r.sup.Reload(t.Context(), off); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if st, _ := r.sup.State(host.ID); st != module.StateDisabled {
		t.Fatalf("state = %v after disabling, want disabled", st)
	}
}

func TestShutdownReleasesEverything(t *testing.T) {
	before := runtime.NumGoroutine()

	r := newRig(t, enabled(), true)
	if err := r.sup.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "collection to begin", func() bool {
		_, ok := r.tel.GaugeValue(host.MetricMemoryTotal, platform.A(host.AttrEntityID, "ent-host-1"))
		return ok
	})

	if err := r.sup.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if r.rt.ActiveCount() != 0 {
		t.Fatal("shutdown left a capability admission held")
	}
	eventually(t, "goroutines to return to baseline", func() bool {
		return runtime.NumGoroutine() <= before+2
	})
}

// BenchmarkAgentWithHostModule measures startup of the whole agent with the
// host module registered — the number an operator experiences on install.
func BenchmarkAgentWithHostModule(b *testing.B) {
	cfg := config.Default()
	cfg.Revision = 1
	cfg.Modules = map[string]config.ModuleConfig{string(host.ID): {Enabled: true}}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		rt := inproc.NewCapabilityRuntime()
		rt.Grant(string(host.ID), host.PermissionRead)
		sup, err := supervisor.New(supervisor.Options{
			Config: cfg,
			Ports: platform.Ports{
				Runtime:   rt,
				Telemetry: inproc.NewTelemetry(),
				Identity:  inproc.NewIdentity("a", "t", "h"),
				Clock:     platform.NewSystemClock(),
			},
			Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
			Diagnostics: diagnostics.NewRecorder(256),
		})
		if err != nil {
			b.Fatal(err)
		}
		if err := sup.Register(host.New()); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if err := sup.Start(context.Background()); err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		if err := sup.Shutdown(context.Background()); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
