package supervisor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func TestRegisterRejectsInvalidModules(t *testing.T) {
	h := newHarness(t, testConfig(nil))

	if err := h.sup.Register(nil); err == nil {
		t.Error("registering nil should fail")
	}

	noID := newTestModule("")
	if err := h.sup.Register(noID); err == nil {
		t.Error("a module with an empty ID should be rejected")
	}

	noVersion := newTestModule("a")
	noVersion.manifest.Version = ""
	if err := h.sup.Register(noVersion); err == nil {
		t.Error("a module with an empty version should be rejected")
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	if err := h.sup.Register(newTestModule("a")); err == nil {
		t.Fatal("registering the same module ID twice should fail")
	}
}

func TestRegisterAfterStartIsRejected(t *testing.T) {
	// The complete dependency graph must be known before anything runs, or
	// start order would depend on registration order.
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	h.start()
	if err := h.sup.Register(newTestModule("b")); err == nil {
		t.Fatal("registering after Start should fail")
	}
}

func TestRegisterSurvivesAPanickingManifest(t *testing.T) {
	h := newHarness(t, testConfig(nil))
	if err := h.sup.Register(&panicManifestModule{}); err == nil {
		t.Fatal("a module whose Manifest panics must be rejected, not crash the agent")
	}
}

// panicManifestModule panics in the one method the supervisor must call before
// it can know anything about the module at all.
type panicManifestModule struct{}

func (*panicManifestModule) Manifest() module.Manifest { panic("manifest exploded") }
func (*panicManifestModule) Start(context.Context, module.Host) error {
	return nil
}
func (*panicManifestModule) Stop(context.Context) error           { return nil }
func (*panicManifestModule) Health(context.Context) health.Report { return health.OK("") }

// ---------------------------------------------------------------------------
// Startup and shutdown ordering
// ---------------------------------------------------------------------------

func TestStartsInDependencyOrderAndStopsInReverse(t *testing.T) {
	rec := &orderRecorder{}
	scrubber := newTestModule("scrubber").recordOrder(rec)
	otel := newTestModule("otel", "scrubber").recordOrder(rec)
	host := newTestModule("host", "otel").recordOrder(rec)

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"scrubber": enabled(), "otel": enabled(), "host": enabled(),
	}), scrubber, otel, host)
	h.start()

	sStart, _ := scrubber.orders()
	oStart, _ := otel.orders()
	hStart, _ := host.orders()
	if !(sStart < oStart && oStart < hStart) {
		t.Fatalf("start order wrong: scrubber=%d otel=%d host=%d\n%s", sStart, oStart, hStart, h.describe())
	}

	if err := h.sup.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	_, sStop := scrubber.orders()
	_, oStop := otel.orders()
	_, hStop := host.orders()
	// Reverse order guarantees a module is never left running with a stopped
	// dependency.
	if !(hStop < oStop && oStop < sStop) {
		t.Fatalf("stop order wrong: host=%d otel=%d scrubber=%d", hStop, oStop, sStop)
	}
}

func TestStartRejectsDependencyCycle(t *testing.T) {
	// A structural failure must prevent startup; the agent cannot honour this
	// configuration at all.
	a := newTestModule("a", "b")
	b := newTestModule("b", "a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled(), "b": enabled()}), a, b)

	err := h.sup.Start(t.Context())
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("Start error = %v, want *CycleError", err)
	}
	if starts, _, _ := a.counts(); starts != 0 {
		t.Fatal("no module should have started when the graph is unresolvable")
	}
}

func TestStartRejectsDependencyOnDisabledModule(t *testing.T) {
	// Silently breaking the dependent would be worse than refusing: the
	// operator would believe a collector is working.
	a := newTestModule("a")
	b := newTestModule("b", "a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"a": {Enabled: false}, "b": enabled(),
	}), a, b)

	var mde *MissingDependencyError
	if err := h.sup.Start(t.Context()); !errors.As(err, &mde) {
		t.Fatalf("Start error = %v, want *MissingDependencyError", err)
	}
}

func TestDisabledModuleIsNeverStarted(t *testing.T) {
	off := newTestModule("off")
	on := newTestModule("on")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"off": {Enabled: false}, "on": enabled(),
	}), off, on)
	h.start()

	if starts, stops, _ := off.counts(); starts != 0 || stops != 0 {
		t.Fatalf("disabled module was touched: %d starts, %d stops", starts, stops)
	}
	if got := h.state("off"); got != module.StateDisabled {
		t.Fatalf("state = %v, want disabled", got)
	}
	// A disabled module must not appear in health at all: an operator who
	// turned a collector off did not ask to be told the agent is degraded.
	if _, ok := h.sup.Health().Component("off"); ok {
		t.Fatal("a disabled module appeared in the health aggregate")
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	m := newTestModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()

	for i := 0; i < 3; i++ {
		if err := h.sup.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown %d: %v", i, err)
		}
	}
	if _, stops, _ := m.counts(); stops != 1 {
		t.Fatalf("Stop called %d times across three Shutdowns, want 1", stops)
	}
}

func TestShutdownBeforeStartIsSafe(t *testing.T) {
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	if err := h.sup.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}
}

func TestSlowModuleDoesNotConsumeTheWholeShutdownBudget(t *testing.T) {
	// Without a per-module bound, one hung collector eats the entire budget
	// and the rest are never asked to stop.
	cfg := testConfig(map[string]config.ModuleConfig{"slow": enabled(), "fast": enabled()})
	cfg.Agent.ModuleStopTimeout = config.D(100 * time.Millisecond)
	cfg.Agent.ShutdownTimeout = config.D(3 * time.Second)

	slow := newTestModule("slow")
	slow.stopFn = func(ctx context.Context) error {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
		return ctx.Err()
	}
	fast := newTestModule("fast")

	h := newHarness(t, cfg, slow, fast)
	h.start()

	begin := time.Now()
	_ = h.sup.Shutdown(t.Context())
	elapsed := time.Since(begin)

	if elapsed > 2*time.Second {
		t.Fatalf("shutdown took %v; the per-module bound did not apply", elapsed)
	}
	if _, stops, _ := fast.counts(); stops != 1 {
		t.Fatal("the fast module was never asked to stop")
	}
}

// ---------------------------------------------------------------------------
// Failure isolation
// ---------------------------------------------------------------------------

func TestPanicDuringStartIsIsolated(t *testing.T) {
	// A nil map write in one collector must not take down the others.
	boom := newTestModule("boom")
	boom.startFn = func(context.Context, module.Host) error { panic("nil map write") }
	survivor := newTestModule("survivor")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"boom": enabled(), "survivor": enabled(),
	}), boom, survivor)
	h.start()

	if got := h.state("survivor"); got != module.StateRunning {
		t.Fatalf("survivor state = %v, want running", got)
	}
	if got := h.state("boom"); got != module.StateFailed {
		t.Fatalf("boom state = %v, want failed", got)
	}
	if !h.hasDiag("boom", diagnostics.CodePanic) {
		t.Fatal("no panic diagnostic was recorded")
	}
	if v, _ := h.tel.CounterValue(MetricModulePanics, platform.A(AttrModule, "boom")); v != 1 {
		t.Fatalf("panic counter = %d, want 1", v)
	}
}

func TestFailedModuleDoesNotAffectUnrelatedSiblings(t *testing.T) {
	bad := newTestModule("bad")
	bad.startFn = func(context.Context, module.Host) error { return errors.New("no such device") }

	good1, good2 := newTestModule("good1"), newTestModule("good2")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"bad": enabled(), "good1": enabled(), "good2": enabled(),
	}), bad, good1, good2)
	h.start()

	for _, id := range []string{"good1", "good2"} {
		if got := h.state(id); got != module.StateRunning {
			t.Errorf("%s state = %v, want running", id, got)
		}
	}
	if got := h.state("bad"); got != module.StateFailed {
		t.Errorf("bad state = %v, want failed", got)
	}
}

func TestFailedStartReceivesACleanupStop(t *testing.T) {
	// Start can fail after acquiring resources. Without a cleanup Stop, every
	// failed start leaks, and a crash-looping module leaks repeatedly.
	m := newTestModule("a")
	m.startFn = func(context.Context, module.Host) error { return errors.New("half-initialised") }

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()

	starts, stops, _ := m.counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("got %d starts and %d stops, want 1 and 1", starts, stops)
	}
}

func TestUnsupportedModuleDegradesAndIsNeverRetried(t *testing.T) {
	// This is what lets one binary ship everywhere without faking data.
	ebpf := newTestModule("ebpf")
	ebpf.startFn = func(context.Context, module.Host) error {
		return module.Unsupported("eBPF requires Linux with BTF")
	}
	host := newTestModule("host")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"ebpf": enabled(), "host": required(),
	}), ebpf, host)
	h.start()

	if got := h.state("ebpf"); got != module.StateUnsupported {
		t.Fatalf("ebpf state = %v, want unsupported", got)
	}
	if !h.hasDiag("ebpf", diagnostics.CodeUnsupported) {
		t.Fatal("no unsupported diagnostic was recorded")
	}

	// Unsupported must degrade, never fail, and never restart.
	h.pumpCycles(5, time.Second)
	if starts, _, _ := ebpf.counts(); starts != 1 {
		t.Fatalf("unsupported module was started %d times, want exactly 1", starts)
	}
	if got := h.sup.Health().Status; got != health.Degraded {
		t.Fatalf("agent health = %v, want degraded", got)
	}
}

func TestPermissionDenialPreventsModuleCodeFromRunning(t *testing.T) {
	// The permission check strictly precedes any module code: a module that is
	// not permitted to run must never have had its Start called.
	const perm platform.Permission = "read:proc"
	m := newTestModule("process")
	m.manifest.Permissions = []platform.Permission{perm}

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"process": enabled()}), m)
	h.rt.Revoke("process", perm)
	h.start()

	if starts, _, _ := m.counts(); starts != 0 {
		t.Fatalf("module code ran %d times despite a denied permission", starts)
	}
	if got := h.state("process"); got != module.StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}
	if h.rt.ActiveCount() != 0 {
		t.Fatal("a refused module is holding a capability admission slot")
	}
}

func TestSuccessfulStopReleasesTheCapabilityLease(t *testing.T) {
	m := newTestModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()

	if h.rt.ActiveCount() != 1 {
		t.Fatalf("active leases = %d, want 1", h.rt.ActiveCount())
	}
	if err := h.sup.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.rt.ActiveCount() != 0 {
		t.Fatal("shutdown left a capability lease held")
	}
}

func TestFailingStopStillSurrendersItsLease(t *testing.T) {
	// Otherwise a restart is refused because the old registration is still
	// held, converting a transient stop failure into a permanent outage.
	m := newTestModule("a")
	m.stopFn = func(context.Context) error { return errors.New("flush failed") }

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	_ = h.sup.Shutdown(t.Context())

	if h.rt.ActiveCount() != 0 {
		t.Fatal("a module that failed to stop is still holding its lease")
	}
}

// ---------------------------------------------------------------------------
// Restart and crash-loop protection
// ---------------------------------------------------------------------------

func TestModuleRestartsAfterBackoff(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	m := newTestModule("a")
	m.startFn = func(context.Context, module.Host) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			return errors.New("transient failure")
		}
		return nil
	}

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	h.waitState("a", module.StateFailed)

	h.pumpUntil("module to restart", time.Second, func() bool {
		s, _ := h.sup.State("a")
		return s == module.StateRunning
	})

	if v, _ := h.tel.CounterValue(MetricModuleRestarts, platform.A(AttrModule, "a")); v < 1 {
		t.Fatalf("restart counter = %d, want at least 1", v)
	}
}

func TestCrashLoopQuarantineStopsTheBleeding(t *testing.T) {
	// MaxRestarts is 2 in the test configuration, so the third failure
	// quarantines. An agent must not restart a broken module forever on a
	// customer host.
	m := newTestModule("a")
	m.startFn = func(context.Context, module.Host) error { return errors.New("always fails") }
	survivor := newTestModule("survivor")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"a": enabled(), "survivor": enabled(),
	}), m, survivor)
	h.start()

	h.pumpUntil("module to be quarantined", time.Second, func() bool {
		s, _ := h.sup.State("a")
		return s == module.StateCrashLooping
	})

	starts, _, _ := m.counts()
	if starts != 3 {
		t.Fatalf("module started %d times, want 3 (initial + 2 restarts)", starts)
	}
	if !h.hasDiag("a", diagnostics.CodeCrashLoop) {
		t.Fatal("no crash-loop diagnostic was recorded")
	}

	// Quarantine must be terminal until an operator intervenes.
	h.pumpCycles(5, time.Second)
	if s, _, _ := m.counts(); s != 3 {
		t.Fatalf("quarantined module restarted again: %d starts", s)
	}
	// And the rest of the agent keeps working.
	if got := h.state("survivor"); got != module.StateRunning {
		t.Fatalf("survivor state = %v, want running", got)
	}
}

func TestRestartCanBeDisabled(t *testing.T) {
	cfg := testConfig(map[string]config.ModuleConfig{"a": enabled()})
	cfg.Agent.Restart.Enabled = false

	m := newTestModule("a")
	m.startFn = func(context.Context, module.Host) error { return errors.New("nope") }

	h := newHarness(t, cfg, m)
	h.start()
	h.waitState("a", module.StateFailed)

	h.pumpCycles(5, time.Second)
	if starts, _, _ := m.counts(); starts != 1 {
		t.Fatalf("module started %d times with restart disabled, want 1", starts)
	}
}

func TestRuntimeFailureStopsDependentsAndRecovers(t *testing.T) {
	// A module whose dependency has gone is operating on assumptions that no
	// longer hold; letting it keep emitting produces confidently wrong data.
	var mu sync.Mutex
	var baseAttempts int

	base := newTestModule("base")
	base.startFn = func(context.Context, module.Host) error {
		mu.Lock()
		defer mu.Unlock()
		baseAttempts++
		return nil
	}
	dependent := newTestModule("dependent", "base")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"base": enabled(), "dependent": enabled(),
	}), base, dependent)
	h.start()
	h.waitState("base", module.StateRunning)
	h.waitState("dependent", module.StateRunning)

	// The module's collection loop dies and reports it.
	base.capturedHost().ReportFailure(errors.New("kernel subscription lost"))

	eventually(t, "dependent to be stopped", func() bool {
		_, stops, _ := dependent.counts()
		return stops >= 1
	})
	if !h.hasDiag("dependent", diagnostics.CodeDependencyUnavailable) {
		t.Fatal("dependent has no dependency-unavailable diagnostic")
	}

	// Both come back automatically once the dependency recovers.
	h.pumpUntil("both modules to recover", time.Second, func() bool {
		b, _ := h.sup.State("base")
		d, _ := h.sup.State("dependent")
		return b == module.StateRunning && d == module.StateRunning
	})

	// A dependency wait must not consume the dependent's crash-loop budget:
	// the dependent never crashed.
	if got := h.state("dependent"); got == module.StateCrashLooping {
		t.Fatal("a dependency wait consumed the dependent's crash-loop budget")
	}
}

func TestStaleFailureReportIsIgnored(t *testing.T) {
	// A late report from a previous instance of a module must not disturb the
	// instance running now.
	m := newTestModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	h.waitState("a", module.StateRunning)

	// Generation 0 can never match a started module, whose generation is >= 1.
	h.sup.reportFailure("a", 0, errors.New("stale report from a previous instance"))

	// Give the loop a chance to mishandle it.
	h.pumpCycles(3, time.Second)
	if got := h.state("a"); got != module.StateRunning {
		t.Fatalf("state = %v, want running; a stale report was acted on", got)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealthAggregatesRequiredAndOptionalDifferently(t *testing.T) {
	failRequired := newTestModule("required-fail")
	failRequired.startFn = func(context.Context, module.Host) error { return errors.New("down") }
	failOptional := newTestModule("optional-fail")
	failOptional.startFn = func(context.Context, module.Host) error { return errors.New("down") }
	ok := newTestModule("ok")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"required-fail": required(), "optional-fail": enabled(), "ok": required(),
	}), failRequired, failOptional, ok)
	h.start()

	agg := h.sup.Health()
	if agg.Status != health.Unhealthy {
		t.Fatalf("agent health = %v, want unhealthy with a failed required module", agg.Status)
	}

	c, _ := agg.Component("optional-fail")
	if c.Required {
		t.Fatal("optional module reported as required")
	}
}

func TestOptionalFailureOnlyDegrades(t *testing.T) {
	failOptional := newTestModule("optional-fail")
	failOptional.startFn = func(context.Context, module.Host) error { return errors.New("down") }
	ok := newTestModule("ok")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"optional-fail": enabled(), "ok": required(),
	}), failOptional, ok)
	h.start()

	if got := h.sup.Health().Status; got != health.Degraded {
		t.Fatalf("agent health = %v, want degraded\n%s", got, h.describe())
	}
}

func TestHealthProbeReflectsModuleReport(t *testing.T) {
	m := newTestModule("a")
	m.healthFn = func(context.Context) health.Report {
		return health.DegradedReport("collection interval was stretched")
	}

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": required()}), m)
	h.start()
	h.tick()

	eventually(t, "health to reflect the module report", func() bool {
		return h.sup.Health().Status == health.Degraded
	})
}

func TestHealthProbePanicIsIsolated(t *testing.T) {
	boom := newTestModule("boom")
	boom.healthFn = func(context.Context) health.Report { panic("health exploded") }
	ok := newTestModule("ok")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"boom": enabled(), "ok": required(),
	}), boom, ok)
	h.start()
	h.tick()

	eventually(t, "the panic to be recorded", func() bool {
		return h.hasDiag("boom", diagnostics.CodePanic)
	})
	// The panicking module stays running — it panicked in its probe, not in
	// its collection path — and the rest of the agent is unaffected.
	if got := h.state("ok"); got != module.StateRunning {
		t.Fatalf("ok state = %v, want running", got)
	}
}

func TestHealthProbeTimeoutIsUnknownNotUnhealthy(t *testing.T) {
	// A slow probe is evidence of a slow module, not proof of a broken one.
	// Escalating it to Unhealthy would page operators for scheduler pressure.
	cfg := testConfig(map[string]config.ModuleConfig{"a": required()})
	cfg.Agent.HealthProbeTimeout = config.D(30 * time.Millisecond)

	m := newTestModule("a")
	m.healthFn = func(ctx context.Context) health.Report {
		time.Sleep(300 * time.Millisecond)
		return health.OK("eventually")
	}

	h := newHarness(t, cfg, m)
	h.start()
	h.tick()

	eventually(t, "a health timeout to be recorded", func() bool {
		return h.hasDiag("a", diagnostics.CodeHealthTimeout)
	})
	if got := h.sup.Health().Status; got == health.Unhealthy {
		t.Fatal("a probe timeout escalated the agent to unhealthy")
	}
	if v, _ := h.tel.CounterValue(MetricModuleHealthTimeouts, platform.A(AttrModule, "a")); v < 1 {
		t.Fatal("health timeout counter was not incremented")
	}
}

func TestSlowProbeDoesNotAccumulateGoroutines(t *testing.T) {
	// A module whose Health hangs must not gain a probe goroutine every tick.
	cfg := testConfig(map[string]config.ModuleConfig{"a": enabled()})
	cfg.Agent.HealthProbeTimeout = config.D(20 * time.Millisecond)

	release := make(chan struct{})
	var calls int
	var mu sync.Mutex
	m := newTestModule("a")
	m.healthFn = func(context.Context) health.Report {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return health.OK("")
	}

	h := newHarness(t, cfg, m)
	h.start()
	for i := 0; i < 5; i++ {
		h.tick()
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	close(release)

	if got > 1 {
		t.Fatalf("a hung probe was re-dispatched %d times; in-flight probes are not bounded", got)
	}
}

// ---------------------------------------------------------------------------
// Diagnostics surface and self-telemetry
// ---------------------------------------------------------------------------

func TestSnapshotDescribesEveryModule(t *testing.T) {
	ok := newTestModule("ok")
	bad := newTestModule("bad")
	bad.startFn = func(context.Context, module.Host) error { return errors.New("no device") }

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"ok": required(), "bad": enabled(),
	}), ok, bad)
	h.start()

	snap := h.sup.Snapshot(t.Context())
	if len(snap.Modules) != 2 {
		t.Fatalf("snapshot has %d modules, want 2", len(snap.Modules))
	}
	byID := map[module.ID]ModuleStatus{}
	for _, m := range snap.Modules {
		byID[m.ID] = m
	}
	if byID["ok"].State != module.StateRunning || !byID["ok"].Required {
		t.Fatalf("ok status = %+v", byID["ok"])
	}
	if byID["bad"].State != module.StateFailed {
		t.Fatalf("bad status = %+v", byID["bad"])
	}
	if !strings.Contains(byID["bad"].LastError, "no device") {
		t.Fatalf("last error not surfaced: %q", byID["bad"].LastError)
	}
	if snap.ConfigRevision == 0 {
		t.Fatal("snapshot did not carry a configuration revision")
	}
}

func TestSelfTelemetryUsesOnlyBoundedAttributes(t *testing.T) {
	// The agent must never become the source of the cardinality incident it
	// exists to detect. The only attribute this package attaches is `module`.
	m := newTestModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	h.tick()

	if v, _ := h.tel.CounterValue(MetricModuleStarts, platform.A(AttrModule, "a")); v != 1 {
		t.Fatalf("start counter = %d, want 1", v)
	}
	for _, ev := range h.tel.Events() {
		for _, attr := range ev.Attrs {
			switch attr.Key {
			case AttrModule, "from", "to":
			default:
				t.Errorf("event %q carries unexpected attribute %q", ev.Name, attr.Key)
			}
		}
	}
	if h.tel.DroppedSeries(MetricModuleStarts) != 0 {
		t.Fatal("the agent's own metrics hit the cardinality bound")
	}
}

func TestSelfMetricsAreCollected(t *testing.T) {
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	h.start()
	h.tick()

	// Poll for both gauges: they are published sequentially inside one
	// collection pass, so asserting the second immediately after observing the
	// first is a race in the test, not a product defect.
	eventually(t, "self metrics to be published", func() bool {
		g, gok := h.tel.GaugeValue(MetricAgentGoroutines)
		_, hok := h.tel.GaugeValue(MetricAgentHeapBytes)
		return gok && g > 0 && hok
	})
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentReadersDoNotRace(t *testing.T) {
	mods := make([]module.Module, 0, 8)
	cfgModules := map[string]config.ModuleConfig{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		mods = append(mods, newTestModule(id))
		cfgModules[id] = enabled()
	}

	h := newHarness(t, testConfig(cfgModules), mods...)
	h.start()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = h.sup.Health()
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = h.sup.Snapshot(context.Background())
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = h.sup.State("a")
				}
			}
		}()
	}

	for i := 0; i < 20; i++ {
		h.clock.Advance(time.Second)
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

func TestConcurrentFailureReportsAreCoalesced(t *testing.T) {
	// ReportFailure is contracted to be non-blocking and safe from any
	// goroutine; a storm of reports must not block the reporter or the loop.
	m := newTestModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	h.waitState("a", module.StateRunning)

	host := m.capturedHost()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				host.ReportFailure(errors.New("loop died"))
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ReportFailure blocked its caller")
	}
}

// ---------------------------------------------------------------------------
// Deadline handling
// ---------------------------------------------------------------------------

// TestFastCallIsNeverReportedAsATimeout is a regression test.
//
// An earlier implementation cancelled the deadline context from inside the
// worker goroutine, which made both arms of the waiting select ready at the
// same instant for any fast call. Go then chose between them at random, so a
// module that started or stopped perfectly was reported as having timed out
// roughly half the time under load — and was then given failure cleanup and
// counted against its crash-loop budget. It reproduced only under contention,
// which is exactly the kind of defect that reaches production.
func TestFastCallIsNeverReportedAsATimeout(t *testing.T) {
	var wg sync.WaitGroup
	failures := make(chan error, 64)

	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				err, settled := withTimeout(context.Background(), 30*time.Second,
					func(context.Context) error { return nil })
				<-settled
				if err != nil {
					select {
					case failures <- err:
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)

	if err := <-failures; err != nil {
		t.Fatalf("an instantaneous call was reported as failing: %v", err)
	}
}

// TestValueCallIsNeverReportedAsATimeout covers the same defect on the health
// probe path.
func TestValueCallIsNeverReportedAsATimeout(t *testing.T) {
	var wg sync.WaitGroup
	failures := make(chan error, 64)

	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				rep, err, settled := valueWithTimeout(context.Background(), 30*time.Second,
					func(context.Context) health.Report { return health.OK("fine") })
				<-settled
				if err != nil || rep.Status != health.Healthy {
					select {
					case failures <- err:
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)

	if err := <-failures; err != nil {
		t.Fatalf("an instantaneous probe was reported as failing: %v", err)
	}
}

// TestTimeoutIsStillReportedForASlowCall proves the fix did not simply disable
// deadline detection.
func TestTimeoutIsStillReportedForASlowCall(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	err, _ := withTimeout(context.Background(), 20*time.Millisecond, func(ctx context.Context) error {
		<-release
		return nil
	})
	if err == nil {
		t.Fatal("a call that overran its deadline was not reported as a timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a deadline-exceeded timeout", err)
	}
}
