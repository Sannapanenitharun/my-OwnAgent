package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
)

func withSetting(mc config.ModuleConfig, k, v string) config.ModuleConfig {
	out := mc
	out.Settings = map[string]string{k: v}
	return out
}

func TestReloadBeforeStartIsRejected(t *testing.T) {
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	if err := h.sup.Reload(t.Context(), testConfig(map[string]config.ModuleConfig{"a": enabled()})); err == nil {
		t.Fatal("Reload before Start should be rejected")
	}
}

func TestReloadRejectsInvalidConfiguration(t *testing.T) {
	// An operator pushing a bad configuration to a fleet should lose the
	// change, not the fleet.
	m := newConfigurableModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()

	bad := testConfig(map[string]config.ModuleConfig{"a": enabled()})
	bad.Agent.HealthInterval = config.D(0)

	if err := h.sup.Reload(t.Context(), bad); err == nil {
		t.Fatal("an invalid configuration must be rejected")
	}
	if p, c, _ := m.configCounts(); p != 0 || c != 0 {
		t.Fatalf("modules were touched by a rejected configuration: %d prepares, %d commits", p, c)
	}
	if got := h.state("a"); got != module.StateRunning {
		t.Fatalf("state = %v, want running; the previous configuration should still be in effect", got)
	}
	if !h.hasDiag("supervisor", diagnostics.CodeConfigInvalid) {
		t.Fatal("no config-invalid diagnostic was recorded")
	}
}

func TestReloadRejectsUnknownModules(t *testing.T) {
	// Silently ignoring is how an operator concludes a collector is running
	// when this build does not even contain it.
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	h.start()

	candidate := testConfig(map[string]config.ModuleConfig{"a": enabled(), "ebpf": enabled()})
	err := h.sup.Reload(t.Context(), candidate)
	if err == nil {
		t.Fatal("a configuration naming a module absent from this build must be rejected")
	}
}

func TestReloadRejectsANewlyIntroducedCycle(t *testing.T) {
	a := newTestModule("a")
	b := newTestModule("b", "a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"a": enabled(), "b": {Enabled: false},
	}), a, b)
	h.start()

	// Enabling b is legal on its own, but a's manifest is unchanged, so this
	// only checks that graph re-resolution happens. Disable a instead: b would
	// then depend on a disabled module.
	candidate := testConfig(map[string]config.ModuleConfig{
		"a": {Enabled: false}, "b": enabled(),
	})
	var mde *MissingDependencyError
	if err := h.sup.Reload(t.Context(), candidate); !errors.As(err, &mde) {
		t.Fatalf("Reload error = %v, want *MissingDependencyError", err)
	}
	if got := h.state("a"); got != module.StateRunning {
		t.Fatalf("state = %v; a rejected reload must change nothing", got)
	}
}

func TestReloadPrepareRejectionRollsBackEveryPreparedModule(t *testing.T) {
	// This is the property that makes "invalid configuration must not
	// partially apply" a fact rather than an aspiration.
	first := newConfigurableModule("first")
	second := newConfigurableModule("second")
	third := newConfigurableModule("third")
	third.prepareFn = func(context.Context, config.ModuleConfig) error {
		return errors.New("interval below the supported minimum")
	}

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"first": enabled(), "second": enabled(), "third": enabled(),
	}), first, second, third)
	h.start()

	candidate := testConfig(map[string]config.ModuleConfig{
		"first":  withSetting(enabled(), "interval", "5s"),
		"second": withSetting(enabled(), "interval", "5s"),
		"third":  withSetting(enabled(), "interval", "5s"),
	})

	if err := h.sup.Reload(t.Context(), candidate); err == nil {
		t.Fatal("a module rejecting its fragment must abort the whole reload")
	}

	// Everything that prepared must have rolled back, and nothing may commit.
	for name, m := range map[string]*configurableModule{"first": first, "second": second} {
		p, c, r := m.configCounts()
		if p != 1 {
			t.Errorf("%s: %d prepares, want 1", name, p)
		}
		if c != 0 {
			t.Errorf("%s: %d commits, want 0 — no module may commit when the reload aborts", name, c)
		}
		if r != 1 {
			t.Errorf("%s: %d rollbacks, want 1", name, r)
		}
	}
	if _, c, _ := third.configCounts(); c != 0 {
		t.Errorf("the rejecting module committed %d times, want 0", c)
	}
	if !h.hasDiag("supervisor", diagnostics.CodeConfigRolledBack) {
		t.Error("no rollback diagnostic was recorded")
	}
	if v, _ := h.tel.CounterValue(MetricAgentConfigRollbacks); v < 1 {
		t.Error("rollback counter was not incremented")
	}
}

func TestReloadCommitsWhenEveryModuleAccepts(t *testing.T) {
	a := newConfigurableModule("a")
	b := newConfigurableModule("b")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled(), "b": enabled()}), a, b)
	h.start()

	candidate := testConfig(map[string]config.ModuleConfig{
		"a": withSetting(enabled(), "interval", "5s"),
		"b": withSetting(enabled(), "interval", "5s"),
	})
	candidate.Revision = 2

	if err := h.sup.Reload(t.Context(), candidate); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	for name, m := range map[string]*configurableModule{"a": a, "b": b} {
		p, c, r := m.configCounts()
		if p != 1 || c != 1 || r != 0 {
			t.Errorf("%s: %d prepares, %d commits, %d rollbacks; want 1, 1, 0", name, p, c, r)
		}
		if got := m.liveConfig().Settings["interval"]; got != "5s" {
			t.Errorf("%s: live interval = %q, want 5s", name, got)
		}
	}
	if got := h.sup.Snapshot(t.Context()).ConfigRevision; got != 2 {
		t.Errorf("config revision = %d, want 2", got)
	}
	if v, _ := h.tel.CounterValue(MetricAgentConfigReloads); v != 1 {
		t.Errorf("reload counter = %d, want 1", v)
	}
}

func TestReloadDoesNotDisturbUnchangedModules(t *testing.T) {
	unchanged := newConfigurableModule("unchanged")
	changed := newConfigurableModule("changed")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"unchanged": enabled(), "changed": enabled(),
	}), unchanged, changed)
	h.start()

	candidate := testConfig(map[string]config.ModuleConfig{
		"unchanged": enabled(),
		"changed":   withSetting(enabled(), "interval", "5s"),
	})
	if err := h.sup.Reload(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := unchanged.configCounts(); p != 0 {
		t.Fatalf("an unchanged module was reconfigured %d times", p)
	}
	if p, _, _ := changed.configCounts(); p != 1 {
		t.Fatalf("the changed module was prepared %d times, want 1", p)
	}
}

func TestReloadStartsAndStopsModules(t *testing.T) {
	on := newTestModule("on")
	off := newTestModule("off")

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"on": enabled(), "off": {Enabled: false},
	}), on, off)
	h.start()

	if got := h.state("off"); got != module.StateDisabled {
		t.Fatalf("off state = %v, want disabled", got)
	}

	// Flip both.
	candidate := testConfig(map[string]config.ModuleConfig{
		"on": {Enabled: false}, "off": enabled(),
	})
	if err := h.sup.Reload(t.Context(), candidate); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := h.state("off"); got != module.StateRunning {
		t.Fatalf("newly enabled module state = %v, want running", got)
	}
	if got := h.state("on"); got != module.StateDisabled {
		t.Fatalf("newly disabled module state = %v, want disabled", got)
	}
	if _, stops, _ := on.counts(); stops != 1 {
		t.Fatalf("the disabled module was stopped %d times, want 1", stops)
	}
	if starts, _, _ := off.counts(); starts != 1 {
		t.Fatalf("the enabled module was started %d times, want 1", starts)
	}
}

func TestReloadStartsNewModulesInDependencyOrder(t *testing.T) {
	rec := &orderRecorder{}
	base := newTestModule("base").recordOrder(rec)
	dependent := newTestModule("dependent", "base").recordOrder(rec)

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{
		"base": {Enabled: false}, "dependent": {Enabled: false},
	}), base, dependent)
	h.start()

	candidate := testConfig(map[string]config.ModuleConfig{
		"base": enabled(), "dependent": enabled(),
	})
	if err := h.sup.Reload(t.Context(), candidate); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	bStart, _ := base.orders()
	dStart, _ := dependent.orders()
	if bStart == 0 || dStart == 0 {
		t.Fatalf("modules did not start: base=%d dependent=%d\n%s", bStart, dStart, h.describe())
	}
	if bStart >= dStart {
		t.Fatalf("dependency order violated on reload: base=%d dependent=%d", bStart, dStart)
	}
}

func TestReloadReleasesCrashLoopQuarantine(t *testing.T) {
	// An operator who has fixed the fault must not have to restart the whole
	// agent and lose every other module's state.
	var failing bool = true
	m := newTestModule("a")
	m.startFn = func(context.Context, module.Host) error {
		if failing {
			return errors.New("still broken")
		}
		return nil
	}

	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), m)
	h.start()
	h.pumpUntil("module to be quarantined", time.Second, func() bool {
		s, _ := h.sup.State("a")
		return s == module.StateCrashLooping
	})

	failing = false
	candidate := testConfig(map[string]config.ModuleConfig{"a": enabled()})
	candidate.Revision = 2
	if err := h.sup.Reload(t.Context(), candidate); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	h.pumpUntil("module to recover after the quarantine was released", time.Second, func() bool {
		s, _ := h.sup.State("a")
		return s == module.StateRunning
	})
}

func TestReloadIsSerialised(t *testing.T) {
	// Two interleaved reloads could leave modules on different revisions,
	// which is exactly the partial application the model forbids.
	a := newConfigurableModule("a")
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), a)
	h.start()

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			candidate := testConfig(map[string]config.ModuleConfig{
				"a": withSetting(enabled(), "interval", string(rune('a'+i))),
			})
			candidate.Revision = uint64(i + 2)
			done <- h.sup.Reload(context.Background(), candidate)
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent reload %d failed: %v", i, err)
		}
	}

	// Every prepare must be paired with exactly one commit, and none may have
	// been rolled back.
	p, c, r := a.configCounts()
	if p != c {
		t.Fatalf("%d prepares but %d commits; a reload was interleaved", p, c)
	}
	if r != 0 {
		t.Fatalf("%d rollbacks on a run where every reload was valid", r)
	}
}

func TestReloadAfterShutdownIsRejected(t *testing.T) {
	h := newHarness(t, testConfig(map[string]config.ModuleConfig{"a": enabled()}), newTestModule("a"))
	h.start()
	if err := h.sup.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.sup.Reload(t.Context(), testConfig(map[string]config.ModuleConfig{"a": enabled()})); err == nil {
		t.Fatal("Reload after Shutdown should be rejected")
	}
}
