package supervisor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/clockfake"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// testModule is a module whose behaviour each test dictates. Using one
// configurable module rather than a family of purpose-built fakes keeps the
// tests describing supervisor behaviour instead of fixture behaviour.
type testModule struct {
	manifest module.Manifest

	startFn  func(context.Context, module.Host) error
	stopFn   func(context.Context) error
	healthFn func(context.Context) health.Report

	mu          sync.Mutex
	startCount  int
	stopCount   int
	healthCount int
	host        module.Host
	startOrder  int
	stopOrder   int
}

type orderRecorder struct {
	mu       sync.Mutex
	sequence int
}

func (o *orderRecorder) next() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sequence++
	return o.sequence
}

func newTestModule(id string, deps ...module.ID) *testModule {
	return &testModule{
		manifest: module.Manifest{
			ID:           module.ID(id),
			Version:      "1.0.0",
			Category:     module.CategoryCollector,
			Description:  "test module " + id,
			Dependencies: deps,
			Priority:     module.PriorityNormal,
		},
	}
}

func (m *testModule) Manifest() module.Manifest { return m.manifest }

func (m *testModule) Start(ctx context.Context, host module.Host) error {
	m.mu.Lock()
	m.startCount++
	m.host = host
	fn := m.startFn
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, host)
	}
	return nil
}

func (m *testModule) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.stopCount++
	fn := m.stopFn
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return nil
}

func (m *testModule) Health(ctx context.Context) health.Report {
	m.mu.Lock()
	m.healthCount++
	fn := m.healthFn
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return health.OK("ok")
}

func (m *testModule) counts() (starts, stops, healths int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startCount, m.stopCount, m.healthCount
}

func (m *testModule) capturedHost() module.Host {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.host
}

// recordOrder makes the module note when it was started and stopped relative to
// its siblings, so ordering assertions do not depend on timing.
func (m *testModule) recordOrder(rec *orderRecorder) *testModule {
	m.startFn = func(context.Context, module.Host) error {
		m.mu.Lock()
		m.startOrder = rec.next()
		m.mu.Unlock()
		return nil
	}
	m.stopFn = func(context.Context) error {
		m.mu.Lock()
		m.stopOrder = rec.next()
		m.mu.Unlock()
		return nil
	}
	return m
}

func (m *testModule) orders() (start, stop int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startOrder, m.stopOrder
}

// configurableModule adds the three-phase Configurable contract.
type configurableModule struct {
	*testModule

	prepareFn func(context.Context, config.ModuleConfig) error

	cmu       sync.Mutex
	prepares  int
	commits   int
	rollbacks int
	staged    *config.ModuleConfig
	live      config.ModuleConfig
}

func newConfigurableModule(id string, deps ...module.ID) *configurableModule {
	return &configurableModule{testModule: newTestModule(id, deps...)}
}

func (m *configurableModule) PrepareConfig(ctx context.Context, cfg config.ModuleConfig) error {
	m.cmu.Lock()
	m.prepares++
	fn := m.prepareFn
	m.cmu.Unlock()
	if fn != nil {
		if err := fn(ctx, cfg); err != nil {
			return err
		}
	}
	m.cmu.Lock()
	defer m.cmu.Unlock()
	staged := cfg
	m.staged = &staged
	return nil
}

func (m *configurableModule) CommitConfig(context.Context) error {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	m.commits++
	if m.staged != nil {
		m.live = *m.staged
		m.staged = nil
	}
	return nil
}

func (m *configurableModule) RollbackConfig(context.Context) error {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	m.rollbacks++
	m.staged = nil
	return nil
}

func (m *configurableModule) configCounts() (prepares, commits, rollbacks int) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	return m.prepares, m.commits, m.rollbacks
}

func (m *configurableModule) liveConfig() config.ModuleConfig {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	return m.live
}

// harness wires a supervisor against fully controllable ports.
type harness struct {
	t     *testing.T
	sup   *Supervisor
	clock *clockfake.Clock
	tel   *inproc.Telemetry
	rt    *inproc.CapabilityRuntime
	diags *diagnostics.Recorder
	cfg   config.Config
}

// testConfig uses short intervals so that the fake clock only has to be nudged
// by small amounts, and disables jitter so restart timing is exactly
// predictable.
func testConfig(modules map[string]config.ModuleConfig) config.Config {
	cfg := config.Default()
	cfg.Revision = 1
	cfg.Agent.HealthInterval = config.D(time.Second)
	cfg.Agent.HealthProbeTimeout = config.D(200 * time.Millisecond)
	// Start/stop deadlines run on real time even though the rest of the suite
	// uses a fake clock, so they are set generously. Tests that exercise a
	// deadline override them explicitly; everywhere else a tight value would
	// only convert a loaded CI machine into a spurious failure.
	cfg.Agent.ModuleStartTimeout = config.D(20 * time.Second)
	cfg.Agent.ModuleStopTimeout = config.D(20 * time.Second)
	cfg.Agent.ShutdownTimeout = config.D(30 * time.Second)
	cfg.Agent.Restart.InitialBackoff = config.D(time.Second)
	cfg.Agent.Restart.MaxBackoff = config.D(time.Second)
	cfg.Agent.Restart.JitterFraction = 0
	cfg.Agent.Restart.MaxRestarts = 2
	cfg.Agent.Restart.Window = config.D(time.Minute)
	if modules != nil {
		cfg.Modules = modules
	}
	return cfg
}

// enabled is shorthand for an enabled, optional module fragment.
func enabled() config.ModuleConfig { return config.ModuleConfig{Enabled: true} }

// required is shorthand for an enabled, required module fragment.
func required() config.ModuleConfig { return config.ModuleConfig{Enabled: true, Required: true} }

func newHarness(t *testing.T, cfg config.Config, modules ...module.Module) *harness {
	t.Helper()

	clock := clockfake.New(time.Time{})
	tel := inproc.NewTelemetry()
	rt := inproc.NewCapabilityRuntime()
	diags := diagnostics.NewRecorder(cfg.Agent.DiagnosticsRetention)

	// Grant every declared permission by default; tests that exercise denial
	// revoke explicitly, so a missing grant is never an accident.
	for _, m := range modules {
		mf := m.Manifest()
		if len(mf.Permissions) > 0 {
			rt.Grant(string(mf.ID), mf.Permissions...)
		}
	}

	sup, err := New(Options{
		Config: cfg,
		Ports: platform.Ports{
			Runtime:   rt,
			Telemetry: tel,
			Identity:  inproc.NewIdentity("agent-1", "tenant-1", "host-1"),
			Clock:     clock,
		},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Diagnostics: diags,
		// A fixed source keeps backoff deterministic across runs.
		NewRand: func() *rand.Rand { return rand.New(rand.NewPCG(1, 2)) },
	})
	if err != nil {
		t.Fatalf("constructing supervisor: %v", err)
	}

	for _, m := range modules {
		if err := sup.Register(m); err != nil {
			t.Fatalf("registering module: %v", err)
		}
	}

	h := &harness{t: t, sup: sup, clock: clock, tel: tel, rt: rt, diags: diags, cfg: cfg}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sup.Shutdown(ctx)
	})
	return h
}

func (h *harness) start() {
	h.t.Helper()
	if err := h.sup.Start(h.t.Context()); err != nil {
		h.t.Fatalf("Start: %v", err)
	}
}

func (h *harness) state(id string) module.State {
	h.t.Helper()
	s, ok := h.sup.State(module.ID(id))
	if !ok {
		h.t.Fatalf("module %q is not registered", id)
	}
	return s
}

// eventually polls until cond holds or the deadline passes.
//
// Polling rather than sleeping a fixed duration keeps the suite fast in the
// common case and removes the "works on my machine, flakes in CI" class of
// lifecycle test.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) waitState(id string, want module.State) {
	h.t.Helper()
	eventually(h.t, "module "+id+" to reach "+want.String(), func() bool {
		s, ok := h.sup.State(module.ID(id))
		return ok && s == want
	})
}

// advanceTo waits for the control loop to arm the expected number of timers,
// then moves the fake clock forward. Waiting first closes the race between the
// loop arming its timer and the test advancing past it.
func (h *harness) advanceTo(waiters int, d time.Duration) {
	h.t.Helper()
	h.clock.BlockUntil(waiters)
	h.clock.Advance(d)
}

// pumpUntil repeatedly advances the fake clock until cond holds.
//
// Restart scheduling depends on the supervisor re-arming timers between steps,
// and the exact number of steps depends on how many dependency re-checks a
// module needs. Driving to a condition rather than asserting a step count keeps
// these tests about behaviour instead of about internal scheduling detail.
func (h *harness) pumpUntil(what string, step time.Duration, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		h.clock.BlockUntil(1)
		h.clock.Advance(step)
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s", what)
}

// pumpCycles advances the fake clock a fixed number of times.
//
// Use it to prove a NEGATIVE — that a quarantined or unsupported module is not
// restarted no matter how much time passes. pumpUntil cannot express that,
// because there is no condition to wait for.
func (h *harness) pumpCycles(n int, step time.Duration) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		h.clock.BlockUntil(1)
		h.clock.Advance(step)
		time.Sleep(2 * time.Millisecond)
	}
}

// tick drives one health-probe cycle.
func (h *harness) tick() {
	h.t.Helper()
	h.advanceTo(1, h.cfg.Agent.HealthInterval.Std())
}

// describe renders every module's state and health, for failure messages. A
// lifecycle assertion that fails without saying what the lifecycle was is a
// second debugging session waiting to happen.
func (h *harness) describe() string {
	var b strings.Builder
	agg := h.sup.Health()
	fmt.Fprintf(&b, "agent health=%s", agg.Status)
	for _, c := range agg.Components {
		st, _ := h.sup.State(module.ID(c.ID))
		fmt.Fprintf(&b, "\n  %-16s state=%-13s required=%-5v health=%-9s %s",
			c.ID, st, c.Required, c.Report.Status, c.Report.Message)
	}
	return b.String()
}

func (h *harness) diagCodes(source string) map[diagnostics.Code]int {
	out := map[diagnostics.Code]int{}
	for _, rec := range h.diags.BySource(source) {
		out[rec.Code]++
	}
	return out
}

func (h *harness) hasDiag(source string, code diagnostics.Code) bool {
	return h.diagCodes(source)[code] > 0
}
