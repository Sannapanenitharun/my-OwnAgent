package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
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

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeLister lets a test express "the host has these processes right now"
// without needing a host that has them.
type fakeLister struct {
	mu sync.Mutex

	listing Listing
	err     error
	fn      func(ctx context.Context, opts ListOptions) (Listing, error)

	calls    int
	lastOpts ListOptions
}

func (f *fakeLister) ListProcesses(ctx context.Context, opts ListOptions) (Listing, error) {
	f.mu.Lock()
	f.calls++
	f.lastOpts = opts
	fn, listing, err := f.fn, f.listing, f.err
	f.mu.Unlock()

	if fn != nil {
		return fn(ctx, opts)
	}
	if err != nil {
		return Listing{}, err
	}
	// Honour the pre-filter, exactly as a real reader must.
	if opts.Accept != nil {
		out := Listing{Vanished: listing.Vanished, Denied: listing.Denied, Unreadable: listing.Unreadable}
		for _, p := range listing.Processes {
			if opts.Accept(p.PID) {
				out.Processes = append(out.Processes, p)
			}
		}
		return out, nil
	}
	return listing, nil
}

func (f *fakeLister) set(procs []Info) {
	f.mu.Lock()
	f.listing = Listing{Processes: procs}
	f.mu.Unlock()
}

func (f *fakeLister) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeDetail struct {
	mu sync.Mutex

	io    map[PID]IOCounters
	ioErr error

	files    map[PID]uint64
	filesErr error

	paths   map[PID]string
	pathErr error

	cmds   map[PID][]string
	cmdErr error

	ioCalls   int
	fileCalls int
	pathCalls int
	cmdCalls  int
}

func newFakeDetail() *fakeDetail {
	return &fakeDetail{
		io:    map[PID]IOCounters{},
		files: map[PID]uint64{},
		paths: map[PID]string{},
		cmds:  map[PID][]string{},
	}
}

func (f *fakeDetail) ReadIO(context.Context, PID) (IOCounters, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ioCalls++
	if f.ioErr != nil {
		return IOCounters{}, f.ioErr
	}
	return IOCounters{}, nil
}

func (f *fakeDetail) ReadOpenFiles(_ context.Context, pid PID) (U64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fileCalls++
	if f.filesErr != nil {
		return U64{}, f.filesErr
	}
	return KnownU64(f.files[pid]), nil
}

func (f *fakeDetail) ReadExecutablePath(_ context.Context, pid PID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pathCalls++
	if f.pathErr != nil {
		return "", f.pathErr
	}
	return f.paths[pid], nil
}

func (f *fakeDetail) ReadCommandLine(_ context.Context, pid PID) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmdCalls++
	if f.cmdErr != nil {
		return nil, f.cmdErr
	}
	return f.cmds[pid], nil
}

func (f *fakeDetail) counts() (ioC, fileC, pathC, cmdC int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ioCalls, f.fileCalls, f.pathCalls, f.cmdCalls
}

type fakeBoot struct {
	id  string
	err error
}

func (f *fakeBoot) ReadBootIdentity(context.Context) (BootIdentity, error) {
	if f.err != nil {
		return BootIdentity{}, f.err
	}
	return BootIdentity{ID: f.id, Time: time.Unix(1700000000, 0), HasTime: true}, nil
}

// fullSet returns a reader set where every feature is available.
func fullSet(l *fakeLister, d *fakeDetail) Set {
	return Set{
		Lister:  l,
		IO:      d,
		Files:   d,
		Path:    d,
		Command: d,
		Boot:    &fakeBoot{id: "boot-test"},
		Inline: map[Feature]bool{
			FeatureCPU: true, FeatureMemory: true, FeatureThreads: true,
			FeatureState: true, FeatureUser: true,
		},
	}
}

// proc builds one Info with plausible values.
func proc(pid PID, name string, start uint64) Info {
	return Info{
		PID: pid, PPID: 1, Name: name, State: StateSleeping,
		StartRaw: start, HasStartRaw: true,
		StartTime: time.Unix(1700000000+int64(start), 0), HasStartTime: true,
		CPUUserNanos:   KnownU64(0),
		CPUSystemNanos: KnownU64(0),
		RSSBytes:       KnownU64(1 << 20),
		VirtualBytes:   KnownU64(4 << 20),
		Threads:        KnownU64(2),
		UID:            KnownU64(1000),
	}
}

func (i Info) withCPU(nanos uint64) Info {
	i.CPUUserNanos = KnownU64(nanos)
	i.CPUSystemNanos = KnownU64(0)
	return i
}

func (i Info) withRSS(bytes uint64) Info {
	i.RSSBytes = KnownU64(bytes)
	return i
}

func (i Info) withState(s State) Info {
	i.State = s
	return i
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type harness struct {
	t      *testing.T
	mod    *Module
	lister *fakeLister
	detail *fakeDetail
	tel    *inproc.Telemetry
	diags  *diagnostics.Recorder
	clock  *clockfake.Clock
	host   module.Host

	authErr error
}

const testEntity = "ent-host-1"

func newHarness(t *testing.T, set Set, settings map[string]string) *harness {
	t.Helper()
	return newHarnessWithIdentity(t, set, settings, inproc.NewIdentity("agent-1", "tenant-1", testEntity))
}

func newHarnessWithIdentity(t *testing.T, set Set, settings map[string]string, id platform.Identity) *harness {
	t.Helper()

	h := &harness{
		t:     t,
		tel:   inproc.NewTelemetry(),
		diags: diagnostics.NewRecorder(1024),
		clock: clockfake.New(time.Time{}),
	}
	if l, ok := set.Lister.(*fakeLister); ok {
		h.lister = l
	}
	if d, ok := set.IO.(*fakeDetail); ok {
		h.detail = d
	}

	h.mod = NewWithSet(set)
	h.host = module.Host{
		ID:          ID,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Telemetry:   h.tel,
		Clock:       h.clock,
		Identity:    id,
		Diagnostics: diagnostics.Scoped(string(ID), h.diags),
		Config:      config.ModuleConfig{Enabled: true, Settings: settings},
		Authorize: func(context.Context, platform.Permission) error {
			return h.authErr
		},
		ReportFailure: func(error) {},
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.mod.Stop(ctx)
	})
	return h
}

func (h *harness) start() {
	h.t.Helper()
	if err := h.mod.Start(h.t.Context(), h.host); err != nil {
		h.t.Fatalf("Start: %v", err)
	}
}

// waitCycles blocks until the module has completed at least n collection cycles.
func (h *harness) waitCycles(n int64) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if h.cycles() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d cycles; got %d. %s", n, h.cycles(), h.describe())
}

func (h *harness) cycles() int64 {
	return h.mod.Statistics(context.Background()).Counters["cycles"]
}

func (h *harness) stat(key string) int64 {
	return h.mod.Statistics(context.Background()).Counters[key]
}

// advance drives one more collection cycle and waits for it to finish.
func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	before := h.cycles()
	h.clock.BlockUntil(1)
	h.clock.Advance(d)
	h.waitCycles(before + 1)
}

// describe renders the module's state so a failing test explains itself instead
// of leaving the next engineer to reproduce it.
func (h *harness) describe() string {
	st := h.mod.Statistics(context.Background())
	rep := h.mod.Health(context.Background())
	return fmt.Sprintf("health=%s (%s) counters=%v gauges=%v lister_calls=%d",
		rep.Status, rep.Message, st.Counters, st.Gauges, h.lister.callCount())
}

func (h *harness) gauge(name string, attrs ...platform.Attr) (float64, bool) {
	all := append([]platform.Attr{platform.A(AttrEntityID, testEntity)}, attrs...)
	return h.tel.GaugeValue(name, all...)
}

func (h *harness) counter(name string, attrs ...platform.Attr) (int64, bool) {
	all := append([]platform.Attr{platform.A(AttrEntityID, testEntity)}, attrs...)
	return h.tel.CounterValue(name, all...)
}

func (h *harness) events(name string) []platform.Event {
	var out []platform.Event
	for _, ev := range h.tel.Events() {
		if ev.Name == name {
			out = append(out, ev)
		}
	}
	return out
}

func (h *harness) diagCodes() map[diagnostics.Code]int {
	out := map[diagnostics.Code]int{}
	for _, r := range h.diags.BySource(string(ID)) {
		out[r.Code]++
	}
	return out
}

func eventAttr(ev platform.Event, key string) (string, bool) {
	for _, a := range ev.Attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return "", false
}

// procs builds n processes named from a small set, so tests can control the
// distinct-executable count independently of the process count.
func procs(n, distinctNames int) []Info {
	out := make([]Info, 0, n)
	for i := 0; i < n; i++ {
		name := "proc" + strconv.Itoa(i%distinctNames)
		out = append(out, proc(PID(1000+i), name, uint64(i)))
	}
	return out
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestStartCollectsImmediately(t *testing.T) {
	// An operator who has just installed the agent should see data at once, not
	// after the first thirty-second interval.
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 1), proc(200, "postgres", 2)})
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if v, ok := h.gauge(MetricCount); !ok || v != 2 {
		t.Fatalf("process.count = %v (ok=%v), want 2. %s", v, ok, h.describe())
	}
}

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	l := &fakeLister{}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{"max_processes": "zero"})
	err := h.mod.Start(t.Context(), h.host)
	if err == nil {
		t.Fatal("Start accepted an invalid configuration")
	}
	if l.callCount() != 0 {
		t.Error("a module that failed to start still enumerated processes")
	}
}

func TestStartWithoutEnumerationReportsUnsupported(t *testing.T) {
	// The unsupported path must be terminal, not a failure the supervisor
	// retries forever against a condition that cannot change.
	h := newHarness(t, platformSetAllUnsupported(), nil)
	err := h.mod.Start(t.Context(), h.host)
	if !module.IsUnsupported(err) {
		t.Fatalf("Start error = %v, want unsupported", err)
	}
}

func platformSetAllUnsupported() Set {
	unsupported := make([]Unsupported, 0, len(AllFeatures))
	for _, f := range AllFeatures {
		unsupported = append(unsupported, Unsupported{Feature: f, Reason: "test: unavailable"})
	}
	return Set{Unsupported: unsupported}
}

func TestAuthorizationRefusalPreventsCollection(t *testing.T) {
	l := &fakeLister{}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.authErr = platform.ErrDenied

	if err := h.mod.Start(t.Context(), h.host); err == nil {
		t.Fatal("Start succeeded despite denied authorization")
	}
	if l.callCount() != 0 {
		t.Error("an unauthorized module still enumerated processes")
	}
}

func TestStopIsIdempotentAndToleratesPartialStart(t *testing.T) {
	l := &fakeLister{}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)

	// Stop before Start — the supervisor does exactly this after a failed Start.
	if err := h.mod.Stop(t.Context()); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	h.start()
	h.waitCycles(1)
	for i := 0; i < 3; i++ {
		if err := h.mod.Stop(context.Background()); err != nil {
			t.Fatalf("Stop #%d: %v", i, err)
		}
	}
}

func TestDoubleStartIsRejected(t *testing.T) {
	h := newHarness(t, fullSet(&fakeLister{}, newFakeDetail()), nil)
	h.start()
	if err := h.mod.Start(t.Context(), h.host); err == nil {
		t.Fatal("second Start succeeded")
	}
}

func TestManifestDeclaresLeastPrivilege(t *testing.T) {
	m := New()
	man := m.Manifest()
	if man.ID != ID {
		t.Errorf("manifest ID = %q", man.ID)
	}
	if len(man.Permissions) != 1 || man.Permissions[0] != PermissionRead {
		t.Errorf("permissions = %v, want exactly [%s]", man.Permissions, PermissionRead)
	}
	if man.Category != module.CategoryCollector {
		t.Errorf("category = %v", man.Category)
	}
}

// ---------------------------------------------------------------------------
// Failure isolation, panics, timeouts
// ---------------------------------------------------------------------------

func TestReaderPanicIsContainedAndModuleKeepsRunning(t *testing.T) {
	l := &fakeLister{}
	var panicked bool
	l.fn = func(context.Context, ListOptions) (Listing, error) {
		if !panicked {
			panicked = true
			panic("reader exploded")
		}
		return Listing{Processes: []Info{proc(1, "init", 1)}}, nil
	}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if got := h.diagCodes()[diagnostics.CodePanic]; got == 0 {
		t.Fatalf("no panic diagnostic recorded. %s", h.describe())
	}
	// The module survives and the next cycle succeeds.
	h.advance(31 * time.Second)
	if v, ok := h.gauge(MetricCount); !ok || v != 1 {
		t.Fatalf("module did not recover after a panic: count=%v ok=%v. %s", v, ok, h.describe())
	}
}

func TestSlowReaderTimesOutAndDoesNotAccumulateGoroutines(t *testing.T) {
	// A wedged procfs must cost one parked goroutine ONCE, not one per interval
	// forever. This is the defect the host module found in Stage 2, encoded
	// here so the process module cannot reintroduce it.
	release := make(chan struct{})
	l := &fakeLister{}
	l.fn = func(ctx context.Context, _ ListOptions) (Listing, error) {
		<-release
		return Listing{}, nil
	}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"interval":           "1s",
		"collection.timeout": "100ms",
	})
	h.start()
	h.waitCycles(1)

	before := l.callCount()
	for i := 0; i < 20; i++ {
		h.clock.BlockUntil(1)
		h.clock.Advance(2 * time.Second)
		time.Sleep(time.Millisecond)
	}
	if after := l.callCount(); after != before {
		t.Errorf("stalled reader was called %d more times; it must be suspended until it returns",
			after-before)
	}
	if got := h.diagCodes()[diagnostics.CodeHealthTimeout]; got == 0 {
		t.Error("no timeout diagnostic recorded")
	}
	close(release)
}

func TestEnumerationErrorDegradesButDoesNotStopTheModule(t *testing.T) {
	l := &fakeLister{err: errors.New("procfs is unavailable")}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if got := h.stat("cycle_failures"); got == 0 {
		t.Fatalf("failure was not counted. %s", h.describe())
	}
	rep := h.mod.Health(context.Background())
	if rep.Status != health.Unhealthy {
		t.Errorf("health = %v, want unhealthy when collection has never succeeded", rep.Status)
	}

	// Recovery.
	l.mu.Lock()
	l.err = nil
	l.listing = Listing{Processes: []Info{proc(1, "init", 1)}}
	l.mu.Unlock()
	h.advance(31 * time.Second)
	if rep := h.mod.Health(context.Background()); rep.Status == health.Unhealthy {
		t.Errorf("module stayed unhealthy after recovery: %s", rep.Message)
	}
}

func TestPerProcessReadFailuresDoNotFailTheCycle(t *testing.T) {
	// PID 100 OK, PID 101 denied, PID 102 exited, PID 103 OK. The cycle must
	// succeed and report all four outcomes distinctly.
	l := &fakeLister{}
	l.listing = Listing{
		Processes: []Info{proc(100, "a", 1), proc(103, "d", 4)},
		Denied:    1,
		Vanished:  1,
	}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if got := h.stat("cycle_failures"); got != 0 {
		t.Errorf("per-process failures failed the whole cycle (%d failures)", got)
	}
	if got := h.stat("processes_denied"); got != 1 {
		t.Errorf("processes_denied = %d, want 1", got)
	}
	if got := h.stat("exited_during_collection"); got != 1 {
		t.Errorf("exited_during_collection = %d, want 1", got)
	}
	if got := h.stat("processes_discovered"); got != 2 {
		t.Errorf("processes_discovered = %d, want 2", got)
	}
}

func TestChurnIsNotAnErrorStorm(t *testing.T) {
	// Ten thousand processes vanishing mid-collection is a build farm finishing
	// a job, not a broken agent.
	l := &fakeLister{}
	l.listing = Listing{Processes: []Info{proc(1, "init", 1)}, Vanished: 10000}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if rep := h.mod.Health(context.Background()); rep.Status != health.Healthy {
		t.Errorf("health = %v (%s), want healthy: process churn is not a fault",
			rep.Status, rep.Message)
	}
	if n := len(h.diags.BySource(string(ID))); n > 20 {
		t.Errorf("%d diagnostics recorded for pure churn; that is an error storm", n)
	}
}

func TestPermissionDenialDoesNotDegradeHealthByDefault(t *testing.T) {
	// An unelevated agent on Windows is denied every other user's process. That
	// is a correctly configured agent, not a broken one.
	l := &fakeLister{}
	l.listing = Listing{Processes: []Info{proc(1, "init", 1)}, Denied: 500}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if rep := h.mod.Health(context.Background()); rep.Status != health.Healthy {
		t.Errorf("health = %v (%s), want healthy with denials at default settings",
			rep.Status, rep.Message)
	}
}

func TestDenialsCanBeMadeToCountWhenOperatorsWant(t *testing.T) {
	l := &fakeLister{}
	l.listing = Listing{Processes: []Info{proc(1, "init", 1)}, Denied: 500}
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{
		"health.denied_is_failure": "true",
	})
	h.start()
	h.waitCycles(1)

	if rep := h.mod.Health(context.Background()); rep.Status != health.Degraded {
		t.Errorf("health = %v, want degraded when denials are configured to count", rep.Status)
	}
}

func TestUnreadableProcessesDegradeAboveThreshold(t *testing.T) {
	l := &fakeLister{}
	l.listing = Listing{Processes: procs(10, 2), Unreadable: 90}
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	rep := h.mod.Health(context.Background())
	if rep.Status != health.Degraded {
		t.Errorf("health = %v (%s), want degraded at a 90%% read failure rate",
			rep.Status, rep.Message)
	}
}

// ---------------------------------------------------------------------------
// Entity binding
// ---------------------------------------------------------------------------

func TestMetricsAreBoundToTheHostEntity(t *testing.T) {
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 1)})
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	if _, ok := h.gauge(MetricCount); !ok {
		t.Fatalf("process.count is not bound to the host entity. %s", h.describe())
	}
	// And the unbound form must NOT exist: an observation that lost its entity
	// binding while health reported it resolved is the worst combination.
	if _, ok := h.tel.GaugeValue(MetricCount); ok {
		t.Error("process.count was also emitted without an entity binding")
	}
}

func TestUnresolvedHostIdentityDegradesAndEmitsUnbound(t *testing.T) {
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 1)})
	h := newHarnessWithIdentity(t, fullSet(l, newFakeDetail()), nil,
		inproc.NewIdentity("agent-1", "tenant-1", ""))
	h.start()
	h.waitCycles(1)

	if _, ok := h.tel.GaugeValue(MetricCount); !ok {
		t.Error("collection stopped because identity was unresolved; it must continue unbound")
	}
	if got := h.diagCodes()[diagnostics.CodeUnresolvedIdentity]; got == 0 {
		t.Error("no unresolved-identity diagnostic")
	}
	if rep := h.mod.Health(context.Background()); rep.Status != health.Degraded {
		t.Errorf("health = %v, want degraded with an unresolved host entity", rep.Status)
	}
}

func TestProcessEntitiesAreResolvedThroughThePlatformNotInvented(t *testing.T) {
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 42)})
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	started := h.events(EventStarted)
	if len(started) != 1 {
		t.Fatalf("got %d start events, want 1. %s", len(started), h.describe())
	}
	id, ok := eventAttr(started[0], AttrProcessEntityID)
	if !ok || id == "" {
		t.Fatalf("start event carries no resolved process entity: %v", started[0].Attrs)
	}
	// The reference adapter derives process IDs with a "process-" prefix. The
	// module must not have produced anything of its own shape.
	if len(id) < 8 || id[:8] != "process-" {
		t.Errorf("process entity %q does not look like a platform-assigned ID", id)
	}
}

// identityWithoutResolver satisfies platform.Identity but NOT
// platform.EntityResolver, which is the case every existing adapter is in.
type identityWithoutResolver struct{ host string }

func (i identityWithoutResolver) AgentID(context.Context) (string, error)  { return "a", nil }
func (i identityWithoutResolver) TenantID(context.Context) (string, error) { return "t", nil }
func (i identityWithoutResolver) HostID(context.Context) (string, error)   { return i.host, nil }

func TestAnAdapterWithoutEntityResolutionStillWorks(t *testing.T) {
	// The extension is additive: an adapter that predates it must keep working,
	// with process entity binding simply absent.
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 42)})
	h := newHarnessWithIdentity(t, fullSet(l, newFakeDetail()), nil,
		identityWithoutResolver{host: testEntity})
	h.start()
	h.waitCycles(1)

	if v, ok := h.gauge(MetricCount); !ok || v != 1 {
		t.Fatalf("collection failed without an entity resolver. %s", h.describe())
	}
	started := h.events(EventStarted)
	if len(started) != 1 {
		t.Fatalf("got %d start events, want 1", len(started))
	}
	if id, ok := eventAttr(started[0], AttrProcessEntityID); ok {
		t.Errorf("a process entity %q appeared without a resolver; the module invented an ID", id)
	}
}

func TestEntityResolutionIsCachedPerInstance(t *testing.T) {
	counting := &countingIdentity{host: testEntity}
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 42), proc(200, "redis", 43)})
	h := newHarnessWithIdentity(t, fullSet(l, newFakeDetail()), nil, counting)
	h.start()
	h.waitCycles(1)

	first := counting.count()
	if first != 2 {
		t.Fatalf("resolved %d entities on the first cycle, want 2", first)
	}
	for i := 0; i < 5; i++ {
		h.advance(31 * time.Second)
	}
	if got := counting.count(); got != first {
		t.Errorf("resolution is not cached: %d calls after 5 more cycles, want %d", got, first)
	}
}

type countingIdentity struct {
	host string
	mu   sync.Mutex
	n    int
}

func (c *countingIdentity) AgentID(context.Context) (string, error)  { return "a", nil }
func (c *countingIdentity) TenantID(context.Context) (string, error) { return "t", nil }
func (c *countingIdentity) HostID(context.Context) (string, error)   { return c.host, nil }

func (c *countingIdentity) ResolveEntity(_ context.Context, ref platform.EntityRef) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return "process-" + strconv.Itoa(c.n), nil
}

func (c *countingIdentity) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestConfigurationPreparesAndCommitsAtomically(t *testing.T) {
	l := &fakeLister{}
	l.set(procs(50, 5))
	h := newHarness(t, fullSet(l, newFakeDetail()), nil)
	h.start()
	h.waitCycles(1)

	cfg := config.ModuleConfig{Enabled: true, Settings: map[string]string{"max_processes": "10"}}
	if err := h.mod.PrepareConfig(t.Context(), cfg); err != nil {
		t.Fatalf("PrepareConfig: %v", err)
	}
	// Prepare must not change live behaviour.
	h.advance(31 * time.Second)
	if got := h.stat("dropped_max_processes"); got != 0 {
		t.Errorf("prepare changed live behaviour: %d processes already dropped", got)
	}

	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatalf("CommitConfig: %v", err)
	}
	h.waitCycles(h.cycles() + 1)
	if got := h.stat("dropped_max_processes"); got == 0 {
		t.Errorf("commit did not take effect. %s", h.describe())
	}
}

func TestInvalidConfigurationIsRejectedWholeAndNothingApplies(t *testing.T) {
	h := newHarness(t, fullSet(&fakeLister{}, newFakeDetail()), nil)
	h.start()

	cfg := config.ModuleConfig{Enabled: true, Settings: map[string]string{
		"max_processes": "10",
		"interval":      "not-a-duration",
	}}
	err := h.mod.PrepareConfig(t.Context(), cfg)
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatalf("CommitConfig after a failed prepare: %v", err)
	}
	h.mod.mu.RLock()
	got := h.mod.settings.MaxProcesses
	h.mod.mu.RUnlock()
	if got != DefaultSettings().MaxProcesses {
		t.Errorf("a rejected configuration partially applied: max_processes = %d", got)
	}
}

func TestRollbackDiscardsStagedConfiguration(t *testing.T) {
	h := newHarness(t, fullSet(&fakeLister{}, newFakeDetail()), nil)
	h.start()

	cfg := config.ModuleConfig{Enabled: true, Settings: map[string]string{"max_processes": "7"}}
	if err := h.mod.PrepareConfig(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := h.mod.RollbackConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.mod.mu.RLock()
	got := h.mod.settings.MaxProcesses
	h.mod.mu.RUnlock()
	if got == 7 {
		t.Error("a rolled-back configuration was committed anyway")
	}
}

func TestHotIntervalChangeTakesEffectWithoutRestart(t *testing.T) {
	l := &fakeLister{}
	l.set([]Info{proc(1, "init", 1)})
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{"interval": "10m"})
	h.start()
	h.waitCycles(1)

	// The timeout must move with the interval: the cross-field rule correctly
	// rejects a 1s interval with the default 2s collection timeout.
	cfg := config.ModuleConfig{Enabled: true, Settings: map[string]string{
		"interval":           "1s",
		"collection.timeout": "500ms",
	}}
	if err := h.mod.PrepareConfig(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Commit signals the loop, which recollects immediately.
	h.waitCycles(2)
}

// ---------------------------------------------------------------------------
// Back-pressure
// ---------------------------------------------------------------------------

func TestThrottleShedsLowestPriorityOutputFirst(t *testing.T) {
	l := &fakeLister{}
	l.set(procs(20, 4))
	d := newFakeDetail()
	h := newHarness(t, fullSet(l, d), map[string]string{
		"collect.open_files": "true",
		"events.top_n":       "5",
	})
	h.start()
	h.waitCycles(1)

	if _, _, _, _ = d.counts(); true {
		_, files, _, _ := d.counts()
		if files == 0 {
			t.Fatal("detail reads did not happen at PressureNone")
		}
	}

	// Moderate: detail reads stop, rollups continue.
	if err := h.mod.Throttle(t.Context(), module.PressureModerate); err != nil {
		t.Fatal(err)
	}
	h.waitCycles(h.cycles() + 1)
	_, filesAfterModerate, _, _ := d.counts()
	h.advance(2 * time.Minute)
	_, filesLater, _, _ := d.counts()
	if filesLater != filesAfterModerate {
		t.Errorf("detail reads continued under moderate pressure (%d -> %d)",
			filesAfterModerate, filesLater)
	}
	if _, ok := h.gauge(MetricInstances, platform.A(AttrExecutable, "proc0")); !ok {
		t.Error("rollups stopped under moderate pressure; they are priority 2")
	}

	// Critical: only the aggregate survives, and it must still be emitted.
	if err := h.mod.Throttle(t.Context(), module.PressureCritical); err != nil {
		t.Fatal(err)
	}
	h.waitCycles(h.cycles() + 1)
	before, _ := h.gauge(MetricCount)
	l.set(procs(30, 4))
	h.advance(10 * time.Minute)
	after, ok := h.gauge(MetricCount)
	if !ok || after == before {
		t.Errorf("aggregate counts stopped under critical pressure: %v -> %v (ok=%v)",
			before, after, ok)
	}
}

func TestThrottleStretchesTheInterval(t *testing.T) {
	l := &fakeLister{}
	l.set([]Info{proc(1, "init", 1)})
	h := newHarness(t, fullSet(l, newFakeDetail()), map[string]string{"interval": "10s"})
	h.start()
	h.waitCycles(1)

	if got := h.mod.effectiveInterval(); got != 10*time.Second {
		t.Fatalf("interval at rest = %s, want 10s", got)
	}
	_ = h.mod.Throttle(t.Context(), module.PressureHigh)
	if got := h.mod.effectiveInterval(); got != 40*time.Second {
		t.Errorf("interval at high pressure = %s, want 40s", got)
	}
	_ = h.mod.Throttle(t.Context(), module.PressureNone)
	if got := h.mod.effectiveInterval(); got != 10*time.Second {
		t.Errorf("interval did not return to normal: %s", got)
	}
}

func TestThrottleIsIdempotentAndReturnsPromptly(t *testing.T) {
	h := newHarness(t, fullSet(&fakeLister{}, newFakeDetail()), nil)
	h.start()
	for i := 0; i < 10; i++ {
		start := time.Now()
		if err := h.mod.Throttle(t.Context(), module.PressureHigh); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("Throttle took %s; it must return promptly", d)
		}
	}
	if h.mod.Pressure() != module.PressureHigh {
		t.Error("pressure was not retained")
	}
}

// ---------------------------------------------------------------------------
// Capability reporting
// ---------------------------------------------------------------------------

func TestCapabilitiesReportEveryFeatureWithAReason(t *testing.T) {
	set := fullSet(&fakeLister{}, newFakeDetail())
	set.Command = nil
	set.Unsupported = []Unsupported{{Feature: FeatureCommandLine, Reason: "test: not available"}}
	h := newHarness(t, set, nil)
	h.start()

	caps := h.mod.Capabilities(context.Background())
	if len(caps) != len(AllFeatures) {
		t.Fatalf("got %d capabilities, want %d", len(caps), len(AllFeatures))
	}
	for _, c := range caps {
		if !c.Available && c.Reason == "" {
			t.Errorf("capability %s is unavailable with no reason", c.Name)
		}
		if c.Available && c.Reason != "" {
			t.Errorf("capability %s is available but carries a reason %q", c.Name, c.Reason)
		}
	}
}

func TestUnsupportedFeaturesProduceDiagnosticsNotFakeData(t *testing.T) {
	set := fullSet(&fakeLister{}, newFakeDetail())
	set.Inline = map[Feature]bool{FeatureCPU: true, FeatureMemory: true}
	set.Unsupported = []Unsupported{
		{Feature: FeatureState, Reason: "test: no per-process state"},
		{Feature: FeatureThreads, Reason: "test: no thread counts"},
	}
	l := &fakeLister{}
	l.set([]Info{proc(100, "nginx", 1)})
	set.Lister = l

	h := newHarness(t, set, nil)
	h.start()
	h.waitCycles(1)

	if got := h.diagCodes()[diagnostics.CodeUnsupported]; got == 0 {
		t.Error("no unsupported diagnostics were recorded")
	}
	// The by-state metric must be ABSENT, not zero.
	for _, st := range AllStates {
		if _, ok := h.gauge(MetricCountByState, platform.A(AttrState, st.String())); ok {
			t.Errorf("process.count.by_state was emitted for state %s on a platform without state support", st)
		}
	}
}
