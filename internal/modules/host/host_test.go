package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
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

// fakeReader implements every reader interface with injectable behaviour, so
// that a test can express "the disk reader panics" without needing a broken
// machine.
type fakeReader struct {
	mu sync.Mutex

	cpuFn  func(context.Context, bool) (CPUStats, error)
	memFn  func(context.Context) (MemoryStats, error)
	diskFn func(context.Context) ([]DiskStats, error)
	fsFn   func(context.Context) ([]FilesystemStats, error)
	netFn  func(context.Context) ([]InterfaceStats, error)
	osFn   func(context.Context) (OSInfo, error)
	loadFn func(context.Context) (LoadStats, error)

	calls map[Source]int
}

func newFakeReader() *fakeReader { return &fakeReader{calls: map[Source]int{}} }

func (f *fakeReader) record(src Source) {
	f.mu.Lock()
	f.calls[src]++
	f.mu.Unlock()
}

func (f *fakeReader) callCount(src Source) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[src]
}

func (f *fakeReader) ReadCPU(ctx context.Context, perCore bool) (CPUStats, error) {
	f.record(SourceCPU)
	if f.cpuFn != nil {
		return f.cpuFn(ctx, perCore)
	}
	return CPUStats{LogicalCount: KnownU64(4), HasTotal: true,
		Total: CPUTimes{User: 100, System: 50, Idle: 850}}, nil
}

func (f *fakeReader) ReadMemory(ctx context.Context) (MemoryStats, error) {
	f.record(SourceMemory)
	if f.memFn != nil {
		return f.memFn(ctx)
	}
	return MemoryStats{Total: KnownU64(1000), Available: KnownU64(400), Used: KnownU64(600)}, nil
}

func (f *fakeReader) ReadDisks(ctx context.Context) ([]DiskStats, error) {
	f.record(SourceDisk)
	if f.diskFn != nil {
		return f.diskFn(ctx)
	}
	return []DiskStats{{Device: "sda", ReadBytes: KnownU64(1000), WriteBytes: KnownU64(2000)}}, nil
}

func (f *fakeReader) ReadFilesystems(ctx context.Context) ([]FilesystemStats, error) {
	f.record(SourceFilesystem)
	if f.fsFn != nil {
		return f.fsFn(ctx)
	}
	return []FilesystemStats{{
		Mountpoint: "/", Device: "/dev/sda1", FSType: "ext4",
		TotalBytes: KnownU64(1000), UsedBytes: KnownU64(400), AvailBytes: KnownU64(600),
	}}, nil
}

func (f *fakeReader) ReadInterfaces(ctx context.Context) ([]InterfaceStats, error) {
	f.record(SourceNetwork)
	if f.netFn != nil {
		return f.netFn(ctx)
	}
	return []InterfaceStats{{Name: "eth0", RxBytes: KnownU64(500), TxBytes: KnownU64(700)}}, nil
}

func (f *fakeReader) ReadOS(ctx context.Context) (OSInfo, error) {
	f.record(SourceOS)
	if f.osFn != nil {
		return f.osFn(ctx)
	}
	return OSInfo{OS: "testos", Platform: "Test", PlatformVersion: "1.0",
		KernelVersion: "1.2.3", Architecture: "amd64", Hostname: "testhost"}, nil
}

func (f *fakeReader) ReadLoad(ctx context.Context) (LoadStats, error) {
	f.record(SourceLoad)
	if f.loadFn != nil {
		return f.loadFn(ctx)
	}
	return LoadStats{Load1: KnownF64(1.5), Load5: KnownF64(1.0), Load15: KnownF64(0.5)}, nil
}

// fullSet returns a reader set where every source is available.
func fullSet(f *fakeReader) Set {
	return Set{CPU: f, Memory: f, Disk: f, Filesystem: f, Network: f, OS: f, Load: f}
}

type harness struct {
	t       *testing.T
	mod     *Module
	reader  *fakeReader
	tel     *inproc.Telemetry
	diags   *diagnostics.Recorder
	clock   *clockfake.Clock
	host    module.Host
	authErr error
}

func newHarness(t *testing.T, set Set, settings map[string]string) *harness {
	t.Helper()

	h := &harness{
		t:     t,
		tel:   inproc.NewTelemetry(),
		diags: diagnostics.NewRecorder(256),
		clock: clockfake.New(time.Time{}),
	}
	h.mod = NewWithSet(set)
	h.host = module.Host{
		ID:          ID,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Telemetry:   h.tel,
		Clock:       h.clock,
		Identity:    inproc.NewIdentity("agent-1", "tenant-1", "ent-host-1"),
		Diagnostics: diagnostics.Scoped(string(ID), h.diags),
		Config:      config.ModuleConfig{Enabled: true, Settings: settings},
		Authorize: func(context.Context, platform.Permission) error {
			return h.authErr
		},
		ReportFailure: func(error) {},
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// waitCollections blocks until a source has completed at least n reads.
func (h *harness) waitCollections(src Source, n int) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	key := src.String() + ".successes"
	failKey := src.String() + ".failures"
	for time.Now().Before(deadline) {
		st := h.mod.Statistics(context.Background()).Counters
		if st[key]+st[failKey] >= int64(n) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d collections of %s", n, src)
}

// advance moves the fake clock, waking the collection loop.
func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	h.clock.BlockUntil(1)
	h.clock.Advance(d)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestStartCollectsEverySourceImmediately(t *testing.T) {
	// An operator who has just installed the agent should see data at once,
	// not after the longest configured interval.
	f := newFakeReader()
	h := newHarness(t, fullSet(f), nil)
	h.start()

	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}
	for _, src := range AllSources {
		if got := f.callCount(src); got != 1 {
			t.Errorf("%s read %d times during the first cycle, want 1", src, got)
		}
	}
}

func TestModuleUsesExactlyOneGoroutine(t *testing.T) {
	// The whole scheduling design exists to make this true: no goroutine per
	// metric, per filesystem, per interface or per CPU.
	f := newFakeReader()
	f.fsFn = func(context.Context) ([]FilesystemStats, error) {
		out := make([]FilesystemStats, 40)
		for i := range out {
			out[i] = FilesystemStats{
				Mountpoint: fmt.Sprintf("/mnt/%02d", i), FSType: "ext4",
				TotalBytes: KnownU64(1000), UsedBytes: KnownU64(1),
			}
		}
		return out, nil
	}
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		out := make([]InterfaceStats, 20)
		for i := range out {
			out[i] = InterfaceStats{Name: fmt.Sprintf("eth%d", i), RxBytes: KnownU64(uint64(i))}
		}
		return out, nil
	}

	before := runtime.NumGoroutine()
	h := newHarness(t, fullSet(f), nil)
	h.start()
	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}
	// Let transient guard workers finish.
	time.Sleep(50 * time.Millisecond)
	during := runtime.NumGoroutine()

	if delta := during - before; delta > 3 {
		t.Fatalf("module added %d goroutines (%d -> %d); it must own one collection goroutine",
			delta, before, during)
	}

	if err := h.mod.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "goroutines to return to baseline", func() bool {
		return runtime.NumGoroutine() <= before+1
	})
}

func TestStopIsIdempotentAndSafeBeforeStart(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	if err := h.mod.Stop(t.Context()); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	h.start()
	for i := 0; i < 3; i++ {
		if err := h.mod.Stop(t.Context()); err != nil {
			t.Fatalf("Stop %d: %v", i, err)
		}
	}
}

func TestStartRefusesWithoutAuthorization(t *testing.T) {
	// Fail closed: a module that is not permitted must not read anything.
	f := newFakeReader()
	h := newHarness(t, fullSet(f), nil)
	h.authErr = platform.ErrDenied

	err := h.mod.Start(t.Context(), h.host)
	if err == nil {
		t.Fatal("Start should fail when authorization is refused")
	}
	if !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	time.Sleep(20 * time.Millisecond)
	for _, src := range AllSources {
		if n := f.callCount(src); n != 0 {
			t.Errorf("%s was read %d times despite a denied authorization", src, n)
		}
	}
}

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), map[string]string{"interval.cpu": "not-a-duration"})
	if err := h.mod.Start(t.Context(), h.host); err == nil {
		t.Fatal("Start should fail on invalid configuration")
	}
}

func TestAllSourcesUnsupportedReportsUnsupportedNotFailure(t *testing.T) {
	// This is the path a build for an unsupported OS takes. It must move the
	// supervisor to its terminal unsupported state — degraded, no restarts —
	// rather than looking like a failure that will be retried forever.
	set := Set{Unsupported: []Unsupported{
		{Source: SourceCPU, Reason: "not implemented"},
	}}
	h := newHarness(t, set, nil)

	err := h.mod.Start(t.Context(), h.host)
	if err == nil {
		t.Fatal("Start should report unsupported when no source is available")
	}
	if !module.IsUnsupported(err) {
		t.Fatalf("error = %v, want an unsupported error", err)
	}
}

// ---------------------------------------------------------------------------
// Failure isolation
// ---------------------------------------------------------------------------

func TestPanickingReaderIsIsolated(t *testing.T) {
	// A defect in one reader must not stop the other six, and must not take
	// down the agent.
	f := newFakeReader()
	f.cpuFn = func(context.Context, bool) (CPUStats, error) { panic("nil map write in cpu reader") }

	h := newHarness(t, fullSet(f), nil)
	h.start()

	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}

	stats := h.mod.Statistics(t.Context()).Counters
	if stats["cpu.failures"] != 1 {
		t.Fatalf("cpu failures = %d, want 1", stats["cpu.failures"])
	}
	for _, src := range []Source{SourceMemory, SourceDisk, SourceFilesystem, SourceNetwork, SourceOS, SourceLoad} {
		if stats[src.String()+".successes"] != 1 {
			t.Errorf("%s did not collect despite an unrelated panic", src)
		}
	}

	var panics int
	for _, rec := range h.diags.Records() {
		if rec.Code == diagnostics.CodePanic {
			panics++
		}
	}
	if panics == 0 {
		t.Fatal("no panic diagnostic was recorded")
	}
}

func TestFailingReaderDoesNotAffectOthers(t *testing.T) {
	f := newFakeReader()
	f.memFn = func(context.Context) (MemoryStats, error) {
		return MemoryStats{}, errors.New("permission denied reading meminfo")
	}

	h := newHarness(t, fullSet(f), nil)
	h.start()
	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}

	stats := h.mod.Statistics(t.Context()).Counters
	if stats["memory.failures"] != 1 {
		t.Fatalf("memory failures = %d, want 1", stats["memory.failures"])
	}
	if stats["cpu.successes"] != 1 {
		t.Fatal("cpu collection was affected by an unrelated memory failure")
	}
	if v, _ := h.tel.CounterValue(MetricCollectionFailure, platform.A(AttrSource, "memory")); v != 1 {
		t.Fatalf("failure counter = %d, want 1", v)
	}
}

func TestStalledReaderIsSuspendedRatherThanRetried(t *testing.T) {
	// A statfs against a wedged mount never returns. Re-dispatching it every
	// cycle would accumulate one parked goroutine per cycle forever.
	release := make(chan struct{})
	defer close(release)

	var calls int
	var mu sync.Mutex
	f := newFakeReader()
	f.fsFn = func(context.Context) ([]FilesystemStats, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return nil, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{
		"collection.timeout":  "100ms",
		"interval.filesystem": "1s",
	})
	h.start()
	h.waitCollections(SourceFilesystem, 1)

	for i := 0; i < 5; i++ {
		h.advance(2 * time.Second)
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("a stalled reader was dispatched %d times, want 1", got)
	}

	// The other sources kept collecting throughout.
	if h.mod.Statistics(t.Context()).Counters["cpu.successes"] < 2 {
		t.Fatal("a stalled filesystem read stopped CPU collection")
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealthyWhenEverySourceWorks(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()
	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}
	if got := h.mod.Health(t.Context()).Status; got != health.Healthy {
		t.Fatalf("health = %v, want healthy", got)
	}
}

func TestDegradedWhenSomeSourcesAreUnavailable(t *testing.T) {
	// This is the normal Windows and macOS case. It must not read as failure,
	// or every host in a fleet reports a broken agent.
	f := newFakeReader()
	set := fullSet(f)
	set.Disk = nil
	set.Load = nil
	set.Unsupported = []Unsupported{
		{Source: SourceDisk, Reason: "requires elevation"},
		{Source: SourceLoad, Reason: "no load average on this platform"},
	}

	h := newHarness(t, set, nil)
	h.start()
	for _, src := range []Source{SourceCPU, SourceMemory, SourceFilesystem, SourceNetwork, SourceOS} {
		h.waitCollections(src, 1)
	}

	rep := h.mod.Health(t.Context())
	if rep.Status != health.Degraded {
		t.Fatalf("health = %v, want degraded", rep.Status)
	}
}

func TestUnhealthyWhenEveryAvailableSourceFails(t *testing.T) {
	f := newFakeReader()
	boom := errors.New("device gone")
	f.cpuFn = func(context.Context, bool) (CPUStats, error) { return CPUStats{}, boom }
	f.memFn = func(context.Context) (MemoryStats, error) { return MemoryStats{}, boom }

	set := Set{CPU: f, Memory: f}
	h := newHarness(t, set, nil)
	h.start()
	h.waitCollections(SourceCPU, 1)
	h.waitCollections(SourceMemory, 1)

	if got := h.mod.Health(t.Context()).Status; got != health.Unhealthy {
		t.Fatalf("health = %v, want unhealthy when nothing is collecting", got)
	}
}

func TestCapabilitiesReportUnsupportedSourcesWithReasons(t *testing.T) {
	set := fullSet(newFakeReader())
	set.Disk = nil
	set.Unsupported = []Unsupported{{Source: SourceDisk, Reason: "requires Administrator"}}

	h := newHarness(t, set, nil)
	caps := h.mod.Capabilities(t.Context())
	if len(caps) != len(AllSources) {
		t.Fatalf("reported %d capabilities, want %d", len(caps), len(AllSources))
	}
	for _, c := range caps {
		if c.Name == "host.disk" {
			if c.Available {
				t.Fatal("disk reported available when the reader is absent")
			}
			if c.Reason == "" {
				t.Fatal("an unavailable capability must carry a reason")
			}
			return
		}
	}
	t.Fatal("host.disk capability not reported")
}

// ---------------------------------------------------------------------------
// Entity binding
// ---------------------------------------------------------------------------

func TestObservationsCarryTheHostEntityID(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()
	h.waitCollections(SourceMemory, 1)

	if _, ok := h.tel.GaugeValue(MetricMemoryTotal, platform.A(AttrEntityID, "ent-host-1")); !ok {
		t.Fatal("memory total was not emitted with the platform host entity ID")
	}
}

func TestUnresolvedEntityEmitsDiagnosticAndNeverInventsAnID(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.host.Identity = inproc.NewIdentity("", "", "")
	h.start()
	h.waitCollections(SourceMemory, 1)

	var unresolved bool
	for _, rec := range h.diags.Records() {
		if rec.Code == diagnostics.CodeUnresolvedIdentity {
			unresolved = true
		}
	}
	if !unresolved {
		t.Fatal("no unresolved-identity diagnostic was recorded")
	}
	// The observation is still emitted, with NO entity attribute. An invented
	// ID would silently fork the platform entity graph.
	if _, ok := h.tel.GaugeValue(MetricMemoryTotal); !ok {
		t.Fatal("collection stopped because identity was unresolved")
	}
	if h.mod.Health(t.Context()).Status != health.Degraded {
		t.Fatal("unresolved entity binding should degrade health")
	}
}

// ---------------------------------------------------------------------------
// Telemetry contract and cardinality
// ---------------------------------------------------------------------------

func TestOnlyDeclaredAttributesAreEmitted(t *testing.T) {
	allowed := map[string]bool{
		AttrEntityID: true, AttrState: true, AttrCPU: true, AttrType: true,
		AttrDevice: true, AttrInterface: true, AttrMountpoint: true,
		AttrFSType: true, AttrSource: true, AttrReason: true,
		AttrInfoOS: true, AttrInfoPlatform: true, AttrInfoVersion: true,
		AttrInfoKernel: true, AttrInfoArch: true,
	}
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()
	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}
	for _, ev := range h.tel.Events() {
		for _, a := range ev.Attrs {
			if !allowed[a.Key] {
				t.Errorf("event %q carries undeclared attribute %q", ev.Name, a.Key)
			}
		}
	}
}

func TestCardinalityCapDropsAndReportsRatherThanGrowing(t *testing.T) {
	f := newFakeReader()
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		out := make([]InterfaceStats, 500)
		for i := range out {
			out[i] = InterfaceStats{Name: "if" + strconv.Itoa(i), RxBytes: KnownU64(uint64(i))}
		}
		return out, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{"network.max": "10"})
	h.start()
	h.waitCollections(SourceNetwork, 1)

	if got := h.mod.Statistics(t.Context()).Counters["network.dropped_series"]; got != 490 {
		t.Fatalf("dropped series = %d, want 490", got)
	}
	if v, _ := h.tel.CounterValue(MetricTelemetryDropped,
		platform.A(AttrSource, "network"), platform.A(AttrReason, dropReasonCardinality)); v != 490 {
		t.Fatalf("dropped counter = %d, want 490", v)
	}
}

func TestCardinalitySelectionIsStableAcrossCycles(t *testing.T) {
	// If the cap were applied in OS order, a host over its cap would report a
	// different subset every cycle — a churn of half-populated series that is
	// worse than reporting nothing.
	f := newFakeReader()
	order := 0
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		order++
		// The reader returns a different ORDER each cycle, which is what a real
		// OS does. Values stay monotonic per interface, since a decreasing
		// counter would legitimately be suppressed as a reset and would
		// confuse this test with a different property.
		names := []string{"eth2", "eth0", "eth1"}
		if order%2 == 0 {
			names = []string{"eth1", "eth2", "eth0"}
		}
		base := map[string]uint64{"eth0": 10, "eth1": 20, "eth2": 30}
		out := make([]InterfaceStats, 0, 3)
		for _, n := range names {
			out = append(out, InterfaceStats{Name: n, RxBytes: KnownU64(base[n] + 1000*uint64(order))})
		}
		return out, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{"network.max": "2", "interval.network": "1s"})
	h.start()
	h.waitCollections(SourceNetwork, 1)
	h.advance(2 * time.Second)
	h.waitCollections(SourceNetwork, 2)

	// eth0 and eth1 sort first, so they must be the pair kept both times.
	for _, name := range []string{"eth0", "eth1"} {
		if _, ok := h.tel.CounterValue(MetricNetworkRxBytes,
			platform.A(AttrEntityID, "ent-host-1"), platform.A(AttrInterface, name)); !ok {
			t.Errorf("interface %q was not consistently selected", name)
		}
	}
	if _, ok := h.tel.CounterValue(MetricNetworkRxBytes,
		platform.A(AttrEntityID, "ent-host-1"), platform.A(AttrInterface, "eth2")); ok {
		t.Error("eth2 sorts last and should never have been selected")
	}
}

func TestUnknownValuesAreNotEmittedAsZero(t *testing.T) {
	// The single most important property of this module: an absent measurement
	// is absent, never a plausible-looking zero.
	f := newFakeReader()
	f.memFn = func(context.Context) (MemoryStats, error) {
		return MemoryStats{Total: KnownU64(1000)}, nil // available/swap unknown
	}

	h := newHarness(t, fullSet(f), nil)
	h.start()
	h.waitCollections(SourceMemory, 1)

	entity := platform.A(AttrEntityID, "ent-host-1")
	if _, ok := h.tel.GaugeValue(MetricMemoryTotal, entity); !ok {
		t.Fatal("known total was not emitted")
	}
	for _, metric := range []string{MetricSwapTotal, MetricSwapUsed, MetricMemoryAvailable} {
		if _, ok := h.tel.GaugeValue(metric, entity); ok {
			t.Errorf("%s was emitted despite being unknown", metric)
		}
	}
}

func TestFirstCPUSampleEmitsNoUtilisation(t *testing.T) {
	// Emitting the raw cumulative counter as a delta produces the classic
	// "100% busy since boot" spike on the first scrape.
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()
	h.waitCollections(SourceCPU, 1)

	if _, ok := h.tel.GaugeValue(MetricCPUUtilization,
		platform.A(AttrEntityID, "ent-host-1"), platform.A(AttrState, "busy")); ok {
		t.Fatal("utilisation was emitted from a single sample")
	}
	// The count, which needs no delta, is emitted immediately.
	if _, ok := h.tel.GaugeValue(MetricCPUCount,
		platform.A(AttrEntityID, "ent-host-1"), platform.A(AttrType, "logical")); !ok {
		t.Fatal("CPU count should be emitted on the first sample")
	}
}

func TestSecondCPUSampleEmitsUtilisation(t *testing.T) {
	var n int
	f := newFakeReader()
	f.cpuFn = func(context.Context, bool) (CPUStats, error) {
		n++
		// 100 ticks pass, 25 of them busy.
		return CPUStats{HasTotal: true, LogicalCount: KnownU64(1), Total: CPUTimes{
			User: uint64(25 * n), Idle: uint64(75 * n),
		}}, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{"interval.cpu": "1s"})
	h.start()
	h.waitCollections(SourceCPU, 1)
	h.advance(2 * time.Second)
	h.waitCollections(SourceCPU, 2)

	entity := platform.A(AttrEntityID, "ent-host-1")
	busy, ok := h.tel.GaugeValue(MetricCPUUtilization, entity, platform.A(AttrState, "busy"))
	if !ok {
		t.Fatal("utilisation was not emitted on the second sample")
	}
	if busy < 0.24 || busy > 0.26 {
		t.Fatalf("busy = %v, want ~0.25", busy)
	}
}

func TestCountersEmitDeltasNotCumulativeValues(t *testing.T) {
	var n int
	f := newFakeReader()
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		n++
		return []InterfaceStats{{Name: "eth0", RxBytes: KnownU64(uint64(1000 * n))}}, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{"interval.network": "1s"})
	h.start()
	h.waitCollections(SourceNetwork, 1)
	h.advance(2 * time.Second)
	h.waitCollections(SourceNetwork, 2)

	got, _ := h.tel.CounterValue(MetricNetworkRxBytes,
		platform.A(AttrEntityID, "ent-host-1"), platform.A(AttrInterface, "eth0"))
	// First sample seeds the baseline (nothing emitted), second adds 1000.
	if got != 1000 {
		t.Fatalf("counter = %d, want 1000 (one delta, not the cumulative 2000)", got)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestPrepareDoesNotChangeLiveBehaviour(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()

	before := h.mod.settings.Interval(SourceCPU)
	if err := h.mod.PrepareConfig(t.Context(), config.ModuleConfig{
		Enabled:  true,
		Settings: map[string]string{"interval.cpu": "45s"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := h.mod.settings.Interval(SourceCPU); got != before {
		t.Fatalf("prepare changed the live interval to %v; it must only stage", got)
	}

	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := h.mod.settings.Interval(SourceCPU); got != 45*time.Second {
		t.Fatalf("commit did not apply the staged interval: %v", got)
	}
}

func TestRollbackDiscardsStagedConfiguration(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()

	if err := h.mod.PrepareConfig(t.Context(), config.ModuleConfig{
		Enabled: true, Settings: map[string]string{"interval.cpu": "45s"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.mod.RollbackConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.mod.CommitConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := h.mod.settings.Interval(SourceCPU); got != 10*time.Second {
		t.Fatalf("interval = %v after rollback; the staged value survived", got)
	}
}

func TestPrepareRejectsInvalidConfigurationWithoutStaging(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()

	err := h.mod.PrepareConfig(t.Context(), config.ModuleConfig{
		Enabled: true, Settings: map[string]string{"interval.cpu": "5ms"},
	})
	if err == nil {
		t.Fatal("a sub-second interval must be rejected")
	}
	if h.mod.staged != nil {
		t.Fatal("a rejected configuration was staged anyway")
	}
}

func TestDisabledSourceIsNotCollected(t *testing.T) {
	f := newFakeReader()
	h := newHarness(t, fullSet(f), map[string]string{"sources.disabled": "disk,network"})
	h.start()
	h.waitCollections(SourceCPU, 1)
	time.Sleep(30 * time.Millisecond)

	if n := f.callCount(SourceDisk); n != 0 {
		t.Errorf("disabled disk source was read %d times", n)
	}
	if n := f.callCount(SourceNetwork); n != 0 {
		t.Errorf("disabled network source was read %d times", n)
	}
}

func TestDisabledMetricIsNotEmitted(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), map[string]string{
		"metrics.disabled": MetricMemoryUtilization,
	})
	h.start()
	h.waitCollections(SourceMemory, 1)

	entity := platform.A(AttrEntityID, "ent-host-1")
	if _, ok := h.tel.GaugeValue(MetricMemoryUtilization, entity); ok {
		t.Fatal("a disabled metric was emitted")
	}
	if _, ok := h.tel.GaugeValue(MetricMemoryTotal, entity); !ok {
		t.Fatal("disabling one metric suppressed another")
	}
}

// ---------------------------------------------------------------------------
// Adaptive collection seam
// ---------------------------------------------------------------------------

func TestThrottleStretchesIntervals(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()

	base := h.mod.effectiveInterval(SourceCPU)
	if err := h.mod.Throttle(t.Context(), module.PressureHigh); err != nil {
		t.Fatal(err)
	}
	throttled := h.mod.effectiveInterval(SourceCPU)

	if throttled <= base {
		t.Fatalf("throttled interval %v is not longer than %v", throttled, base)
	}
	if throttled != base*4 {
		t.Fatalf("high pressure gave %v, want 4x %v", throttled, base)
	}
	if h.mod.Pressure() != module.PressureHigh {
		t.Fatal("pressure level was not recorded")
	}

	if err := h.mod.Throttle(t.Context(), module.PressureNone); err != nil {
		t.Fatal(err)
	}
	if got := h.mod.effectiveInterval(SourceCPU); got != base {
		t.Fatalf("returning to PressureNone gave %v, want %v", got, base)
	}
}

func TestThrottleIsIdempotentAndReturnsPromptly(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), nil)
	h.start()

	begin := time.Now()
	for i := 0; i < 100; i++ {
		if err := h.mod.Throttle(t.Context(), module.PressureModerate); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("100 Throttle calls took %v; it must return promptly", elapsed)
	}
}

func TestThrottleIsCappedSoCollectionStaysMeaningful(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), map[string]string{"interval.os": "6h"})
	h.start()
	if err := h.mod.Throttle(t.Context(), module.PressureCritical); err != nil {
		t.Fatal(err)
	}
	if got := h.mod.effectiveInterval(SourceOS); got != maxEffectiveInterval {
		t.Fatalf("interval = %v, want the %v cap", got, maxEffectiveInterval)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentReadersDoNotRace(t *testing.T) {
	h := newHarness(t, fullSet(newFakeReader()), map[string]string{"interval.cpu": "1s"})
	h.start()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = h.mod.Health(context.Background())
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
					_ = h.mod.Statistics(context.Background())
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
					_ = h.mod.Capabilities(context.Background())
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
					_ = h.mod.Throttle(context.Background(), module.PressureModerate)
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
