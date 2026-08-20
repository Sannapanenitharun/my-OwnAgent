package inproc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
)

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

func TestCounterAccumulatesPerSeries(t *testing.T) {
	tel := NewTelemetry()
	c := tel.Counter("agent.test.counter")
	c.Add(2, platform.A("module", "host"))
	c.Add(3, platform.A("module", "host"))
	c.Add(7, platform.A("module", "logs"))

	if v, _ := tel.CounterValue("agent.test.counter", platform.A("module", "host")); v != 5 {
		t.Fatalf("host counter = %d, want 5", v)
	}
	if v, _ := tel.CounterValue("agent.test.counter", platform.A("module", "logs")); v != 7 {
		t.Fatalf("logs counter = %d, want 7", v)
	}
}

func TestSeriesKeyIsOrderIndependent(t *testing.T) {
	// Two call sites listing the same attributes in different orders must hit
	// one series, not two — otherwise attribute ordering silently doubles
	// cardinality.
	tel := NewTelemetry()
	c := tel.Counter("m")
	c.Add(1, platform.A("a", "1"), platform.A("b", "2"))
	c.Add(1, platform.A("b", "2"), platform.A("a", "1"))

	if got := tel.SeriesCount("m"); got != 1 {
		t.Fatalf("series count = %d, want 1", got)
	}
	if v, _ := tel.CounterValue("m", platform.A("a", "1"), platform.A("b", "2")); v != 2 {
		t.Fatalf("counter = %d, want 2", v)
	}
}

func TestCardinalityBoundDropsRatherThanGrows(t *testing.T) {
	// An agent must never destabilise its host. A truncated metric with a loud
	// diagnostic is recoverable; an OOM is not.
	tel := NewTelemetry(WithMaxSeries(10))
	c := tel.Counter("unbounded")
	for i := 0; i < 1000; i++ {
		c.Add(1, platform.A("pid", strconv.Itoa(i)))
	}

	if got := tel.SeriesCount("unbounded"); got != 10 {
		t.Fatalf("series count = %d, want the bound of 10", got)
	}
	if got := tel.DroppedSeries("unbounded"); got != 990 {
		t.Fatalf("dropped = %d, want 990", got)
	}
}

func TestExistingSeriesStillUpdateAtTheBound(t *testing.T) {
	// Dropping must apply to NEW series only; an established series going
	// silent would be a worse failure than the cardinality it prevents.
	tel := NewTelemetry(WithMaxSeries(2))
	c := tel.Counter("m")
	c.Add(1, platform.A("k", "a"))
	c.Add(1, platform.A("k", "b"))
	c.Add(1, platform.A("k", "c")) // dropped
	c.Add(5, platform.A("k", "a")) // must still land

	if v, _ := tel.CounterValue("m", platform.A("k", "a")); v != 6 {
		t.Fatalf("established series = %d, want 6", v)
	}
}

func TestGaugeAndHistogram(t *testing.T) {
	tel := NewTelemetry()
	tel.Gauge("g").Set(42.5)
	if v, ok := tel.GaugeValue("g"); !ok || v != 42.5 {
		t.Fatalf("gauge = %v, %v", v, ok)
	}

	h := tel.Histogram("h")
	for _, v := range []float64{1, 5, 3} {
		h.Observe(v)
	}
	d, ok := tel.HistogramValue("h")
	if !ok {
		t.Fatal("histogram series missing")
	}
	if d.Count != 3 || d.Sum != 9 || d.Min != 1 || d.Max != 5 {
		t.Fatalf("distribution = %+v", d)
	}
}

func TestEventRingIsBounded(t *testing.T) {
	tel := NewTelemetry(WithMaxEvents(4))
	for i := 0; i < 50; i++ {
		tel.Emit(platform.Event{Name: fmt.Sprintf("e%d", i)})
	}
	events := tel.Events()
	if len(events) != 4 {
		t.Fatalf("retained %d events, want 4", len(events))
	}
	if events[len(events)-1].Name != "e49" {
		t.Fatalf("newest event = %q, want e49", events[len(events)-1].Name)
	}
}

func TestLogsAndTracesDropAtTheBound(t *testing.T) {
	tel := NewTelemetry(WithMaxLogs(2), WithMaxTraces(1))
	tel.EmitLog(platform.LogRecord{Body: "a"})
	tel.EmitLog(platform.LogRecord{Body: "b"})
	tel.EmitLog(platform.LogRecord{Body: "c"})
	if tel.DroppedLogs() != 1 {
		t.Fatalf("dropped logs = %d, want 1", tel.DroppedLogs())
	}
	logs := tel.DrainLogs()
	if len(logs) != 2 {
		t.Fatalf("drained %d logs, want 2", len(logs))
	}
	if extra := tel.DrainLogs(); len(extra) != 0 {
		t.Fatal("second drain should be empty")
	}

	tel.IngestTraces(platform.TracePayload{Body: []byte("one")})
	tel.IngestTraces(platform.TracePayload{Body: []byte("two")})
	if tel.DroppedTraces() != 1 {
		t.Fatalf("dropped traces = %d, want 1", tel.DroppedTraces())
	}
}

func TestEmitStampsTimestamp(t *testing.T) {
	tel := NewTelemetry()
	tel.Emit(platform.Event{Name: "e"})
	if tel.Events()[0].Timestamp.IsZero() {
		t.Fatal("event timestamp was not stamped")
	}
}

func TestTelemetryIsConcurrencySafe(t *testing.T) {
	tel := NewTelemetry()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); tel.Counter("c").Add(1, platform.A("k", "v")) }()
		go func() { defer wg.Done(); tel.Gauge("g").Set(1) }()
		go func() { defer wg.Done(); tel.Histogram("h").Observe(1) }()
		go func() { defer wg.Done(); tel.Emit(platform.Event{Name: "e"}) }()
	}
	wg.Wait()
	if v, _ := tel.CounterValue("c", platform.A("k", "v")); v != 32 {
		t.Fatalf("counter = %d, want 32", v)
	}
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

func TestIdentityReportsUnresolvedRatherThanInventing(t *testing.T) {
	// A locally invented entity ID silently forks the platform entity graph,
	// which is far harder to reconcile than an unresolved diagnostic.
	id := NewIdentity("", "", "")
	for name, fn := range map[string]func() (string, error){
		"agent":  func() (string, error) { return id.AgentID(t.Context()) },
		"tenant": func() (string, error) { return id.TenantID(t.Context()) },
		"host":   func() (string, error) { return id.HostID(t.Context()) },
	} {
		v, err := fn()
		if !errors.Is(err, platform.ErrUnresolved) {
			t.Errorf("%s: error = %v, want ErrUnresolved", name, err)
		}
		if v != "" {
			t.Errorf("%s: returned %q alongside an error", name, v)
		}
	}
}

func TestIdentityReturnsConfiguredValues(t *testing.T) {
	id := NewIdentity("agent-1", "tenant-1", "host-1")
	got, err := id.HostID(t.Context())
	if err != nil || got != "host-1" {
		t.Fatalf("HostID = %q, %v", got, err)
	}
}

// ---------------------------------------------------------------------------
// Capability runtime
// ---------------------------------------------------------------------------

func TestRuntimeFailsClosedOnUngrantedPermission(t *testing.T) {
	rt := NewCapabilityRuntime()
	_, err := rt.Register(t.Context(), platform.CapabilityDescriptor{
		ID: "process", Version: "1", Permissions: []platform.Permission{"read:proc"},
	})
	if !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if rt.ActiveCount() != 0 {
		t.Fatal("a denied capability holds an admission slot")
	}
}

func TestRuntimeAdmitsGrantedCapability(t *testing.T) {
	rt := NewCapabilityRuntime()
	rt.Grant("process", "read:proc")

	lease, err := rt.Register(t.Context(), platform.CapabilityDescriptor{
		ID: "process", Version: "1", Permissions: []platform.Permission{"read:proc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Authorize(t.Context(), "process", "read:proc"); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := rt.Authorize(t.Context(), "process", "write:proc"); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("an ungranted permission was authorized: %v", err)
	}
	if err := lease.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rt.ActiveCount() != 0 {
		t.Fatal("released lease still counted as active")
	}
}

func TestAuthorizeDeniesUnregisteredCapability(t *testing.T) {
	rt := NewCapabilityRuntime()
	rt.Grant("ghost", "read:proc")
	if err := rt.Authorize(t.Context(), "ghost", "read:proc"); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("an unregistered capability was authorized: %v", err)
	}
}

func TestAuthorizeFailsClosedOnCancelledContext(t *testing.T) {
	// An expired context must deny, never allow.
	rt := NewCapabilityRuntime()
	rt.Grant("a", "p")
	if _, err := rt.Register(t.Context(), platform.CapabilityDescriptor{
		ID: "a", Version: "1", Permissions: []platform.Permission{"p"},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := rt.Authorize(ctx, "a", "p"); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("cancelled context did not deny: %v", err)
	}
}

func TestRuntimeRejectsDuplicateRegistration(t *testing.T) {
	rt := NewCapabilityRuntime()
	desc := platform.CapabilityDescriptor{ID: "a", Version: "1"}
	if _, err := rt.Register(t.Context(), desc); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Register(t.Context(), desc); err == nil {
		t.Fatal("duplicate registration should fail")
	}
}

func TestLeaseReleaseIsIdempotent(t *testing.T) {
	rt := NewCapabilityRuntime()
	lease, err := rt.Register(t.Context(), platform.CapabilityDescriptor{ID: "a", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := lease.Release(t.Context()); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if got := rt.ReleaseCount("a"); got != 1 {
		t.Fatalf("release recorded %d times, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Ports validation
// ---------------------------------------------------------------------------

func TestPortsValidateNamesEveryMissingPort(t *testing.T) {
	err := platform.Ports{}.Validate()
	var mpe *platform.MissingPortsError
	if !errors.As(err, &mpe) {
		t.Fatalf("error = %v, want *MissingPortsError", err)
	}
	if len(mpe.Missing) != 4 {
		t.Fatalf("missing = %v, want all four ports named", mpe.Missing)
	}
}

func TestPortsValidateAcceptsCompleteSet(t *testing.T) {
	ports := platform.Ports{
		Runtime:   NewCapabilityRuntime(),
		Telemetry: NewTelemetry(),
		Identity:  NewIdentity("a", "t", "h"),
		Clock:     platform.NewSystemClock(),
	}
	if err := ports.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
