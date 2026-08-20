package module

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
)

func configFragment() config.ModuleConfig {
	return config.ModuleConfig{Enabled: true, Settings: map[string]string{"interval": "10s"}}
}

func TestBaseSuppliesUsableDefaults(t *testing.T) {
	var b Base
	ctx := t.Context()

	if got := b.Diagnostics(ctx); got != nil {
		t.Fatalf("default Diagnostics() = %v, want nil", got)
	}
	if got := b.Capabilities(ctx); got != nil {
		t.Fatalf("default Capabilities() = %v, want nil", got)
	}
	stats := b.Statistics(ctx)
	if stats.Counters == nil || stats.Gauges == nil {
		t.Fatal("default Statistics() returned nil maps; callers should not have to nil-check")
	}
	if len(stats.Counters) != 0 || len(stats.Gauges) != 0 {
		t.Fatal("default Statistics() should be empty")
	}
}

func TestBaseStoresHost(t *testing.T) {
	var b Base
	if b.Host().ID != "" {
		t.Fatal("Base.Host() should be the zero value before Init")
	}
	b.Init(Host{ID: "host"})
	if b.Host().ID != "host" {
		t.Fatalf("Base.Host().ID = %q, want %q", b.Host().ID, "host")
	}
}

// TestBaseDoesNotSatisfyModule is a compile-time-shaped assertion in test form:
// embedding Base must not make a type accidentally satisfy Module, or authors
// could forget Start/Stop/Health and still register a do-nothing module.
func TestBaseDoesNotSatisfyModule(t *testing.T) {
	type embedsBase struct{ Base }
	var v any = &embedsBase{}
	if _, ok := v.(Module); ok {
		t.Fatal("embedding Base alone satisfies Module; the required surface can be forgotten")
	}
}

func TestCategoryAndPriorityHaveNames(t *testing.T) {
	for c := CategoryCollector; c <= CategoryLifecycle; c++ {
		if c.String() == "unknown" {
			t.Errorf("category %d has no name", int(c))
		}
	}
	for p := PriorityCritical; p <= PriorityLow; p++ {
		if p.String() == "unknown" {
			t.Errorf("priority %d has no name", int(p))
		}
	}
}

func TestNoopHelpers(t *testing.T) {
	if err := NoopStop(t.Context()); err != nil {
		t.Fatalf("NoopStop returned %v", err)
	}
	if got := AlwaysHealthy(t.Context()).Status.String(); got != "healthy" {
		t.Fatalf("AlwaysHealthy status = %q", got)
	}
}
