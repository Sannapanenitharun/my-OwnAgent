package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

type stubModule struct {
	id string

	mu     sync.Mutex
	starts int
	stops  int
}

func (m *stubModule) Manifest() module.Manifest {
	return module.Manifest{ID: module.ID(m.id), Version: "1.0.0", Category: module.CategoryCollector}
}

func (m *stubModule) Start(context.Context, module.Host) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starts++
	return nil
}

func (m *stubModule) Stop(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stops++
	return nil
}

func (m *stubModule) Health(context.Context) health.Report { return health.OK("") }

func (m *stubModule) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.starts, m.stops
}

func testPorts(identity *inproc.Identity) platform.Ports {
	if identity == nil {
		identity = inproc.NewIdentity("agent-1", "tenant-1", "host-1")
	}
	return platform.Ports{
		Runtime:   inproc.NewCapabilityRuntime(),
		Telemetry: inproc.NewTelemetry(),
		Identity:  identity,
		Clock:     platform.NewSystemClock(),
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewRequiresItsDependencies(t *testing.T) {
	if _, err := New(Options{Ports: testPorts(nil)}); err == nil {
		t.Error("a missing logger should be rejected")
	}
	if _, err := New(Options{Logger: discardLogger()}); err == nil {
		t.Error("missing platform ports should be rejected")
	}
}

func TestNewValidatesConfigurationBeforeWiringAnything(t *testing.T) {
	// This is the path `--check` exercises, so an installer can discover a
	// broken configuration before it creates a service that would crash-loop.
	path := writeConfig(t, `{"schema_version":1,"agent":{"health_interval":"0s"}}`)

	_, err := New(Options{ConfigPath: path, Ports: testPorts(nil), Logger: discardLogger()})
	if err == nil {
		t.Fatal("an invalid configuration must prevent construction")
	}
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v, want *config.ValidationError", err)
	}
}

func TestNewRejectsAModuleTheConfigurationDoesNotKnow(t *testing.T) {
	// A module registered but absent from configuration is disabled, not an
	// error; this asserts the inverse is caught at Start, not silently.
	path := writeConfig(t, `{"schema_version":1,"modules":{"host":{"enabled":true}}}`)

	a, err := New(Options{
		ConfigPath: path,
		Ports:      testPorts(nil),
		Logger:     discardLogger(),
		Modules:    []module.Module{&stubModule{id: "host"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !a.Config().Modules["host"].Enabled {
		t.Fatal("host should be enabled by this configuration")
	}
}

func TestUnresolvedIdentityIsRecordedNotInvented(t *testing.T) {
	// The agent must run without identity and say so. Fabricating an ID would
	// fork the platform entity graph in a way that is very hard to reconcile.
	a, err := New(Options{
		Ports:   testPorts(inproc.NewIdentity("", "", "")),
		Logger:  discardLogger(),
		Modules: []module.Module{&stubModule{id: "host"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var unresolved int
	for _, rec := range a.Diagnostics().Records() {
		if rec.Code == diagnostics.CodeUnresolvedIdentity {
			unresolved++
			if strings.Contains(rec.Message, "generated") || strings.Contains(rec.Message, "assigned") {
				t.Errorf("diagnostic suggests an identifier was invented: %q", rec.Message)
			}
		}
	}
	if unresolved != 3 {
		t.Fatalf("recorded %d unresolved-identity diagnostics, want 3 (agent, tenant, host)", unresolved)
	}
}

func TestResolvedIdentityProducesNoDiagnostic(t *testing.T) {
	a, err := New(Options{Ports: testPorts(nil), Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, rec := range a.Diagnostics().Records() {
		if rec.Code == diagnostics.CodeUnresolvedIdentity {
			t.Fatalf("unexpected unresolved-identity diagnostic: %s", rec)
		}
	}
}

func TestRunStartsModulesAndShutsDownOnCancel(t *testing.T) {
	path := writeConfig(t, `{"schema_version":1,"modules":{"host":{"enabled":true,"required":true}}}`)
	host := &stubModule{id: "host"}

	a, err := New(Options{
		ConfigPath: path,
		Ports:      testPorts(nil),
		Logger:     discardLogger(),
		Modules:    []module.Module{host},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := host.counts(); s == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if s, _ := host.counts(); s != 1 {
		t.Fatalf("module started %d times, want 1", s)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	if _, stops := host.counts(); stops != 1 {
		t.Fatalf("module stopped %d times, want 1", stops)
	}
}

func TestRunReturnsStructuralStartupFailures(t *testing.T) {
	// A dependency cycle is unrunnable; Run must surface it rather than
	// entering a loop that supervises nothing.
	path := writeConfig(t, `{"schema_version":1,"modules":{"a":{"enabled":true},"b":{"enabled":true}}}`)

	a, err := New(Options{
		ConfigPath: path,
		Ports:      testPorts(nil),
		Logger:     discardLogger(),
		Modules:    []module.Module{cyclicModule("a", "b"), cyclicModule("b", "a")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Run(ctx); err == nil {
		t.Fatal("Run should fail when the dependency graph cannot be resolved")
	}
}

type cyclic struct {
	stubModule
	dep string
}

func cyclicModule(id, dep string) module.Module {
	return &cyclic{stubModule: stubModule{id: id}, dep: dep}
}

func (c *cyclic) Manifest() module.Manifest {
	return module.Manifest{
		ID: module.ID(c.id), Version: "1.0.0",
		Dependencies: []module.ID{module.ID(c.dep)},
	}
}

func TestShutdownUsesAFreshContext(t *testing.T) {
	// Run's context is already cancelled when shutdown begins. If shutdown
	// inherited it, every module would abort cleanup immediately — turning a
	// graceful shutdown into an abrupt one exactly when gracefulness matters.
	path := writeConfig(t, `{"schema_version":1,"modules":{"slow":{"enabled":true}}}`)
	slow := &deadlineAwareModule{stubModule: stubModule{id: "slow"}}

	a, err := New(Options{
		ConfigPath: path,
		Ports:      testPorts(nil),
		Logger:     discardLogger(),
		Modules:    []module.Module{slow},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := slow.counts(); s == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	if slow.stopCtxErr != nil {
		t.Fatalf("Stop received an already-cancelled context: %v", slow.stopCtxErr)
	}
}

type deadlineAwareModule struct {
	stubModule
	stopCtxErr error
}

func (m *deadlineAwareModule) Stop(ctx context.Context) error {
	m.stopCtxErr = ctx.Err()
	return m.stubModule.Stop(ctx)
}
