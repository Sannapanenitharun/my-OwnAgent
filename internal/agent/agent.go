// Package agent is the observability agent's shell.
//
// It owns exactly three things: process-level wiring (configuration, ports,
// logging), the run loop that translates operating-system signals into
// lifecycle actions, and the module registration list. Everything else belongs
// to the supervisor or to a module.
//
// The shell is deliberately thin. One binary, one service, one identity, one
// configuration model — but the shell should not be where that unity is
// implemented, or it becomes the place every future feature is bolted onto.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/localui"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/supervisor"
)

// Options configures an Agent.
type Options struct {
	// ConfigPath is the configuration file; empty uses built-in defaults.
	ConfigPath string
	// Config, when non-nil, is used instead of loading ConfigPath. The
	// entrypoint loads configuration once so it can wire the OTLP adapter
	// from the same document the supervisor will run.
	Config *config.Config
	// Ports are the platform dependencies. All must be populated.
	Ports platform.Ports
	// Logger receives operational logs. Required.
	Logger *slog.Logger
	// Modules are the modules to register, in any order; the supervisor
	// resolves the start order from their manifests.
	Modules []module.Module
	// Loader supplies configuration. Nil selects a default loader.
	Loader *config.Loader
	// UIListen is the local status UI address. Empty, "off" or "-" disables it.
	UIListen string
	// Host carries IMDS/cloud facts for the local Hosts page. Empty fields
	// mean unresolved and must not be invented.
	Host localui.HostDetails
}

// Agent is the running observability agent.
type Agent struct {
	opts   Options
	loader *config.Loader
	log    *slog.Logger
	diags  *diagnostics.Recorder
	sup    *supervisor.Supervisor
	cfg    config.Config
	uiHTTP *http.Server
}

// New loads configuration, constructs the supervisor and registers modules. It
// starts nothing.
//
// Constructing without starting matters for the install experience: `--check`
// can exercise this whole path — real configuration, real validation, real
// manifests, real dependency resolution — and exit, so an installer discovers a
// broken configuration before it creates a service that would crash-loop.
func New(opts Options) (*Agent, error) {
	if opts.Logger == nil {
		return nil, errors.New("agent: Logger is required")
	}
	if err := opts.Ports.Validate(); err != nil {
		return nil, err
	}

	loader := opts.Loader
	if loader == nil {
		loader = config.NewLoader()
	}

	var cfg config.Config
	var err error
	if opts.Config != nil {
		cfg = *opts.Config
	} else {
		cfg, err = loader.LoadFile(opts.ConfigPath)
		if err != nil {
			return nil, err
		}
	}

	diags := diagnostics.NewRecorder(cfg.Agent.DiagnosticsRetention)

	sup, err := supervisor.New(supervisor.Options{
		Config:      cfg,
		Ports:       opts.Ports,
		Logger:      opts.Logger,
		Diagnostics: diags,
	})
	if err != nil {
		return nil, err
	}

	for _, m := range opts.Modules {
		if err := sup.Register(m); err != nil {
			return nil, err
		}
	}

	a := &Agent{opts: opts, loader: loader, log: opts.Logger, diags: diags, sup: sup, cfg: cfg}
	a.resolveIdentity(context.Background())
	return a, nil
}

// resolveIdentity resolves agent, tenant and host identity once at startup.
//
// Unresolved identity is recorded as a diagnostic and does not block startup.
// The agent still runs and still reports its own health; what it must not do is
// invent an identifier to fill the gap, because a fabricated entity ID forks
// the platform's entity graph in a way that is very hard to reconcile later.
func (a *Agent) resolveIdentity(ctx context.Context) {
	type field struct {
		name string
		fn   func(context.Context) (string, error)
	}
	fields := []field{
		{"agent_id", a.opts.Ports.Identity.AgentID},
		{"tenant_id", a.opts.Ports.Identity.TenantID},
		{"host_id", a.opts.Ports.Identity.HostID},
	}
	attrs := make([]any, 0, len(fields)*2)
	for _, f := range fields {
		v, err := f.fn(ctx)
		if err != nil {
			a.diags.Record(diagnostics.Record{
				Code:        diagnostics.CodeUnresolvedIdentity,
				Severity:    diagnostics.Warn,
				Source:      "agent",
				Message:     fmt.Sprintf("%s could not be resolved; telemetry will be emitted without it", f.name),
				Remediation: "verify platform identity configuration and connectivity",
				Attrs:       map[string]string{"field": f.name},
			})
			a.log.Warn("identity unresolved", "field", f.name, "error", err)
			continue
		}
		attrs = append(attrs, f.name, v)
	}
	if len(attrs) > 0 {
		a.log.Info("identity resolved", attrs...)
	}
}

// Config returns the currently loaded configuration.
func (a *Agent) Config() config.Config { return a.cfg }

// Supervisor exposes the supervisor for diagnostics and tests.
func (a *Agent) Supervisor() *supervisor.Supervisor { return a.sup }

// Diagnostics exposes the diagnostic recorder.
func (a *Agent) Diagnostics() *diagnostics.Recorder { return a.diags }

// Run starts the agent and blocks until ctx is cancelled or a termination
// signal arrives, then shuts down gracefully.
//
// Shutdown uses a context derived from Background rather than from ctx. This is
// deliberate: ctx is already cancelled by the time shutdown begins, and passing
// a cancelled context to Stop would cause every module to abort its cleanup
// immediately — turning graceful shutdown into an abrupt one at exactly the
// moment gracefulness is required.
func (a *Agent) Run(ctx context.Context) error {
	sigCtx, stop := signal.NotifyContext(ctx, terminationSignals()...)
	defer stop()

	reloads := make(chan os.Signal, 1)
	if sigs := reloadSignals(); len(sigs) > 0 {
		signal.Notify(reloads, sigs...)
		defer signal.Stop(reloads)
	}

	if err := a.sup.Start(sigCtx); err != nil {
		return fmt.Errorf("agent: startup failed: %w", err)
	}

	agg := a.sup.Health()
	a.log.Info("agent running", "health", agg.Status.String(), "modules", len(agg.Components))

	if err := a.startUI(); err != nil {
		a.log.Error("local UI not started", "error", err)
	}

	for {
		select {
		case <-sigCtx.Done():
			return a.shutdown()
		case <-reloads:
			a.log.Info("reload signal received")
			if err := a.reload(sigCtx); err != nil {
				// A rejected reload is an operator error, not an agent
				// failure. The agent keeps running the previous revision.
				a.log.Warn("configuration reload rejected", "error", err)
			}
		}
	}
}

func (a *Agent) reload(ctx context.Context) error {
	cfg, err := a.loader.LoadFile(a.opts.ConfigPath)
	if err != nil {
		return err
	}
	if err := a.sup.Reload(ctx, cfg); err != nil {
		return err
	}
	a.cfg = cfg
	return nil
}

func (a *Agent) startUI() error {
	if !localui.AddrEnabled(a.opts.UIListen) {
		return nil
	}
	ln, err := net.Listen("tcp", a.opts.UIListen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: (&localui.Server{
			Identity:    a.opts.Ports.Identity,
			Telemetry:   a.opts.Ports.Telemetry,
			Supervisor:  a.sup,
			Diagnostics: a.diags,
			Host:        a.opts.Host,
		}).Handler(),
	}
	a.uiHTTP = srv
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			a.log.Error("local UI server stopped", "error", err)
		}
	}()
	a.log.Info("local UI listening", "addr", "http://"+ln.Addr().String()+"/")
	return nil
}

func (a *Agent) shutdown() error {
	a.log.Info("shutdown requested")
	if a.uiHTTP != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.uiHTTP.Shutdown(ctx)
		cancel()
	}

	// Allow the configured shutdown budget plus a small margin, so the
	// supervisor's own deadline is the one that governs rather than this one.
	budget := a.cfg.Agent.ShutdownTimeout.Std() + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	err := a.sup.Shutdown(ctx)
	_ = platform.ShutdownTelemetry(ctx, a.opts.Ports.Telemetry)
	for _, rec := range a.diags.Records() {
		if rec.Severity == diagnostics.Error {
			a.log.Error("diagnostic", "record", rec.String())
		}
	}
	return err
}
