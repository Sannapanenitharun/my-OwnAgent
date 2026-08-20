// Package supervisor is the agent's root lifecycle controller.
//
// It owns module registration, dependency-ordered startup, health aggregation,
// failure isolation, restart with crash-loop protection, configuration reload
// and graceful shutdown.
//
// Scope, and why this exists alongside the platform Capability Runtime: the
// Capability Runtime owns capability ADMISSION — which capabilities may exist,
// with which permissions — and the supervisor calls it through
// platform.CapabilityRuntime for exactly that. What the supervisor adds is
// PROCESS-LOCAL SUPERVISION: restarting an OS-level collector that lost its
// kernel subscription, quarantining one that crash-loops, and stopping the
// agent's own modules in dependency order inside a single address space on a
// customer host. That is a host-execution concern with no equivalent in a
// platform-side runtime, and it is the documented architectural gap that
// justifies this package rather than a second lifecycle framework. See
// docs/adr/0002-supervisor-lifecycle.md.
//
// Concurrency model: all supervisor state is guarded by a single mutex. Module
// methods are NEVER called while that mutex is held; every Start, Stop and
// Health call is dispatched to a short-lived goroutine with a deadline. There
// is exactly one long-lived goroutine, the control loop.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// randSource produces a random source for a module's backoff jitter.
type randSource func() *rand.Rand

// Options configures a Supervisor.
type Options struct {
	// Config is the initial configuration. It must already be validated.
	Config config.Config
	// Ports are the platform dependencies. All must be populated.
	Ports platform.Ports
	// Logger receives operational logs. Required.
	Logger *slog.Logger
	// Diagnostics receives structured diagnostics. Required.
	Diagnostics *diagnostics.Recorder
	// NewRand supplies backoff jitter sources. Nil selects a seeded default;
	// tests inject a deterministic source.
	NewRand func() *rand.Rand
}

// Supervisor is the agent's root lifecycle controller.
type Supervisor struct {
	ports platform.Ports
	log   *slog.Logger
	diags *diagnostics.Recorder
	inst  *instruments

	newRand randSource

	mu        sync.RWMutex
	cfg       config.Config
	runners   map[module.ID]*runner
	regOrder  []module.ID
	graph     *Graph
	started   bool
	stopped   bool
	startedAt time.Time

	loopCancel context.CancelFunc
	loopDone   chan struct{}
	wake       chan struct{}
	failures   chan moduleFailure
	ops        sync.WaitGroup
}

type moduleFailure struct {
	id         module.ID
	generation uint64
	err        error
}

// New returns a Supervisor. It does not start anything.
func New(opts Options) (*Supervisor, error) {
	if err := opts.Ports.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		return nil, errors.New("supervisor: Logger is required")
	}
	if opts.Diagnostics == nil {
		return nil, errors.New("supervisor: Diagnostics is required")
	}
	if err := config.Validate(opts.Config); err != nil {
		return nil, err
	}

	newRand := opts.NewRand
	if newRand == nil {
		newRand = func() *rand.Rand {
			return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
		}
	}

	return &Supervisor{
		ports:    opts.Ports,
		log:      opts.Logger,
		diags:    opts.Diagnostics,
		inst:     newInstruments(opts.Ports.Telemetry),
		newRand:  newRand,
		cfg:      opts.Config.Clone(),
		runners:  make(map[module.ID]*runner),
		wake:     make(chan struct{}, 1),
		failures: make(chan moduleFailure, 64),
	}, nil
}

// Register adds a module. It must be called before Start.
//
// Registration is separate from starting so that the complete dependency graph
// is known before any module runs. Resolving dependencies incrementally would
// mean the start order depends on registration order, which is the kind of
// implicit coupling that makes a modular agent behave differently in test and
// in production.
func (s *Supervisor) Register(m module.Module) error {
	if m == nil {
		return errors.New("supervisor: cannot register a nil module")
	}
	manifest, err := safeValue(m.Manifest)
	if err != nil {
		return fmt.Errorf("supervisor: module manifest panicked: %w", err)
	}
	if manifest.ID == "" {
		return errors.New("supervisor: module manifest has an empty ID")
	}
	if manifest.Version == "" {
		return fmt.Errorf("supervisor: module %q has an empty Version", manifest.ID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("supervisor: cannot register %q after Start", manifest.ID)
	}
	if _, dup := s.runners[manifest.ID]; dup {
		return fmt.Errorf("supervisor: module %q is already registered", manifest.ID)
	}

	mc := s.cfg.ModuleFor(string(manifest.ID))
	r := newRunner(m, manifest, mc, s.cfg.Agent.Restart, s.newRand)
	if !mc.Enabled {
		r.state = module.StateDisabled
	}
	s.runners[manifest.ID] = r
	s.regOrder = append(s.regOrder, manifest.ID)
	return nil
}

// Start resolves dependencies, starts every enabled module in dependency
// order, and launches the control loop.
//
// It returns an error only for STRUCTURAL failures — a dependency cycle, a
// missing dependency, an already-started supervisor — because those mean the
// agent's configuration cannot be honoured at all. An individual module failing
// to start is not a structural failure: it is recorded, isolated, restarted and
// reflected in health, and the rest of the agent runs. An agent that refuses to
// boot because one collector is unavailable is worse than no agent, since it
// takes the working collectors down with it.
func (s *Supervisor) Start(ctx context.Context) error {
	begin := s.ports.Clock.Now()

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("supervisor: already started")
	}
	if s.stopped {
		s.mu.Unlock()
		return errors.New("supervisor: already shut down")
	}

	manifests := make(map[module.ID]module.Manifest, len(s.runners))
	for id, r := range s.runners {
		if r.cfg.Enabled {
			manifests[id] = r.manifest
		}
	}
	graph, err := Resolve(manifests)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.graph = graph
	s.started = true
	s.startedAt = begin
	order := graph.StartOrder()
	s.mu.Unlock()

	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("supervisor: startup cancelled: %w", err)
		}
		s.startOnce(ctx, id)
	}

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.loopCancel = cancel
	s.loopDone = make(chan struct{})
	s.mu.Unlock()
	go s.loop(loopCtx)

	elapsed := s.ports.Clock.Now().Sub(begin)
	s.inst.startupLatency.Observe(elapsed.Seconds())
	s.ports.Telemetry.Emit(platform.Event{
		Name:      EventAgentStarted,
		Severity:  platform.SeverityInfo,
		Timestamp: s.ports.Clock.Now(),
	})
	s.log.Info("agent started",
		"modules", len(order),
		"startup", elapsed,
		"config_revision", s.cfg.Revision)
	return nil
}

// startOnce performs a single synchronous start attempt.
func (s *Supervisor) startOnce(ctx context.Context, id module.ID) {
	r, host, gen, ok := s.claimStart(ctx, id)
	if !ok {
		return
	}
	s.runStart(ctx, r, host, gen)
}

// claimStart takes the module from a startable state into Starting, and builds
// its Host. It returns false when the start must not proceed.
func (s *Supervisor) claimStart(ctx context.Context, id module.ID) (*runner, module.Host, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.runners[id]
	if !ok || s.stopped {
		return nil, module.Host{}, 0, false
	}
	if r.opInFlight || !r.cfg.Enabled {
		return nil, module.Host{}, 0, false
	}
	if !module.CanTransition(r.state, module.StateStarting) {
		return nil, module.Host{}, 0, false
	}

	// A module may only start once every dependency is running. This is
	// re-checked at each attempt rather than trusted from startup ordering,
	// because a dependency can fail after the dependent was started.
	if s.graph != nil {
		for _, dep := range s.graph.Dependencies(id) {
			d, exists := s.runners[dep]
			if !exists || d.state != module.StateRunning {
				r.state = module.StateFailed
				r.blockedOnDeps = true
				r.lastErr = fmt.Errorf("dependency %q is not running", dep)
				r.retryAt = s.ports.Clock.Now().Add(s.cfg.Agent.Restart.InitialBackoff.Std())
				s.diags.Record(diagnostics.Record{
					Code:        diagnostics.CodeDependencyUnavailable,
					Severity:    diagnostics.Warn,
					Source:      string(id),
					Message:     "start deferred: a required dependency is not running",
					Remediation: "check the health of the named dependency; this module will start automatically once it is available",
					Attrs:       map[string]string{"dependency": string(dep)},
				})
				s.setStateLocked(r, module.StateFailed)
				return nil, module.Host{}, 0, false
			}
		}
	}

	r.generation++
	gen := r.generation
	r.opInFlight = true
	r.blockedOnDeps = false
	r.retryAt = time.Time{}
	s.setStateLocked(r, module.StateStarting)

	host := module.Host{
		ID:          id,
		Logger:      s.log.With("module", string(id)),
		Telemetry:   s.ports.Telemetry,
		Clock:       s.ports.Clock,
		Identity:    s.ports.Identity,
		Diagnostics: diagnostics.Scoped(string(id), s.diags),
		Config:      r.cfg,
		Authorize: func(actx context.Context, perm platform.Permission) error {
			return s.ports.Runtime.Authorize(actx, string(id), perm)
		},
		ReportFailure: func(err error) {
			s.reportFailure(id, gen, err)
		},
	}
	_ = ctx
	return r, host, gen, true
}

// runStart registers the capability, calls Start, and records the outcome.
// It never holds the supervisor mutex across a module call.
func (s *Supervisor) runStart(ctx context.Context, r *runner, host module.Host, gen uint64) {
	s.mu.RLock()
	startTimeout := s.cfg.Agent.ModuleStartTimeout.Std()
	stopTimeout := s.cfg.Agent.ModuleStopTimeout.Std()
	s.mu.RUnlock()

	s.inst.starts.Add(1, platform.A(AttrModule, string(r.id)))
	begin := s.ports.Clock.Now()

	// Admission first. A module that is not permitted to run must never have
	// had its Start called, so the permission check strictly precedes any
	// module code.
	lease, err := s.ports.Runtime.Register(ctx, platform.CapabilityDescriptor{
		ID:          string(r.id),
		Version:     r.manifest.Version,
		Permissions: r.manifest.Permissions,
	})
	if err != nil {
		s.finishStart(r, gen, nil, fmt.Errorf("capability admission refused: %w", err), begin)
		return
	}

	err, startSettled := withTimeout(ctx, startTimeout, func(cctx context.Context) error {
		return r.mod.Start(cctx, host)
	})
	if err != nil {
		// Hold the slot until Start has genuinely returned. A module that
		// overran its deadline is still executing, and dispatching the cleanup
		// Stop — or a later restart — into it concurrently would be worse than
		// the delay.
		<-startSettled

		// Start can fail after acquiring resources — a collector that opened
		// its kernel subscription and then failed to open its output buffer
		// still owns the subscription. Stop is idempotent and is contracted to
		// tolerate a partial start, so it is called here to let the module
		// release whatever it managed to acquire. Without this, every failed
		// start would leak, and a crash-looping module would leak repeatedly.
		serr, stopSettled := withTimeout(ctx, stopTimeout, r.mod.Stop)
		<-stopSettled
		if serr != nil {
			s.log.Warn("module cleanup after a failed start did not complete",
				"module", string(r.id), "error", serr)
			s.diags.Record(diagnostics.Record{
				Code:     diagnostics.CodeStopFailed,
				Severity: diagnostics.Warn,
				Source:   string(r.id),
				Message:  "cleanup after a failed start did not complete; resources may be held until the agent restarts",
			})
		}
		// Release the lease so a refused module holds no admission slot.
		_ = lease.Release(ctx)
		lease = nil
	}
	s.finishStart(r, gen, lease, err, begin)
}

// finishStart records a start outcome and decides what happens next.
func (s *Supervisor) finishStart(r *runner, gen uint64, lease platform.Lease, err error, begin time.Time) {
	now := s.ports.Clock.Now()
	attr := platform.A(AttrModule, string(r.id))
	s.inst.startLatency.Observe(now.Sub(begin).Seconds(), attr)

	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.nudgeLocked()

	r.opInFlight = false
	if gen != r.generation {
		// The module was stopped or restarted while this attempt was in
		// flight. Discard the result rather than resurrecting a stale
		// instance, and release whatever admission it obtained.
		if lease != nil {
			go func() { _ = lease.Release(context.Background()) }()
		}
		return
	}

	switch {
	case err == nil:
		r.lease = lease
		r.lastErr = nil
		r.attempt = 0
		r.startedAt = now
		r.report = health.Report{Status: health.Unknown, Message: "awaiting first health probe"}
		s.setStateLocked(r, module.StateRunning)
		s.log.Info("module started", "module", string(r.id), "version", r.manifest.Version)

	case module.IsUnsupported(err):
		// Not a failure. The module cannot run here; say so and stop trying.
		r.lastErr = err
		s.setStateLocked(r, module.StateUnsupported)
		s.diags.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Source:      string(r.id),
			Message:     err.Error(),
			Remediation: "no action required; this module's functionality is unavailable in this environment",
		})
		s.ports.Telemetry.Emit(platform.Event{
			Name:      EventModuleUnsupported,
			Severity:  platform.SeverityWarn,
			Timestamp: now,
			Attrs:     []platform.Attr{attr},
		})
		s.log.Info("module unsupported in this environment", "module", string(r.id), "reason", err.Error())

	default:
		s.inst.startFailures.Add(1, attr)
		var pe *PanicError
		if errors.As(err, &pe) {
			s.inst.panics.Add(1, attr)
			s.diags.Record(diagnostics.Record{
				Code:     diagnostics.CodePanic,
				Severity: diagnostics.Error,
				Source:   string(r.id),
				Message:  "module panicked during Start and was isolated",
			})
			s.log.Error("module panicked during start",
				"module", string(r.id), "panic", fmt.Sprint(pe.Value), "stack", pe.Stack)
		}
		r.lastErr = err
		s.failLocked(r, err, now, diagnostics.CodeStartFailed)
	}
}

// failLocked transitions a module to Failed and schedules a retry, or
// quarantines it if the crash-loop budget is exhausted.
func (s *Supervisor) failLocked(r *runner, err error, now time.Time, code diagnostics.Code) {
	attr := platform.A(AttrModule, string(r.id))
	s.diags.Record(diagnostics.Record{
		Code:     code,
		Severity: diagnostics.Error,
		Source:   string(r.id),
		Message:  err.Error(),
	})

	if !s.cfg.Agent.Restart.Enabled {
		s.setStateLocked(r, module.StateFailed)
		s.log.Error("module failed; automatic restart is disabled",
			"module", string(r.id), "error", err)
		return
	}

	r.attempt++
	if !r.window.record(now) {
		s.inst.crashLoops.Add(1, attr)
		s.setStateLocked(r, module.StateCrashLooping)
		s.diags.Record(diagnostics.Record{
			Code:     diagnostics.CodeCrashLoop,
			Severity: diagnostics.Error,
			Source:   string(r.id),
			Message: fmt.Sprintf("exceeded %d restarts within %s; module quarantined",
				s.cfg.Agent.Restart.MaxRestarts, s.cfg.Agent.Restart.Window),
			Remediation: "fix the underlying fault, then reload configuration or restart the agent to release the quarantine",
		})
		s.ports.Telemetry.Emit(platform.Event{
			Name:      EventModuleCrashLoop,
			Severity:  platform.SeverityError,
			Timestamp: now,
			Attrs:     []platform.Attr{attr},
		})
		s.log.Error("module quarantined after crash loop",
			"module", string(r.id),
			"max_restarts", s.cfg.Agent.Restart.MaxRestarts,
			"window", s.cfg.Agent.Restart.Window.String())
		return
	}

	delay := r.backoff.delay(r.attempt)
	r.retryAt = now.Add(delay)
	s.setStateLocked(r, module.StateFailed)
	s.log.Warn("module failed; scheduling restart",
		"module", string(r.id), "attempt", r.attempt, "retry_in", delay, "error", err)
}

// reportFailure receives a runtime failure reported by a running module.
func (s *Supervisor) reportFailure(id module.ID, gen uint64, err error) {
	if err == nil {
		err = errors.New("module reported an unspecified failure")
	}
	select {
	case s.failures <- moduleFailure{id: id, generation: gen, err: err}:
	default:
		// The queue is full, which means the supervisor already has pending
		// failures for this module. Dropping is correct: the outcome is the
		// same, and blocking here would stall the reporting module's own
		// goroutine inside a callback the contract promises is non-blocking.
	}
}

// setStateLocked applies a state transition and emits the associated telemetry.
func (s *Supervisor) setStateLocked(r *runner, to module.State) {
	from := r.state
	if from == to {
		return
	}
	if !module.CanTransition(from, to) {
		// An illegal transition is a supervisor bug, not a module fault. Log
		// loudly and apply it anyway: refusing would leave the module in a
		// state that no longer matches reality, which is strictly worse.
		s.log.Error("illegal module state transition",
			"module", string(r.id), "from", from.String(), "to", to.String())
	}
	r.state = to
	attr := platform.A(AttrModule, string(r.id))
	s.inst.moduleState.Set(float64(to), attr)
	s.ports.Telemetry.Emit(platform.Event{
		Name:      EventModuleStateChanged,
		Severity:  platform.SeverityInfo,
		Timestamp: s.ports.Clock.Now(),
		Attrs: []platform.Attr{
			attr,
			platform.A("from", from.String()),
			platform.A("to", to.String()),
		},
	})
}

func (s *Supervisor) nudgeLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Supervisor) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
