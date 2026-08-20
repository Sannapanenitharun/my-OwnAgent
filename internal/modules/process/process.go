package process

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/guard"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// ID is the process module's identifier.
const ID module.ID = "process"

// Version is the process module's implementation version.
const Version = "1.0.0"

// PermissionRead is the platform permission the module requires.
//
// Reading /proc, a toolhelp snapshot or kern.proc needs no OS privilege, so this
// is an authorization statement to the platform, not a request for elevation.
// The module never asks the operating system for more than it has.
const PermissionRead platform.Permission = "process:read"

// maxEffectiveInterval caps what throttling may stretch the interval to. Beyond
// this the module is not observing processes in any useful sense, and the
// governor should stop it rather than let it pretend.
const maxEffectiveInterval = 30 * time.Minute

// Module collects process telemetry.
//
// It owns exactly ONE goroutine. Every process on the host is read from that
// goroutine, in one deadline-bounded sweep per interval. There is no goroutine
// per process, no timer per process and no watcher per process — the resource
// cost of this module is independent of how many processes exist, which is the
// property that makes it safe on a fifty-thousand-process machine.
type Module struct {
	set Set

	mu       sync.RWMutex
	settings Settings
	staged   *Settings
	pressure module.PressureLevel
	entityID string
	started  bool
	health   healthState

	host module.Host
	inst *instruments

	// Owned by the collection goroutine after Start.
	em       *emitter
	store    *store
	res      *resolver
	bootID   string
	numCPU   int
	selfAttr []platform.Attr

	lastStarted  int64
	lastExited   int64
	lastReplaced int64
	unresolved   int64

	cancel      context.CancelFunc
	done        chan struct{}
	reconfigure chan struct{}

	// stalled marks a collection whose deadline passed while the reader had not
	// returned. No further cycle is started until it settles, so a wedged
	// procfs costs one parked goroutine once rather than one per interval.
	stalled bool
	settled <-chan struct{}
}

// healthState is the module's own view of itself, updated by the collection
// goroutine and read by the supervisor's health probe.
type healthState struct {
	cycles       int64
	failures     int64
	lastErr      string
	lastSuccess  time.Time
	discovered   int64
	unreadable   int64
	denied       int64
	vanished     int64
	droppedProc  int64
	droppedExec  int64
	stateEntries int
	executables  int
	invalidNames int64
	unresolved   int64

	// Copies of the store's lifetime counters. The store belongs to the
	// collection goroutine; Statistics is called by the supervisor on its own
	// goroutine, so the values are snapshotted here under the mutex rather than
	// read across the boundary.
	totalStarted  int64
	totalExited   int64
	totalReplaced int64
	totalEvicted  int64
}

// New returns a process module using the platform's readers.
func New() *Module { return NewWithSet(NewSet()) }

// NewWithSet returns a process module using an explicit reader set. Tests use it
// to inject failing, panicking and unsupported readers; production uses New.
func NewWithSet(set Set) *Module {
	return &Module{
		set:      set,
		settings: DefaultSettings(),
		store:    newStore(),
		numCPU:   numCPUFor(runtime.NumCPU()),
	}
}

// Manifest implements module.Module.
func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryCollector,
		Description: "process inventory, resource usage and lifecycle telemetry",
		Permissions: []platform.Permission{PermissionRead},
		// Normal, not High. Host telemetry is the baseline everything else is
		// interpreted against and is shed last; process detail is valuable but
		// an agent under real pressure should give it up before it gives up
		// knowing whether the machine is alive.
		Priority: module.PriorityNormal,
	}
}

// Start implements module.Module. It returns promptly; collection runs on the
// single goroutine it launches.
func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}

	// Without enumeration there is no process module. Reporting unsupported
	// (rather than failing) puts it in the supervisor's terminal unsupported
	// state: degraded health, a diagnostic, and no restart attempts against a
	// condition that cannot change.
	if !m.set.Has(FeatureEnumeration) {
		return module.Unsupported(
			"process enumeration is not available on this platform: " +
				m.set.UnsupportedReason(FeatureEnumeration))
	}

	if err := h.Authorize(ctx, PermissionRead); err != nil {
		return fmt.Errorf("process: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("process: already started")
	}
	m.settings = settings
	m.host = h
	m.inst = newInstruments(h.Telemetry)
	m.em = newEmitter(m.inst, settings)
	m.res = newResolver(h.Identity)
	m.started = true
	m.reconfigure = make(chan struct{}, 1)
	m.done = make(chan struct{})
	m.mu.Unlock()

	m.resolveHostEntity(ctx)
	m.readBootIdentity(ctx)
	m.recordUnsupportedDiagnostics()

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()

	go m.run(runCtx)
	return nil
}

// resolveHostEntity binds telemetry to the platform host entity.
//
// If the platform cannot resolve one, the module records an unresolved
// diagnostic, reports degraded health, and emits observations with NO entity
// attribute. It does not invent an identifier: a locally generated entity ID
// silently forks the platform's entity graph, and reconciling that afterwards is
// far more expensive than a missing attribute.
func (m *Module) resolveHostEntity(ctx context.Context) {
	id, err := m.host.Identity.HostID(ctx)
	if err != nil || id == "" {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnresolvedIdentity,
			Severity:    diagnostics.Warn,
			Message:     "host entity ID could not be resolved; process telemetry is emitted without entity binding and process entities cannot be resolved",
			Remediation: "verify platform discovery and identity configuration",
		})
		m.host.Logger.Warn("host entity unresolved", "error", err)
		return
	}
	m.mu.Lock()
	m.entityID = id
	m.mu.Unlock()
	m.selfAttr = []platform.Attr{platform.A(AttrEntityID, id)}
	m.em.setEntity(id)
	m.res.setHostEntity(id)
}

// readBootIdentity establishes the namespace for process instance keys.
//
// Without it, instance keys fall back to a fixed namespace. That is safe within
// one run of the agent — which is all the module's in-memory state spans — and
// the degradation is recorded rather than hidden.
func (m *Module) readBootIdentity(ctx context.Context) {
	if m.set.Boot == nil {
		m.bootID = "boot-unknown"
		return
	}
	boot, err := m.set.Boot.ReadBootIdentity(ctx)
	if err != nil || boot.ID == "" {
		m.bootID = "boot-unknown"
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Info,
			Message:     "host boot identity is unavailable; process instance keys are scoped to this agent run",
			Remediation: "no action required; process identity remains correct for the life of this agent process",
		})
		return
	}
	m.bootID = boot.ID
}

// recordUnsupportedDiagnostics emits one diagnostic per absent feature.
func (m *Module) recordUnsupportedDiagnostics() {
	for _, f := range AllFeatures {
		if m.set.Has(f) {
			continue
		}
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Message:     m.set.UnsupportedReason(f),
			Remediation: "no action required; this capability is unavailable in this environment",
			Attrs:       map[string]string{AttrFeature: f.String()},
		})
		if m.inst != nil {
			m.inst.gauges[MetricUnsupported].Set(1,
				append(append([]platform.Attr{}, m.selfAttr...),
					platform.A(AttrFeature, f.String()))...)
		}
	}
}

// Stop implements module.Module. It is idempotent and tolerates a partial start,
// because the supervisor calls Stop after a failed Start.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.started = false
	m.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// The collection goroutine is parked inside a reader that ignored its
		// context. It will exit when that read returns; reporting the timeout is
		// more useful than consuming the agent's whole shutdown budget.
		return fmt.Errorf("process: collection goroutine did not exit: %w", ctx.Err())
	}
}

// run is the module's single goroutine.
func (m *Module) run(ctx context.Context) {
	defer close(m.done)

	clock := m.host.Clock
	next := clock.Now() // collect immediately: a freshly installed agent should
	// produce data at once, not after the first interval.

	for {
		now := clock.Now()
		if !now.Before(next) {
			m.collect(ctx, now)
			next = clock.Now().Add(m.effectiveInterval())
		}

		wait := next.Sub(clock.Now())
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-clock.After(wait):
		case <-m.reconfigure:
			// A committed configuration or a new pressure level changes the
			// interval and the filters, so the schedule is recomputed from
			// scratch rather than carrying a stale due time.
			//
			// If a prior Call is still inside runCycle after its deadline,
			// wait for it before touching the emitter — otherwise Throttle /
			// Configure races with emitAggregate (CI -race).
			m.awaitSettled()
			m.applyStagedToEmitter()
			next = clock.Now()
		}
	}
}

// awaitSettled blocks until any in-flight Call worker has left runCycle.
func (m *Module) awaitSettled() {
	if m.settled == nil {
		return
	}
	<-m.settled
	m.settled = nil
	m.stalled = false
}

// collect runs one cycle under a deadline and a panic guard.
func (m *Module) collect(ctx context.Context, now time.Time) {
	// Never stack a second guard.Call while a prior worker is still inside
	// runCycle: that races on the process store and was the CI -race failure.
	if m.settled != nil {
		select {
		case <-m.settled:
			m.settled = nil
			m.stalled = false
		default:
			return
		}
	}

	m.mu.RLock()
	timeout := m.settings.CollectionTimeout
	m.mu.RUnlock()

	begin := m.host.Clock.Now()
	// Publish stats on a channel so a deadline return from Call cannot race
	// with the worker still writing a shared stack variable.
	type outcome struct {
		st  cycleStats
		err error
	}
	out := make(chan outcome, 1)
	err, settled := guard.Call(ctx, timeout, func(cctx context.Context) error {
		st, e := m.runCycle(cctx, now)
		out <- outcome{st: st, err: e}
		return e
	})
	m.settled = settled

	var oc outcome
	select {
	case oc = <-out:
		<-settled
		m.settled = nil
		m.stalled = false
	default:
		// Deadline fired while the worker is still inside runCycle.
		m.stalled = true
		if err == nil {
			err = fmt.Errorf("process: collection exceeded deadline: %w", context.DeadlineExceeded)
		}
		m.reportFailure(err, settled)
		m.updateHealth(cycleStats{Duration: m.host.Clock.Now().Sub(begin)}, err)
		return
	}

	oc.st.Duration = m.host.Clock.Now().Sub(begin)

	m.recordCycle(oc.st, oc.err)
	if oc.err != nil {
		m.reportFailure(oc.err, settled)
	}
	// updateHealth LAST, because it bumps the cycle counter and that counter is
	// what everything else treats as "this cycle is fully recorded". Bumping it
	// before the diagnostics were written makes the counter lie, and an observer
	// that acts on it can see a failed cycle with no explanation attached.
	m.updateHealth(oc.st, oc.err)
}

// reportFailure classifies a cycle failure and records it.
//
// A single cycle failing is never a module failure: the supervisor is not told,
// because a process collector that restarts every time /proc hiccups is worse
// than one that reports a degraded cycle and tries again in thirty seconds.
func (m *Module) reportFailure(err error, settled <-chan struct{}) {
	var pe *guard.PanicError
	switch {
	case errors.As(err, &pe):
		m.host.Logger.Error("process reader panicked and was isolated",
			"panic", fmt.Sprint(pe.Value))
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:     diagnostics.CodePanic,
			Severity: diagnostics.Error,
			Message:  "process reader panicked and was isolated; collection will be retried on the next interval",
		})
	case errors.Is(err, context.DeadlineExceeded):
		m.stalled = true
		m.settled = settled
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeHealthTimeout,
			Severity:    diagnostics.Warn,
			Message:     "process collection exceeded its deadline and is suspended until it returns",
			Remediation: "raise collection.timeout, lower max_processes, or disable expensive per-process reads",
		})
	case errors.Is(err, ErrUnsupported):
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:     diagnostics.CodeUnsupported,
			Severity: diagnostics.Warn,
			Message:  err.Error(),
		})
	default:
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:     diagnostics.CodeStartFailed,
			Severity: diagnostics.Warn,
			Message:  "process collection cycle failed: " + err.Error(),
		})
	}
}

func (m *Module) updateHealth(st cycleStats, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := &m.health
	h.cycles++
	if err != nil {
		// On a deadline return the Call worker may still be mutating the
		// store; do not read it here.
		h.failures++
		h.lastErr = err.Error()
		return
	}
	h.totalStarted = m.store.started
	h.totalExited = m.store.exited
	h.totalReplaced = m.store.replacements
	h.totalEvicted = m.store.evictedByCapacity
	h.lastErr = ""
	h.lastSuccess = m.host.Clock.Now()
	h.discovered = int64(st.Discovered)
	h.unreadable = int64(st.Unreadable)
	h.denied = int64(st.Denied)
	h.vanished = int64(st.Vanished)
	h.droppedProc = int64(st.DroppedProcesses)
	h.droppedExec = int64(st.DroppedExecutables)
	h.stateEntries = st.StateEntries
	h.executables = st.Executables
	h.invalidNames = int64(st.InvalidNames)
	h.unresolved = m.unresolved
}

// effectiveInterval applies throttling to the configured interval.
func (m *Module) effectiveInterval() time.Duration {
	m.mu.RLock()
	base := m.settings.Interval
	factor := pressureFactor(m.pressure)
	m.mu.RUnlock()

	d := time.Duration(float64(base) * factor)
	if d > maxEffectiveInterval {
		d = maxEffectiveInterval
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// pressureFactor maps a pressure level onto an interval multiplier.
//
// The steps are wide because a ten percent reduction is not worth the complexity
// of having a governor at all; if the agent is being asked to back off, it should
// back off enough to matter. The multiplier compounds with the priority model in
// collect.go: under pressure the module both collects less often AND emits less.
func pressureFactor(p module.PressureLevel) float64 {
	switch p {
	case module.PressureModerate:
		return 2
	case module.PressureHigh:
		return 4
	case module.PressureCritical:
		return 8
	default:
		return 1
	}
}

// applyStagedToEmitter copies newly committed settings into the emitter. It runs
// on the collection goroutine, which is the only owner of the emitter.
func (m *Module) applyStagedToEmitter() {
	m.mu.RLock()
	s := m.settings.Clone()
	entity := m.entityID
	m.mu.RUnlock()
	m.em.settings = s
	m.em.setEntity(entity)
}

// Health implements module.Module. It is cheap and does no collection.
//
// The mapping onto the agent's three-state model, and the reasoning behind each
// line, because this is where most process collectors get it wrong:
//
//	enumeration works, read failures under threshold  -> Healthy
//	read failure ratio over threshold                 -> Degraded
//	optional features unavailable on this platform    -> Degraded
//	host entity unresolved                            -> Degraded
//	every cycle failing                               -> Unhealthy
//
// PROCESS CHURN IS NOT A HEALTH SIGNAL. Neither is permission denial. A build
// server forking ten thousand short-lived compilers, and an unelevated agent on
// Windows that cannot open other users' processes, are both entirely healthy
// situations — and an agent that reported them as faults would train operators
// to ignore its health signal, which is the worst outcome available.
func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()

	h := m.health
	s := m.settings

	if h.cycles == 0 {
		return health.Report{Status: health.Unknown, Message: "no process collection has completed yet"}
	}
	if h.lastSuccess.IsZero() {
		return health.UnhealthyReport("process collection has never succeeded: " + h.lastErr)
	}

	var diags []diagnostics.Record
	var degraded []string

	failing := h.unreadable
	if s.DeniedCountsAsFailure {
		failing += h.denied
	}
	if h.discovered > 0 {
		ratio := float64(failing) / float64(h.discovered+failing)
		if ratio > s.UnreadableRatioDegraded {
			degraded = append(degraded, fmt.Sprintf(
				"%.0f%% of processes could not be read", ratio*100))
			diags = append(diags, diagnostics.Record{
				Code:     diagnostics.CodePermissionDenied,
				Severity: diagnostics.Warn,
				Message:  "process reads are failing above the configured threshold",
			})
		}
	}

	if h.lastErr != "" {
		degraded = append(degraded, "the most recent collection cycle failed")
	}
	if missing := len(AllFeatures) - len(m.set.Available()); missing > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d of %d process capabilities are unavailable on this platform",
			missing, len(AllFeatures)))
	}
	if m.entityID == "" {
		degraded = append(degraded, "host entity ID is unresolved")
	}
	if h.droppedProc > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d processes exceeded max_processes and were not collected in detail", h.droppedProc))
	}
	if h.droppedExec > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d executables exceeded max_executables and were not reported", h.droppedExec))
	}

	if len(degraded) == 0 {
		return health.OK("process collection is healthy")
	}
	msg := degraded[0]
	for _, d := range degraded[1:] {
		msg += "; " + d
	}
	return health.DegradedReport(msg, diags...)
}

// Capabilities implements module.CapabilityReporter.
func (m *Module) Capabilities(context.Context) []module.Capability {
	out := make([]module.Capability, 0, len(AllFeatures))
	for _, f := range AllFeatures {
		out = append(out, module.Capability{
			Name:      "process." + f.String(),
			Available: m.set.Has(f),
			Reason:    m.set.UnsupportedReason(f),
		})
	}
	return out
}

// Statistics implements module.StatisticsReporter.
//
// The key set is fixed and small. This is a diagnostic surface, not a second
// metrics pipeline, and in particular it contains nothing keyed by PID.
func (m *Module) Statistics(context.Context) module.Statistics {
	m.mu.RLock()
	h := m.health
	m.mu.RUnlock()

	return module.Statistics{
		Counters: map[string]int64{
			"cycles":                   h.cycles,
			"cycle_failures":           h.failures,
			"processes_discovered":     h.discovered,
			"processes_unreadable":     h.unreadable,
			"processes_denied":         h.denied,
			"exited_during_collection": h.vanished,
			"dropped_max_processes":    h.droppedProc,
			"dropped_max_executables":  h.droppedExec,
			"invalid_names":            h.invalidNames,
			"entities_unresolved":      h.unresolved,
			"started_total":            h.totalStarted,
			"exited_total":             h.totalExited,
			"replaced_total":           h.totalReplaced,
			"state_evicted_total":      h.totalEvicted,
		},
		Gauges: map[string]float64{
			"state_entries": float64(h.stateEntries),
			"executables":   float64(h.executables),
		},
	}
}

// Diagnostics implements module.Diagnosable.
func (m *Module) Diagnostics(context.Context) []diagnostics.Record {
	var out []diagnostics.Record
	for _, f := range AllFeatures {
		if m.set.Has(f) {
			continue
		}
		out = append(out, diagnostics.Record{
			Code:     diagnostics.CodeUnsupported,
			Severity: diagnostics.Warn,
			Message:  m.set.UnsupportedReason(f),
			Attrs:    map[string]string{AttrFeature: f.String()},
		})
	}
	return out
}

// PrepareConfig implements module.Configurable. It validates and stages without
// touching live behaviour.
func (m *Module) PrepareConfig(_ context.Context, mc config.ModuleConfig) error {
	s, err := ParseSettings(mc)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := s.Clone()
	m.staged = &staged
	return nil
}

// CommitConfig implements module.Configurable. It cannot fail for anything
// prepare could have caught: the parse already happened.
//
// Every setting this module has is safe to change live. The interval, the
// filters and the caps are read fresh at the top of each cycle, and the state
// store is keyed by process instance rather than by anything configuration
// controls — so a reload never invalidates a counter baseline, and no setting
// requires an agent restart.
func (m *Module) CommitConfig(context.Context) error {
	m.mu.Lock()
	if m.staged == nil {
		m.mu.Unlock()
		return nil
	}
	m.settings = *m.staged
	m.staged = nil
	ch := m.reconfigure
	m.mu.Unlock()

	m.signal(ch)
	return nil
}

// RollbackConfig implements module.Configurable.
func (m *Module) RollbackConfig(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged = nil
	return nil
}

// Throttle implements module.Throttleable. It returns immediately, doing no
// collection work; the running loop picks up the new interval and priority floor
// on its next wake.
func (m *Module) Throttle(_ context.Context, level module.PressureLevel) error {
	m.mu.Lock()
	changed := m.pressure != level
	m.pressure = level
	ch := m.reconfigure
	m.mu.Unlock()

	if changed {
		m.signal(ch)
	}
	return nil
}

// Pressure returns the current throttle level. It exists for tests and for the
// diagnostics surface.
func (m *Module) Pressure() module.PressureLevel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pressure
}

func (m *Module) signal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
		// A signal is already pending; the loop will recompute once, which is
		// all that either signal needed.
	}
}

// Compile-time proof that the module satisfies the required contract and every
// optional interface it claims.
var (
	_ module.Module             = (*Module)(nil)
	_ module.Configurable       = (*Module)(nil)
	_ module.Throttleable       = (*Module)(nil)
	_ module.CapabilityReporter = (*Module)(nil)
	_ module.StatisticsReporter = (*Module)(nil)
	_ module.Diagnosable        = (*Module)(nil)
)
