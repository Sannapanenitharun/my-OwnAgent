package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/guard"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// ID is the discovery module's identifier.
const ID module.ID = "discovery"

// Version is the discovery module's implementation version.
const Version = "1.0.0"

// PermissionRead is the platform permission the module requires.
//
// Reading /proc, mountinfo, the SCM's read-only enumeration and DMI strings
// needs no OS privilege, so this is an authorization statement to the platform
// rather than a request for elevation. The module never asks the operating
// system for more than it has.
const PermissionRead platform.Permission = "discovery:read"

// maxEffectiveInterval caps what throttling may stretch the interval to. Beyond
// this the inventory is stale enough to be misleading, and the governor should
// stop the module rather than let it pretend.
const maxEffectiveInterval = 6 * time.Hour

// Module discovers the host's entities and their relationships.
//
// It owns exactly ONE goroutine. Every source on the host is read from that
// goroutine, in one deadline-bounded sweep per interval. There is no goroutine
// per source, no goroutine per entity, no timer per entity — the module's
// resource cost is independent of how many things exist on the host, which is
// the property that makes it safe on a node running ten thousand containers.
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

	// docker enriches container entities when the operator has opted in. nil
	// when DockerSocket is unset, which is the default.
	docker *dockerClient

	// Owned by the discovery goroutine after Start.
	em            *emitter
	topo          *topology
	res           *resolver
	bootID        string
	selfAttr      []platform.Attr
	prevRelations map[relationKey]string
	lastResync    time.Time
	// resyncCursor is where an unfinished inventory snapshot stopped.
	//
	// A resync emits every entity, and the per-cycle event budget can be
	// smaller than the inventory. Truncating there was silently permanent:
	// snapshot() is sorted by key, so the SAME entities were cut every time
	// and could never reach a receiver -- while relationship deltas naming
	// them still went out, leaving edges pointing at nodes nobody had heard
	// of. Empty means no snapshot is in progress.
	resyncCursor string
	lastDropped  int64

	unresolvedTotal int64

	cancel      context.CancelFunc
	done        chan struct{}
	reconfigure chan struct{}

	// stalled marks a cycle whose deadline passed while a source had not
	// returned. No further cycle is started until it settles, so a wedged source
	// costs one parked goroutine once rather than one per interval.
	stalled bool
	settled <-chan struct{}
}

// healthState is the module's own view of itself, updated by the discovery
// goroutine and read by the supervisor's health probe.
type healthState struct {
	cycles      int64
	failures    int64
	lastErr     string
	lastSuccess time.Time

	entities      int
	relationships int
	added         int64
	updated       int64
	removed       int64
	dropped       int
	unresolved    int
	resolved      int

	sourceFailures    int
	relationConflicts int64
	processesSeen     int

	// Snapshots of the topology's lifetime counters. The topology belongs to
	// the discovery goroutine; Statistics is called by the supervisor on its own
	// goroutine, so the values are copied here under the mutex rather than read
	// across the boundary. The process module shipped that exact race and it was
	// found by inspection, not by a test — the pattern is repeated here
	// deliberately.
	totalAdded      int64
	totalUpdated    int64
	totalRemoved    int64
	totalDropped    int64
	unresolvedTotal int64
}

// New returns a discovery module using the platform's sources.
func New() *Module { return NewWithSet(NewSet()) }

// NewWithSet returns a discovery module using an explicit source set. Tests use
// it to inject failing, panicking and unsupported sources; production uses New.
func NewWithSet(set Set) *Module {
	return &Module{
		set:           set,
		settings:      DefaultSettings(),
		topo:          newTopology(),
		prevRelations: make(map[relationKey]string),
	}
}

// Manifest implements module.Module.
func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryDiscovery,
		Description: "host entity and relationship discovery: services, containers, endpoints, filesystems, runtime and cloud context",
		Permissions: []platform.Permission{PermissionRead},
		// Normal, not Low. An inventory is what every other signal is
		// interpreted against — telemetry from an entity nobody can name is
		// telemetry nobody can act on — so discovery is not the first thing an
		// agent under pressure should abandon. It is not Critical either: the
		// module's own priority model already sheds its expensive work long
		// before the governor would need to stop it.
		Priority: module.PriorityNormal,
	}
}

// Start implements module.Module. It returns promptly; discovery runs on the
// single goroutine it launches.
func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}

	// Without at least one source there is nothing to discover. Reporting
	// unsupported (rather than failing) puts the module in the supervisor's
	// terminal unsupported state: degraded health, a diagnostic, and no restart
	// attempts against a condition that cannot change.
	if len(m.set.Available()) == 0 {
		return module.Unsupported(
			"no discovery sources are available on this platform")
	}

	if err := h.Authorize(ctx, PermissionRead); err != nil {
		return fmt.Errorf("discovery: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("discovery: already started")
	}
	m.settings = settings
	m.docker = newDockerFrom(settings)
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

// resolveHostEntity binds discovery to the platform host entity.
//
// EVERY ENTITY THIS MODULE DISCOVERS HANGS OFF THE HOST, so an unresolved host
// is a harder degradation here than in a collector: without it nothing can be
// resolved, and the module reports a complete local topology that it cannot
// name. It still runs, still counts, and still reports health — because "the
// agent found 43 services and could not name them" is a diagnosable state, while
// silence is not.
//
// What it does NOT do is invent an identifier. A locally generated host ID would
// fork the platform's entity graph, and with twelve kinds hanging off it, it
// would fork it twelve ways.
func (m *Module) resolveHostEntity(ctx context.Context) {
	id, err := m.host.Identity.HostID(ctx)
	if err != nil || id == "" {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnresolvedIdentity,
			Severity:    diagnostics.Warn,
			Message:     "host entity ID could not be resolved; discovered entities cannot be bound to platform identities and no relationships will be emitted",
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
// It matters here for one specific reason: the process natural key includes the
// boot identifier, and this module and the process module must produce the SAME
// key for the same process or the platform mints two entities for it. The boot
// identifier therefore comes from the host source, which reads it the same way
// the process module's reader does.
func (m *Module) readBootIdentity(ctx context.Context) {
	m.bootID = "boot-unknown"
	if m.set.Host == nil {
		return
	}
	facts, err := m.set.Host.DiscoverHost(ctx)
	if err != nil || facts.BootID == "" {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Info,
			Message:     "host boot identity is unavailable; process entity keys are scoped to this agent run and may not match those from the process module",
			Remediation: "no action required on platforms that expose no boot identifier",
		})
		return
	}
	m.bootID = facts.BootID
}

// recordUnsupportedDiagnostics emits one diagnostic per absent domain.
func (m *Module) recordUnsupportedDiagnostics() {
	for _, d := range AllDomains {
		if m.set.Has(d) {
			continue
		}
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Message:     m.set.UnsupportedReason(d),
			Remediation: "no action required; this capability is unavailable in this environment",
			Attrs:       map[string]string{AttrDomain: d.String()},
		})
		if m.inst != nil {
			m.inst.gauges[MetricUnsupported].Set(1,
				m.attrs(platform.A(AttrDomain, d.String()))...)
		}
	}
}

// noteSourceFailure records a single source's failure.
//
// A source failing is NOT a module failure and never a restart: a host where
// systemd is absent, or where /proc/net is restricted by a hardening profile,
// should lose that domain and keep the other nine. The diagnostic names the
// domain so an operator can tell which.
func (m *Module) noteSourceFailure(d Domain, err error) {
	var pe *guard.PanicError
	if errors.As(err, &pe) {
		m.host.Logger.Error("discovery source panicked and was isolated",
			"domain", d.String(), "panic", fmt.Sprint(pe.Value))
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:     diagnostics.CodePanic,
			Severity: diagnostics.Error,
			Message:  "discovery source panicked and was isolated; the remaining domains were unaffected",
			Attrs:    map[string]string{AttrDomain: d.String()},
		})
		return
	}
	m.host.Logger.Debug("discovery source failed", "domain", d.String(), "error", err)
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
		// The discovery goroutine is parked inside a source that ignored its
		// context. It will exit when that call returns; reporting the timeout is
		// more useful than consuming the agent's whole shutdown budget.
		return fmt.Errorf("discovery: goroutine did not exit: %w", ctx.Err())
	}
}

// run is the module's single goroutine.
func (m *Module) run(ctx context.Context) {
	defer close(m.done)

	clock := m.host.Clock
	next := clock.Now() // discover immediately: a freshly installed agent should
	// produce an inventory at once, not after the first interval.

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
			m.applyStagedToEmitter()
			next = clock.Now()
		}
	}
}

// collect runs one cycle under a deadline and a panic guard.
func (m *Module) collect(ctx context.Context, now time.Time) {
	if m.stalled {
		select {
		case <-m.settled:
			m.stalled = false
		default:
			// The previous cycle is still parked inside a source. Skipping is
			// what keeps a wedged source from consuming a goroutine per interval
			// forever.
			return
		}
	}

	m.mu.RLock()
	timeout := m.settings.CollectionTimeout
	m.mu.RUnlock()

	begin := m.host.Clock.Now()
	var st cycleStats
	err, settled := guard.Call(ctx, timeout, func(cctx context.Context) error {
		var e error
		st, e = m.runCycle(cctx, now)
		return e
	})
	st.Duration = m.host.Clock.Now().Sub(begin)

	m.recordCycle(st, err)
	if err != nil {
		m.reportFailure(err, settled)
	}
	// updateHealth LAST, because it bumps the cycle counter and that counter is
	// what everything else treats as "this cycle is fully recorded". Bumping it
	// before the diagnostics were written makes the counter lie, and an observer
	// that acts on it can see a failed cycle with no explanation attached. The
	// process module shipped this defect and a flaky test found it; the ordering
	// is repeated here on purpose.
	m.updateHealth(st, err)
}

// reportFailure classifies a cycle failure and records it.
//
// A single cycle failing is never a module failure: the supervisor is not told,
// because a discovery module that restarts every time one source hiccups is
// worse than one that reports a degraded cycle and tries again.
func (m *Module) reportFailure(err error, settled <-chan struct{}) {
	var pe *guard.PanicError
	switch {
	case errors.As(err, &pe):
		m.host.Logger.Error("discovery cycle panicked and was isolated",
			"panic", fmt.Sprint(pe.Value))
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:     diagnostics.CodePanic,
			Severity: diagnostics.Error,
			Message:  "discovery cycle panicked and was isolated; discovery will be retried on the next interval",
		})
	case errors.Is(err, context.DeadlineExceeded):
		m.stalled = true
		m.settled = settled
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeHealthTimeout,
			Severity:    diagnostics.Warn,
			Message:     "discovery exceeded its deadline and is suspended until it returns",
			Remediation: "raise collection.timeout, disable an expensive domain, or set endpoints.correlate=false",
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
			Message:  "discovery cycle failed: " + err.Error(),
		})
	}
}

func (m *Module) updateHealth(st cycleStats, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := &m.health
	h.cycles++
	h.totalAdded = m.topo.added
	h.totalUpdated = m.topo.updated
	h.totalRemoved = m.topo.removed
	h.totalDropped = m.topo.droppedByCap
	h.unresolvedTotal = m.unresolvedTotal
	if err != nil {
		h.failures++
		h.lastErr = err.Error()
		return
	}
	h.lastErr = ""
	h.lastSuccess = m.host.Clock.Now()
	h.entities = st.Entities
	h.relationships = st.Relationships
	h.added = int64(st.Added)
	h.updated = int64(st.Updated)
	h.removed = int64(st.Removed)
	h.dropped = st.Dropped
	h.unresolved = st.Unresolved
	h.resolved = st.Resolved
	h.sourceFailures = st.SourceFailures
	h.relationConflicts = st.RelationConflicts
	h.processesSeen = st.ProcessesSeen
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
// of having a governor at all. The multiplier compounds with the priority model
// in collect.go: under pressure the module both discovers less often AND emits
// less, and the first thing it stops doing is the full resync.
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
// on the discovery goroutine, which is the only owner of the emitter.
func (m *Module) applyStagedToEmitter() {
	m.mu.RLock()
	s := m.settings.Clone()
	entity := m.entityID
	m.mu.RUnlock()
	m.em.settings = s
	m.em.setEntity(entity)
}

// Health implements module.Module. It is cheap and does no discovery.
//
// The mapping onto the agent's three-state model, and the reasoning behind each
// line, because this is where discovery modules most often mislead:
//
//	sources working, entities resolving              -> Healthy
//	some domains unavailable on this platform        -> Degraded
//	host entity unresolved                           -> Degraded
//	entities over the cap                            -> Degraded
//	unresolved ratio over threshold                  -> Degraded
//	relationship conflicts                           -> Degraded
//	every cycle failing                              -> Unhealthy
//
// AN EMPTY TOPOLOGY IS NOT UNHEALTHY. A minimal container image genuinely has no
// systemd, no containers of its own, and one filesystem — and an agent that
// reported that as a fault would train operators to ignore its health signal,
// which is the worst outcome available.
//
// Neither is churn. A Kubernetes node replacing hundreds of pods an hour is
// working exactly as intended.
func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()

	h := m.health
	s := m.settings

	if h.cycles == 0 {
		return health.Report{Status: health.Unknown, Message: "no discovery cycle has completed yet"}
	}
	if h.lastSuccess.IsZero() {
		return health.UnhealthyReport("discovery has never succeeded: " + h.lastErr)
	}

	var diags []diagnostics.Record
	var degraded []string

	if h.lastErr != "" {
		degraded = append(degraded, "the most recent discovery cycle failed")
	}
	if missing := len(AllDomains) - len(m.set.Available()); missing > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d of %d discovery domains are unavailable on this platform",
			missing, len(AllDomains)))
	}
	if m.entityID == "" {
		degraded = append(degraded, "host entity ID is unresolved; no discovered entity can be bound to a platform identity")
		diags = append(diags, diagnostics.Record{
			Code:     diagnostics.CodeUnresolvedIdentity,
			Severity: diagnostics.Warn,
			Message:  "discovery is running without a resolved host entity",
		})
	}
	if h.sourceFailures > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d discovery sources failed in the last cycle", h.sourceFailures))
	}
	if h.dropped > 0 {
		degraded = append(degraded, fmt.Sprintf(
			"%d entities exceeded the configured caps and were not reported", h.dropped))
	}
	if total := h.resolved + h.unresolved; total > 0 {
		if ratio := float64(h.unresolved) / float64(total); ratio > s.UnresolvedRatioDegraded {
			degraded = append(degraded, fmt.Sprintf(
				"%.0f%% of new entities could not be resolved to platform identities", ratio*100))
		}
	}
	if h.relationConflicts > 0 {
		// A conflict means evidence claimed two targets for a relationship that
		// can only have one. That is a correctness signal about the module
		// itself, not about the host, and it is surfaced rather than counted
		// quietly.
		degraded = append(degraded, fmt.Sprintf(
			"%d relationship conflicts: evidence disagreed about a functional relationship", h.relationConflicts))
	}

	if len(degraded) == 0 {
		return health.OK("discovery is healthy")
	}
	msg := degraded[0]
	for _, d := range degraded[1:] {
		msg += "; " + d
	}
	return health.DegradedReport(msg, diags...)
}

// Capabilities implements module.CapabilityReporter.
func (m *Module) Capabilities(context.Context) []module.Capability {
	out := make([]module.Capability, 0, len(AllDomains))
	for _, d := range AllDomains {
		out = append(out, module.Capability{
			Name:      "discovery." + d.String(),
			Available: m.set.Has(d),
			Reason:    m.set.UnsupportedReason(d),
		})
	}
	return out
}

// Statistics implements module.StatisticsReporter.
//
// The key set is fixed and small. This is a diagnostic surface, not a second
// metrics pipeline, and in particular it contains nothing keyed by entity.
func (m *Module) Statistics(context.Context) module.Statistics {
	m.mu.RLock()
	h := m.health
	m.mu.RUnlock()

	return module.Statistics{
		Counters: map[string]int64{
			"cycles":                 h.cycles,
			"cycle_failures":         h.failures,
			"entities_added_total":   h.totalAdded,
			"entities_updated_total": h.totalUpdated,
			"entities_removed_total": h.totalRemoved,
			"entities_dropped_total": h.totalDropped,
			"entities_unresolved":    h.unresolvedTotal,
			"relationship_conflicts": h.relationConflicts,
			"source_failures":        int64(h.sourceFailures),
		},
		Gauges: map[string]float64{
			"entities":       float64(h.entities),
			"relationships":  float64(h.relationships),
			"processes_seen": float64(h.processesSeen),
		},
	}
}

// Diagnostics implements module.Diagnosable.
func (m *Module) Diagnostics(context.Context) []diagnostics.Record {
	var out []diagnostics.Record
	for _, d := range AllDomains {
		if m.set.Has(d) {
			continue
		}
		out = append(out, diagnostics.Record{
			Code:     diagnostics.CodeUnsupported,
			Severity: diagnostics.Warn,
			Message:  m.set.UnsupportedReason(d),
			Attrs:    map[string]string{AttrDomain: d.String()},
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
// Every setting is safe to change live. The intervals, filters and caps are read
// fresh at the top of each cycle, and the topology is keyed by natural key
// rather than by anything configuration controls — so a reload never invalidates
// an entity's identity, and no setting requires an agent restart. Narrowing a
// cap simply drops entities on the next cycle, which the change stream reports
// as removals, which is exactly what happened.
func (m *Module) CommitConfig(context.Context) error {
	m.mu.Lock()
	if m.staged == nil {
		m.mu.Unlock()
		return nil
	}
	m.settings = *m.staged
	m.docker = newDockerFrom(m.settings)
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
// discovery work; the running loop picks up the new interval and priority floor
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
