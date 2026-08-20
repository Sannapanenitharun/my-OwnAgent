package host

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

// ID is the host module's identifier.
const ID module.ID = "host"

// Version is the host module's implementation version.
const Version = "1.0.0"

// PermissionRead is the platform permission the module requires. Reading
// /proc, sysfs, statfs and the Win32 query APIs needs no OS privilege, so this
// is an authorization statement to the platform, not a request for elevation.
const PermissionRead platform.Permission = "host:read"

// maxEffectiveInterval caps what throttling may stretch an interval to. Beyond
// this the module is no longer observing the host in any useful sense, and the
// governor should stop it rather than pretend it is collecting.
const maxEffectiveInterval = 30 * time.Minute

// Module collects host telemetry.
//
// It owns exactly ONE goroutine. Every source is read from that goroutine, in
// sequence, with a per-read deadline. There is no goroutine per metric, per
// filesystem, per interface or per CPU, and there are no per-source timers: a
// single computed sleep to the next due source replaces them.
type Module struct {
	set Set

	mu       sync.RWMutex
	settings Settings
	staged   *Settings
	pressure module.PressureLevel
	status   map[Source]*sourceStatus
	entityID string
	started  bool

	host module.Host
	inst *instruments
	// em is owned by the collection goroutine after Start.
	em *emitter

	cancel      context.CancelFunc
	done        chan struct{}
	reconfigure chan struct{}
	// slots track a source whose read overran its deadline and has not yet
	// returned. A stalled source is not read again until it does.
	slots map[Source]*slot
}

type slot struct {
	stalled bool
	settled <-chan struct{}
}

type sourceStatus struct {
	available   bool
	reason      string
	successes   int64
	failures    int64
	lastSuccess time.Time
	lastErr     string
	droppedCard int64
}

// New returns a host module using the platform's readers.
func New() *Module { return NewWithSet(NewSet()) }

// NewWithSet returns a host module using an explicit reader set. Tests use it
// to inject failing, panicking and unsupported readers; production uses New.
func NewWithSet(set Set) *Module {
	m := &Module{
		set:      set,
		settings: DefaultSettings(),
		status:   make(map[Source]*sourceStatus, len(AllSources)),
		slots:    make(map[Source]*slot, len(AllSources)),
	}
	for _, src := range AllSources {
		m.status[src] = &sourceStatus{
			available: set.Has(src),
			reason:    set.UnsupportedReason(src),
		}
		m.slots[src] = &slot{}
	}
	return m
}

// Manifest implements module.Module.
func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryCollector,
		Description: "host CPU, memory, disk, filesystem, network, OS and load telemetry",
		Permissions: []platform.Permission{PermissionRead},
		// Host telemetry is the baseline every other signal is interpreted
		// against, so it is shed last under resource pressure.
		Priority: module.PriorityHigh,
	}
}

// Start implements module.Module. It returns promptly; collection runs on the
// single goroutine it launches.
func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}

	// Every source unsupported means this platform cannot be observed at all.
	// Reporting unsupported (rather than failing) puts the module in the
	// supervisor's terminal unsupported state: degraded health, a diagnostic,
	// and no restart attempts against a condition that cannot change.
	if len(m.set.Available()) == 0 {
		reasons := make([]string, 0, len(m.set.Unsupported))
		for _, u := range m.set.Unsupported {
			reasons = append(reasons, u.Source.String()+": "+u.Reason)
		}
		return module.Unsupported(fmt.Sprintf(
			"no host collection sources are available on this platform (%v)", reasons))
	}

	if err := h.Authorize(ctx, PermissionRead); err != nil {
		return fmt.Errorf("host: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("host: already started")
	}
	m.settings = settings
	m.host = h
	m.inst = newInstruments(h.Telemetry)
	m.em = newEmitter(m.inst, settings)
	m.started = true
	m.reconfigure = make(chan struct{}, 1)
	m.done = make(chan struct{})
	m.mu.Unlock()

	m.resolveEntity(ctx)
	m.recordUnsupportedDiagnostics()

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()

	go m.run(runCtx)
	return nil
}

// resolveEntity binds observations to the platform host entity.
//
// If the platform cannot resolve a host entity, the module records an
// unresolved diagnostic, reports degraded health, and emits observations with
// NO entity attribute. It does not invent an identifier: a locally generated
// entity ID silently forks the platform's entity graph, and reconciling that
// afterwards is far more expensive than a missing attribute.
func (m *Module) resolveEntity(ctx context.Context) {
	id, err := m.host.Identity.HostID(ctx)
	if err != nil {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnresolvedIdentity,
			Severity:    diagnostics.Warn,
			Message:     "host entity ID could not be resolved; observations are emitted without entity binding",
			Remediation: "verify platform discovery and identity configuration",
		})
		m.host.Logger.Warn("host entity unresolved", "error", err)
		return
	}
	m.mu.Lock()
	m.entityID = id
	m.mu.Unlock()
	// The emitter carries the binding; setting only the module field would
	// leave every observation unbound while health reported the entity as
	// resolved. This runs before the collection goroutine starts, so it is the
	// one place the emitter is touched from another goroutine.
	m.em.setEntity(id)
}

// recordUnsupportedDiagnostics emits one diagnostic per absent source.
func (m *Module) recordUnsupportedDiagnostics() {
	for _, u := range m.set.Unsupported {
		if m.set.Has(u.Source) {
			continue
		}
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Message:     u.Reason,
			Remediation: "no action required; this source is unavailable in this environment",
			Attrs:       map[string]string{AttrSource: u.Source.String()},
		})
	}
}

// Stop implements module.Module. It is idempotent and tolerates a partial
// start, because the supervisor calls Stop after a failed Start.
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
		// context. It will exit when that read returns; reporting the timeout
		// is more useful than blocking the agent's shutdown budget.
		return fmt.Errorf("host: collection goroutine did not exit: %w", ctx.Err())
	}
}

// run is the module's single goroutine.
//
// It computes the next due source and sleeps until then. A ticker per source
// would mean seven timers whose cost and drift scale with the module count
// across the whole agent; one computed sleep does not.
func (m *Module) run(ctx context.Context) {
	defer close(m.done)

	clock := m.host.Clock
	due := make(map[Source]time.Time, len(AllSources))
	now := clock.Now()
	for _, src := range m.collectableSources() {
		// Everything is due immediately at startup: an operator who just
		// installed the agent should see data at once, not after five minutes
		// of staggering.
		due[src] = now
	}

	for {
		now = clock.Now()
		for _, src := range m.collectableSources() {
			at, ok := due[src]
			if !ok {
				due[src] = now
				at = now
			}
			if at.After(now) {
				continue
			}
			m.collect(ctx, src, now)
			due[src] = now.Add(m.effectiveInterval(src))
		}

		wait := m.timeUntilNext(due, clock.Now())
		select {
		case <-ctx.Done():
			return
		case <-clock.After(wait):
		case <-m.reconfigure:
			// A committed configuration changes intervals and filters, so the
			// schedule is recomputed from scratch rather than carrying stale
			// due times for sources whose interval just changed.
			m.applyStagedToEmitter()
			for src := range due {
				due[src] = clock.Now()
			}
		}
	}
}

// collectableSources returns sources that have a reader and are not disabled.
func (m *Module) collectableSources() []Source {
	m.mu.RLock()
	disabled := m.settings.DisabledSources
	m.mu.RUnlock()

	out := make([]Source, 0, len(AllSources))
	for _, src := range AllSources {
		if m.set.Has(src) && !disabled[src] {
			out = append(out, src)
		}
	}
	return out
}

// timeUntilNext returns how long to sleep before the next source is due.
func (m *Module) timeUntilNext(due map[Source]time.Time, now time.Time) time.Duration {
	next := time.Duration(-1)
	for _, src := range m.collectableSources() {
		at, ok := due[src]
		if !ok {
			return 0
		}
		d := at.Sub(now)
		if d < 0 {
			d = 0
		}
		if next < 0 || d < next {
			next = d
		}
	}
	if next < 0 {
		// Nothing to collect. Wake occasionally anyway so that a configuration
		// reload which re-enables a source is picked up even if the reload
		// signal is missed.
		return time.Minute
	}
	return next
}

// effectiveInterval applies throttling to the configured interval.
func (m *Module) effectiveInterval(src Source) time.Duration {
	m.mu.RLock()
	base := m.settings.Interval(src)
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
// The steps are wide because a 10% reduction is not worth the complexity of
// having a governor at all; if the agent is being asked to back off, it should
// back off enough to matter.
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

// collect reads and emits one source. It runs on the collection goroutine.
func (m *Module) collect(ctx context.Context, src Source, now time.Time) {
	sl := m.slots[src]
	if sl.stalled {
		select {
		case <-sl.settled:
			// The overrunning read finally returned; the source may be tried
			// again.
			sl.stalled = false
		default:
			// Still parked inside the reader. Skipping is what keeps a wedged
			// mount from consuming a goroutine per cycle forever.
			return
		}
	}

	m.mu.RLock()
	timeout := m.settings.CollectionTimeout
	perCore := m.settings.CPUPerCore
	maxCPUs := m.settings.MaxCPUs
	m.mu.RUnlock()

	begin := m.host.Clock.Now()
	var dropped int
	var err error
	var settled <-chan struct{}

	switch src {
	case SourceCPU:
		var v CPUStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.CPU.ReadCPU(cctx, perCore)
			return e
		})
		if err == nil {
			if len(v.PerCore) > maxCPUs {
				dropped = len(v.PerCore) - maxCPUs
				v.PerCore = v.PerCore[:maxCPUs]
			}
			m.em.emitCPU(v)
		}

	case SourceMemory:
		var v MemoryStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.Memory.ReadMemory(cctx)
			return e
		})
		if err == nil {
			m.em.emitMemory(v)
		}

	case SourceDisk:
		var v []DiskStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.Disk.ReadDisks(cctx)
			return e
		})
		if err == nil {
			dropped = m.em.emitDisk(v)
		}

	case SourceFilesystem:
		var v []FilesystemStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.Filesystem.ReadFilesystems(cctx)
			return e
		})
		if err == nil {
			dropped = m.em.emitFilesystems(v)
		}

	case SourceNetwork:
		var v []InterfaceStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.Network.ReadInterfaces(cctx)
			return e
		})
		if err == nil {
			dropped = m.em.emitNetwork(v)
		}

	case SourceOS:
		var v OSInfo
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.OS.ReadOS(cctx)
			return e
		})
		if err == nil {
			m.em.emitOS(v, now)
			// Identity may have been unresolvable at start and resolvable now;
			// the metadata refresh is the natural place to retry.
			m.retryEntity(ctx)
		}

	case SourceLoad:
		var v LoadStats
		err, settled = guard.Call(ctx, timeout, func(cctx context.Context) error {
			var e error
			v, e = m.set.Load.ReadLoad(cctx)
			return e
		})
		if err == nil {
			m.em.emitLoad(v)
		}
	}

	m.finish(src, err, settled, dropped, begin)
}

// finish records the outcome of one source collection.
func (m *Module) finish(src Source, err error, settled <-chan struct{}, dropped int, begin time.Time) {
	end := m.host.Clock.Now()
	srcAttr := platform.A(AttrSource, src.String())
	m.inst.histograms[MetricCollectionDuration].Observe(end.Sub(begin).Seconds(), srcAttr)

	m.mu.Lock()
	st := m.status[src]
	if err == nil {
		st.successes++
		st.lastSuccess = end
		st.lastErr = ""
	} else {
		st.failures++
		st.lastErr = err.Error()
	}
	if dropped > 0 {
		st.droppedCard += int64(dropped)
	}
	m.mu.Unlock()

	if err == nil {
		m.inst.counters[MetricCollectionSuccess].Add(1, srcAttr)
		m.inst.gauges[MetricCollectionLastSuccess].Set(float64(end.Unix()), srcAttr)
	} else {
		m.inst.counters[MetricCollectionFailure].Add(1, srcAttr)

		var pe *guard.PanicError
		if errors.As(err, &pe) {
			// A panicking reader is contained here. It fails one source; the
			// other six are unaffected, and the agent is unaffected.
			m.host.Logger.Error("host reader panicked and was isolated",
				"source", src.String(), "panic", fmt.Sprint(pe.Value))
			m.host.Diagnostics.Record(diagnostics.Record{
				Code:     diagnostics.CodePanic,
				Severity: diagnostics.Error,
				Message:  "host reader panicked and was isolated; this source is unavailable until it recovers",
				Attrs:    map[string]string{AttrSource: src.String()},
			})
		} else if errors.Is(err, context.DeadlineExceeded) {
			m.markStalled(src, settled)
			m.host.Diagnostics.Record(diagnostics.Record{
				Code:        diagnostics.CodeHealthTimeout,
				Severity:    diagnostics.Warn,
				Message:     "host source read exceeded its deadline and is suspended until it returns",
				Remediation: "check for unresponsive mounts or devices; other sources are unaffected",
				Attrs:       map[string]string{AttrSource: src.String()},
			})
		}
	}

	if dropped > 0 {
		m.inst.counters[MetricTelemetryDropped].Add(int64(dropped),
			srcAttr, platform.A(AttrReason, dropReasonCardinality))
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Message:     "series limit reached; the excess was dropped rather than emitted",
			Remediation: "raise the source's max setting, or add an exclusion so the selection is intentional",
			Attrs: map[string]string{
				AttrSource: src.String(),
				"dropped":  fmt.Sprint(dropped),
			},
		})
	}

	if items := m.em.items; items > 0 {
		m.inst.counters[MetricTelemetryItems].Add(items, srcAttr)
		m.em.items = 0
	}
}

// markStalled suspends a source until its overrunning read returns.
func (m *Module) markStalled(src Source, settled <-chan struct{}) {
	if settled == nil {
		return
	}
	sl := m.slots[src]
	sl.stalled = true
	sl.settled = settled
}

func (m *Module) retryEntity(ctx context.Context) {
	m.mu.RLock()
	have := m.entityID != ""
	m.mu.RUnlock()
	if have {
		return
	}
	if id, err := m.host.Identity.HostID(ctx); err == nil && id != "" {
		m.mu.Lock()
		m.entityID = id
		m.mu.Unlock()
		m.em.setEntity(id)
		m.host.Logger.Info("host entity resolved", "entity_id", id)
	}
}

// applyStagedToEmitter copies newly committed settings into the emitter. It
// runs on the collection goroutine, which is the only owner of the emitter.
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
// The mapping onto the agent's three-state model:
//
//	every source available and succeeding  -> Healthy
//	some sources unavailable or failing    -> Degraded
//	no source is producing data            -> Unhealthy ("unavailable")
//
// A partly-working host module is explicitly NOT a failure. On Windows two of
// seven sources are unavailable by design; treating that as failure would mean
// every Windows host in a fleet reports a broken agent.
func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var available, succeeding, failing int
	var diags []diagnostics.Record
	for _, src := range AllSources {
		st := m.status[src]
		if !st.available {
			continue
		}
		available++
		switch {
		case st.failures > 0 && st.lastErr != "":
			failing++
			diags = append(diags, diagnostics.Record{
				Code:     diagnostics.CodeStartFailed,
				Severity: diagnostics.Warn,
				Message:  "host source is failing: " + st.lastErr,
				Attrs:    map[string]string{AttrSource: src.String()},
			})
		case !st.lastSuccess.IsZero():
			succeeding++
		}
	}

	switch {
	case available == 0:
		return health.UnhealthyReport("no host collection sources are available")
	case succeeding == 0 && failing > 0:
		return health.UnhealthyReport("every available host source is failing", diags...)
	case failing > 0:
		return health.DegradedReport(
			fmt.Sprintf("%d of %d host sources are failing", failing, available), diags...)
	case available < len(AllSources):
		return health.DegradedReport(fmt.Sprintf(
			"%d of %d host sources are unavailable on this platform",
			len(AllSources)-available, len(AllSources)))
	case m.entityID == "":
		return health.DegradedReport("host entity ID is unresolved; observations are emitted without entity binding")
	default:
		return health.OK("all host sources are collecting")
	}
}

// Capabilities implements module.CapabilityReporter.
func (m *Module) Capabilities(context.Context) []module.Capability {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]module.Capability, 0, len(AllSources))
	for _, src := range AllSources {
		st := m.status[src]
		out = append(out, module.Capability{
			Name:      "host." + src.String(),
			Available: st.available,
			Reason:    st.reason,
		})
	}
	return out
}

// Statistics implements module.StatisticsReporter.
func (m *Module) Statistics(context.Context) module.Statistics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := module.Statistics{
		Counters: make(map[string]int64, len(AllSources)*3),
		Gauges:   make(map[string]float64, len(AllSources)),
	}
	for _, src := range AllSources {
		st := m.status[src]
		name := src.String()
		stats.Counters[name+".successes"] = st.successes
		stats.Counters[name+".failures"] = st.failures
		stats.Counters[name+".dropped_series"] = st.droppedCard
		if !st.lastSuccess.IsZero() {
			stats.Gauges[name+".last_success_unix"] = float64(st.lastSuccess.Unix())
		}
	}
	return stats
}

// Diagnostics implements module.Diagnosable.
func (m *Module) Diagnostics(context.Context) []diagnostics.Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []diagnostics.Record
	for _, src := range AllSources {
		st := m.status[src]
		if st.available {
			continue
		}
		out = append(out, diagnostics.Record{
			Code:     diagnostics.CodeUnsupported,
			Severity: diagnostics.Warn,
			Message:  st.reason,
			Attrs:    map[string]string{AttrSource: src.String()},
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
// collection work; the running loop picks up the new intervals on its next
// wake.
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
