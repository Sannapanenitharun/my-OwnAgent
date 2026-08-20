package process

import (
	"context"
	"time"

	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// cycleStats is everything one collection cycle can tell an operator about
// itself. Every field here becomes a bounded metric; none of them is per-PID.
type cycleStats struct {
	Discovered int
	Selected   int
	Filtered   int

	DroppedProcesses   int
	DroppedExecutables int
	DroppedByState     int64
	InvalidNames       int

	Vanished   int
	Denied     int
	Unreadable int

	Started  int64
	Exited   int64
	Replaced int64

	Executables    int
	StateEntries   int
	TelemetryItems int64
	EventsDropped  int64

	Duration time.Duration
}

// maxPriority maps back-pressure onto what the module is still willing to emit.
//
// The mapping drops whole CLASSES of output rather than a uniform fraction of
// everything, so what survives is always internally consistent. An agent that
// shed 40% of its observations would produce rollups whose instance counts did
// not match their memory sums — telemetry that is not merely reduced but wrong.
func maxPriority(p module.PressureLevel) Priority {
	switch p {
	case module.PressureModerate:
		// First to go: the expensive per-process detail reads.
		return PriorityRollup
	case module.PressureHigh:
		// Then the per-executable series.
		return PriorityLifecycle
	case module.PressureCritical:
		// Finally everything except the host-level counts, which are what tell
		// an operator the module is alive and what the machine is doing.
		return PriorityAggregate
	default:
		return PriorityDetail
	}
}

// runCycle performs one complete collection.
//
// It runs on the module's single collection goroutine, inside one deadline and
// one panic guard. There is no goroutine per process, no timer per process and
// no watcher per process: the entire sweep of a fifty-thousand-process host is
// this function, called once per interval.
//
// The order of the steps is the cost model. Cheap enumeration, then cheap
// filters, then a bounded selection, and only then the expensive per-process
// reads — so the work done on a process that will be discarded is the minimum
// needed to discard it.
func (m *Module) runCycle(ctx context.Context, now time.Time) (cycleStats, error) {
	var st cycleStats

	m.mu.RLock()
	s := m.settings
	pressure := m.pressure
	m.mu.RUnlock()

	allow := maxPriority(pressure)

	// 1. Enumerate. The PID pre-filter is the one filter that runs before any
	//    per-process work, which is why it is worth having even though it can
	//    only see the PID.
	opts := ListOptions{WantUser: s.Wants(FeatureUser, m.set)}
	if len(s.IncludePIDs) > 0 || len(s.ExcludePIDs) > 0 {
		opts.Accept = s.acceptPID
	}
	listing, err := m.set.Lister.ListProcesses(ctx, opts)
	if err != nil {
		return st, err
	}
	st.Vanished = listing.Vanished
	st.Denied = listing.Denied
	st.Unreadable = listing.Unreadable
	st.Discovered = len(listing.Processes)

	// 2. Reconcile against tracked state. This is where PID reuse is detected
	//    and where CPU deltas are computed, so it must see every process — a
	//    process filtered out of detailed collection still needs its baseline
	//    maintained, or re-including it later would produce one bogus sample.
	obs, changes, invalid := m.store.reconcile(
		listing.Processes, m.bootID, now, m.numCPU, s.MaxTracked, s.ExitRetention)
	st.InvalidNames = invalid
	st.DroppedByState = m.store.evictedByCapacity

	// 3. Aggregates, computed over EVERYTHING discovered. Filters shape
	//    detailed collection; they must not change the host's process count,
	//    which is a fact about the machine rather than about the operator's
	//    interests.
	byState := make(map[State]int, len(AllStates))
	for _, o := range obs {
		byState[o.State]++
	}

	// 4. Cheap filters.
	kept := make([]*observation, 0, len(obs))
	for _, o := range obs {
		if s.admit(o) {
			kept = append(kept, o)
		}
	}
	st.Filtered = len(obs) - len(kept)

	// 5. Bounded, deterministic selection.
	selected, droppedProcesses := s.selectProcesses(kept)
	st.Selected = len(selected)
	st.DroppedProcesses = droppedProcesses

	// 6. Expensive per-process reads, for the selected set only, and only when
	//    back-pressure permits.
	if allow >= PriorityDetail {
		m.readDetail(ctx, selected, s, &st)
	}

	// 7. Entity resolution, per instance and cached, for the selected set.
	m.resolveEntities(ctx, selected, s)

	// 8. Emit. Aggregates first: if anything below fails or is shed, the
	//    host-level counts have already left.
	em := m.em
	em.beginEvents()
	em.emitAggregate(len(obs), byState, m.set.Has(FeatureState))

	if allow >= PriorityLifecycle && s.EventsEnabled {
		m.emitLifecycle(em, changes, selected, now, &st)
	}
	if allow >= PriorityRollup {
		rollups := rollupBy(selected)
		rollups, droppedExec := selectExecutables(rollups, s.MaxExecutables)
		st.DroppedExecutables = droppedExec
		st.Executables = len(rollups)
		em.emitRollups(rollups)
	}
	if allow >= PriorityDetail && s.TopN > 0 {
		em.emitTop(selected, s.TopN, now)
	}

	st.Started = m.store.started - m.lastStarted
	st.Exited = m.store.exited - m.lastExited
	st.Replaced = m.store.replacements - m.lastReplaced
	m.lastStarted, m.lastExited, m.lastReplaced =
		m.store.started, m.store.exited, m.store.replacements

	em.emitChurnSummary(st.Started, st.Exited, st.Replaced, em.eventsDropped, now)

	st.StateEntries = m.store.entries()
	st.TelemetryItems = em.items
	st.EventsDropped = em.eventsDropped
	em.items = 0
	em.eventsDropped = 0
	return st, nil
}

// readDetail performs the expensive per-process reads.
//
// Each read is attempted for at most the selected set, and the loop checks the
// context between processes so that a slow reader cannot overrun the cycle
// deadline by an unbounded amount. Individual failures are counted and skipped:
// a process that exits here, or one the agent may not open, must not abort the
// other nine hundred and ninety-nine.
func (m *Module) readDetail(ctx context.Context, selected []*observation, s Settings, st *cycleStats) {
	wantIO := s.Wants(FeatureIO, m.set)
	wantFiles := s.Wants(FeatureOpenFiles, m.set)
	wantPath := s.Wants(FeatureExecutablePath, m.set)
	wantCmd := s.Wants(FeatureCommandLine, m.set)
	if !wantIO && !wantFiles && !wantPath && !wantCmd {
		return
	}

	for _, o := range selected {
		if ctx.Err() != nil {
			return
		}
		if wantIO {
			if io, err := m.set.IO.ReadIO(ctx, o.PID); err == nil {
				m.store.applyIO(o, io)
			} else {
				st.Denied++
			}
		}
		if wantFiles {
			if n, err := m.set.Files.ReadOpenFiles(ctx, o.PID); err == nil {
				o.OpenFiles = n
			}
		}
		if wantPath {
			if p, err := m.set.Path.ReadExecutablePath(ctx, o.PID); err == nil {
				o.ExecutablePath = p
			}
		}
		if wantCmd {
			if args, err := m.set.Command.ReadCommandLine(ctx, o.PID); err == nil {
				o.CommandLine = args
			}
		}
	}
}

// resolveEntities binds selected processes to platform entities.
//
// Resolution is per INSTANCE and cached on the tracked state, so a process that
// has been running for a week is resolved once and every later cycle is a map
// lookup. In steady state on a stable host this loop performs zero calls, which
// is what makes per-process entity resolution affordable at all.
func (m *Module) resolveEntities(ctx context.Context, selected []*observation, s Settings) {
	if !m.res.canResolve() {
		return
	}
	budget := s.MaxEventsPerCycle
	for _, o := range selected {
		if o.state == nil {
			continue // untracked: no stable instance to resolve
		}
		if o.state.entityTried {
			o.EntityID = o.state.entityID
			continue
		}
		if budget <= 0 || ctx.Err() != nil {
			return
		}
		budget--
		o.state.entityTried = true
		if id, ok := m.res.resolve(ctx, o.Key, o.Name); ok {
			o.state.entityID = id
			o.EntityID = id
		} else {
			m.unresolved++
		}
	}
}

// emitLifecycle publishes lifecycle events for tracked processes.
//
// Events are emitted only for processes in the SELECTED set, plus every exit of
// a process that was previously selected. That is what keeps event volume
// proportional to max_processes rather than to churn: a host forking ten
// thousand short-lived helpers per cycle produces at most a bounded number of
// events plus one churn summary carrying the true totals.
func (m *Module) emitLifecycle(em *emitter, changes []lifecycleChange, selected []*observation, now time.Time, st *cycleStats) {
	interesting := make(map[PID]struct{}, len(selected))
	for _, o := range selected {
		interesting[o.PID] = struct{}{}
	}

	for _, c := range changes {
		// An exit is always interesting: the process is gone, so it cannot be in
		// the selected set, and suppressing it would mean a process that was
		// reported as started is never reported as finished.
		if c.Kind != EventExited {
			if _, ok := interesting[c.PID]; !ok {
				continue
			}
		}
		if c.EntityID == "" {
			if t, ok := m.store.live[c.PID]; ok {
				c.EntityID = t.entityID
			}
		}
		em.emitLifecycle(c, now)
	}
}

// numCPUFor normalises CPU utilisation against the whole host.
//
// Reported utilisation is a fraction of TOTAL host capacity, so 0.5 means half
// the machine regardless of how many cores it has. The alternative — a fraction
// of one core, where 4.0 is legal — reads naturally to anyone who has used top
// and is a trap for every alert threshold written against it.
func numCPUFor(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// recordCycle publishes the cycle's own statistics.
func (m *Module) recordCycle(st cycleStats, err error) {
	in := m.inst
	self := m.selfAttr
	in.histograms[MetricCollectionDuration].Observe(st.Duration.Seconds(), self...)

	if err != nil {
		in.counters[MetricCollectionFailure].Add(1, self...)
		return
	}
	in.counters[MetricCollectionSuccess].Add(1, self...)

	gauge := func(name string, v float64) {
		in.gauges[name].Set(v, self...)
	}
	gauge(MetricDiscovered, float64(st.Discovered))
	gauge(MetricSelected, float64(st.Selected))
	gauge(MetricFiltered, float64(st.Filtered))
	gauge(MetricStateEntries, float64(st.StateEntries))
	gauge(MetricExecutables, float64(st.Executables))

	add := func(name string, v int64, attrs ...platform.Attr) {
		if v <= 0 {
			return
		}
		// A fresh slice per call: append onto the cached one would write into
		// its backing array and corrupt the attribute set for every later
		// caller in this cycle.
		all := make([]platform.Attr, 0, len(self)+len(attrs))
		all = append(all, self...)
		all = append(all, attrs...)
		in.counters[name].Add(v, all...)
	}
	add(MetricChurn, int64(st.Vanished))
	add(MetricStarted, st.Started)
	add(MetricExited, st.Exited)
	add(MetricReplaced, st.Replaced)
	add(MetricTelemetryGenerated, st.TelemetryItems)
	add(MetricDropped, int64(st.DroppedProcesses), platform.A(AttrReason, DropMaxProcesses))
	add(MetricDropped, int64(st.DroppedExecutables), platform.A(AttrReason, DropMaxExecutables))
	add(MetricDropped, int64(st.InvalidNames), platform.A(AttrReason, DropInvalidName))
	add(MetricTelemetryDropped, st.EventsDropped, platform.A(AttrReason, DropMaxEvents))
	add(MetricUnreadable, int64(st.Denied), platform.A(AttrReason, UnreadableDenied))
	add(MetricUnreadable, int64(st.Unreadable), platform.A(AttrReason, UnreadableError))
}

var _ = context.Canceled
