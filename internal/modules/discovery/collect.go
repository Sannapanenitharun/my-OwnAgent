package discovery

import (
	"context"
	"strconv"
	"time"

	"github.com/obsagent/observability-agent/internal/guard"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// cycleStats is everything one discovery cycle can tell an operator about
// itself. Every field here becomes a bounded metric; none of them is per-entity.
type cycleStats struct {
	ProcessesSeen int
	Vanished      int
	Denied        int
	Unreadable    int

	Candidates int
	Entities   int
	Added      int
	Updated    int
	Removed    int
	Dropped    int

	Relationships     int
	RelationsAdded    int
	RelationsRemoved  int
	RelationConflicts int64
	RelationsDropped  int

	Resolved   int
	Unresolved int

	SourceFailures int
	Resync         bool

	TelemetryItems int64
	EventsDropped  int64

	Duration time.Duration
}

// maxPriority maps back-pressure onto what the module is still willing to emit.
//
// Whole CLASSES of output are dropped, lowest first, so that what survives is
// internally consistent. The specific ordering matters: a resync is the module's
// single most expensive act, so it is the first thing surrendered — running a
// full inventory emission at the moment the agent is being asked to use less is
// precisely backwards.
func maxPriority(p module.PressureLevel) Priority {
	switch p {
	case module.PressureModerate:
		return PriorityRelations
	case module.PressureHigh:
		return PriorityEntities
	case module.PressureCritical:
		return PriorityCounts
	default:
		return PriorityResync
	}
}

// facts is one cycle's raw gathering, before anything becomes an entity.
type facts struct {
	host       HostFacts
	hasHost    bool
	procs      []ProcessFacts
	services   []ServiceFacts
	containers []ContainerFacts
	ifaces     []InterfaceFacts
	endpoints  []EndpointFacts
	mounts     []FilesystemFacts
	runtime    RuntimeFacts
	hasRuntime bool
	cloud      CloudFacts
	hasCloud   bool
	kube       KubernetesFacts
	hasKube    bool
}

// runCycle performs one complete discovery.
//
// It runs on the module's single goroutine, inside one deadline and one panic
// guard. There is no goroutine per source, no goroutine per entity, no timer per
// entity: the whole sweep of a host is this function, called once per interval.
//
// The order of the steps is the dependency order, and it is the only order that
// works. Processes are enumerated first because their cgroup paths are the
// evidence that proves containers and pods. Entities are admitted before
// relationships are built, because an edge to an entity that did not fit the
// capacity budget is a dangling reference. Resolution happens between the two,
// because a relationship is only emitted when both of its ends are resolved.
func (m *Module) runCycle(ctx context.Context, now time.Time) (cycleStats, error) {
	var st cycleStats

	m.mu.RLock()
	s := m.settings
	pressure := m.pressure
	m.mu.RUnlock()

	allow := maxPriority(pressure)

	// 1. Gather. Each source is isolated from the others: one that fails, or
	//    panics, costs its own domain and nothing else.
	f := m.gather(ctx, s, &st)

	// 2. Derive the evidence that several later steps share, once.
	evidence := cgroupEvidenceFor(f.procs)
	st.ProcessesSeen = len(f.procs)

	// 3. Build candidates. Non-process kinds first, then processes, because
	//    structural promotion is defined in terms of the other kinds' evidence.
	b := newBuilder(s, m.entityID)
	b.addHost(f)
	b.addRuntime(f)
	b.addCloud(f)
	b.addServices(f.services)
	b.addContainers(f.containers)
	b.addPods(podsFrom(f.containers, f.kube))
	b.addInterfaces(f.ifaces)
	b.addEndpoints(f.endpoints)
	b.addFilesystems(f.mounts)
	b.addProcesses(f.procs, evidence, f.services, f.endpoints, m.bootID)
	st.Candidates = len(b.candidates)

	// 4. Reconcile against the bounded topology. Capacity is applied here, to
	//    the candidates, so an over-capacity host never even allocates the
	//    entities it is about to reject.
	changes := m.topo.reconcile(b.candidates, s.capacity())
	st.Entities = m.topo.size()
	for _, c := range changes {
		switch c.Kind {
		case changeAdded:
			st.Added++
		case changeUpdated:
			st.Updated++
		case changeRemoved:
			st.Removed++
		}
	}
	st.Dropped = int(m.topo.droppedByCap - m.lastDropped)
	m.lastDropped = m.topo.droppedByCap

	// 5. Resolve new entities through the platform. Bounded per cycle, cached
	//    for the entity's life, so a stable host resolves nothing.
	resolved, unresolved := m.topo.resolveEntities(ctx, m.res, s.MaxEventsPerCycle, b.candidates)
	st.Resolved, st.Unresolved = resolved, unresolved
	m.unresolvedTotal += int64(unresolved)

	// 6. Relate. Only entities that were actually admitted may be an endpoint of
	//    an edge, which is what keeps the topology referentially complete.
	rs := m.relate(f, evidence, b)
	st.Relationships = rs.len()
	st.RelationConflicts = rs.conflicts

	// 7. Emit. Counts first: if anything below is shed, the inventory totals
	//    have already left.
	em := m.em
	em.beginEvents()
	em.emitInventory(m.topo.countsByKind(), rs.counts(),
		serviceStateCounts(f.services), s.Wants(DomainService, m.set))

	resync := allow >= PriorityResync && m.resyncDue(now, s)
	st.Resync = resync

	if allow >= PriorityEntities && s.EventsEnabled {
		if resync {
			for _, e := range m.topo.snapshot() {
				em.emitEntitySnapshot(e, now)
			}
		} else {
			for _, c := range changes {
				em.emitEntityChange(c, now)
			}
		}
	}
	if allow >= PriorityRelations && s.EventsEnabled {
		added, removed, dropped := m.emitRelationChanges(em, rs, now, resync, s)
		st.RelationsAdded, st.RelationsRemoved, st.RelationsDropped = added, removed, dropped
	}
	m.rememberRelations(rs, s)

	if resync {
		m.lastResync = now
		em.emitSnapshotSummary(m.topo.size(), rs.len(), em.eventsDropped, now)
	}

	st.TelemetryItems = em.items
	st.EventsDropped = em.eventsDropped
	em.items = 0
	em.eventsDropped = 0
	return st, nil
}

// gather calls every enabled source, isolating each from the others.
//
// ISOLATION IS PER SOURCE, TIME BOUNDING IS PER CYCLE, and the split is
// deliberate. A panicking source must not take the other nine down, so each call
// is wrapped in guard.Safe — which recovers without spending a goroutine.
// Bounding each source's DURATION separately would need guard.Call and therefore
// a goroutine per source per cycle, for a guarantee the cycle-level deadline
// already provides. Sources receive the cycle context and are expected to honour
// it; the deadline is what stops one that does not.
func (m *Module) gather(ctx context.Context, s Settings, st *cycleStats) facts {
	var f facts

	run := func(d Domain, fn func() error) {
		if !s.Wants(d, m.set) {
			return
		}
		start := m.host.Clock.Now()
		err := guard.Safe(fn)
		m.inst.histograms[MetricSourceDuration].Observe(
			m.host.Clock.Now().Sub(start).Seconds(),
			m.attrs(platform.A(AttrDomain, d.String()))...)
		if err == nil {
			return
		}
		st.SourceFailures++
		m.inst.counters[MetricSourceFailure].Add(1,
			m.attrs(platform.A(AttrDomain, d.String()))...)
		m.noteSourceFailure(d, err)
	}

	run(DomainHost, func() error {
		v, err := m.set.Host.DiscoverHost(ctx)
		if err == nil {
			f.host, f.hasHost = v, true
		}
		return err
	})
	run(DomainProcess, func() error {
		listing, err := m.set.Process.DiscoverProcesses(ctx, ProcessOptions{
			// Cgroups are asked for only when something will consume them. On a
			// ten-thousand-process host this flag is ten thousand file reads per
			// cycle, so it is worth the conditional.
			WantCgroups: s.Wants(DomainContainer, m.set) || s.Wants(DomainService, m.set),
			WantUser:    s.ProcessMode != ProcessModeNone,
		})
		f.procs = listing.Processes
		st.Vanished += listing.Vanished
		st.Denied += listing.Denied
		st.Unreadable += listing.Unreadable
		return err
	})
	run(DomainService, func() error {
		v, err := m.set.Service.DiscoverServices(ctx)
		f.services = v
		return err
	})
	run(DomainContainer, func() error {
		v, err := m.set.Container.DiscoverContainers(ctx, f.procs)
		// Enrichment is additive and never fatal: a container observed from a
		// cgroup is a fact about this host whether or not the runtime API can
		// describe it.
		if err == nil {
			v = enrichContainers(ctx, m.docker, v)
		}
		f.containers = v
		return err
	})
	run(DomainInterface, func() error {
		v, err := m.set.Interface.DiscoverInterfaces(ctx)
		f.ifaces = v
		return err
	})
	run(DomainEndpoint, func() error {
		v, err := m.set.Endpoint.DiscoverEndpoints(ctx, EndpointOptions{
			Correlate: s.CorrelateEndpoints && s.ProcessMode != ProcessModeNone,
			MaxScans:  s.MaxFDScans,
		})
		f.endpoints = v
		return err
	})
	run(DomainFilesystem, func() error {
		v, err := m.set.Filesystem.DiscoverFilesystems(ctx)
		f.mounts = v
		return err
	})
	run(DomainRuntime, func() error {
		v, err := m.set.Runtime.DiscoverRuntime(ctx)
		if err == nil {
			f.runtime, f.hasRuntime = v, true
		}
		return err
	})
	run(DomainCloud, func() error {
		v, err := m.set.Cloud.DiscoverCloud(ctx)
		if err == nil {
			f.cloud, f.hasCloud = v, true
		}
		return err
	})
	run(DomainKubernetes, func() error {
		v, err := m.set.Kubernetes.DiscoverKubernetes(ctx)
		if err == nil {
			f.kube, f.hasKube = v, true
		}
		return err
	})
	return f
}

// relate builds the cycle's relationships from admitted entities.
func (m *Module) relate(f facts, evidence map[PID]cgroupEvidence, b *builder) *relationSet {
	rs := newRelationSet()

	// Only entities the topology actually admitted may be an edge endpoint. The
	// filters below are what turn "the capacity budget dropped this container"
	// into "and its edges went with it" rather than into a dangling reference.
	procKeys := admittedKeys(m.topo, b.procKeys)
	serviceKeys := admittedKeys(m.topo, b.serviceKeys)
	containerKeys := admittedKeys(m.topo, b.containerKeys)
	podKeys := admittedKeys(m.topo, b.podKeys)
	ifaceKeys := admittedKeys(m.topo, b.ifaceKeys)
	endpointKeys := admittedKeys(m.topo, b.endpointKeys)
	mainPIDs := admittedKeys(m.topo, b.mainPIDs)

	relateProcesses(rs, f.procs, evidence, procKeys, serviceKeys, containerKeys, mainPIDs)
	relateContainersToPods(rs, f.containers, containerKeys, podKeys)
	relateEndpoints(rs, f.endpoints, endpointKeys, procKeys,
		buildAddressOwners(f.ifaces, ifaceKeys))
	return rs
}

// admittedKeys filters a key index down to entities the topology actually holds.
//
// A free function rather than a method because Go has no generic methods, and
// the alternative — one copy per key type — is four copies of three lines that
// must stay identical.
func admittedKeys[K comparable](topo *topology, in map[K]string) map[K]string {
	out := make(map[K]string, len(in))
	for k, key := range in {
		if _, ok := topo.lookup(key); ok {
			out[k] = key
		}
	}
	return out
}

// emitRelationChanges publishes relationship transitions.
//
// Relationships are diffed against the previous cycle for the same reason
// entities are: a stable host must converge to emitting nothing. The previous
// set is retained as keys only — no attributes, no strings beyond the two entity
// keys — so the memory cost of the diff is a fraction of the topology's.
func (m *Module) emitRelationChanges(
	em *emitter, rs *relationSet, now time.Time, resync bool, s Settings,
) (added, removed, dropped int) {
	current := rs.all()
	seen := make(map[relationKey]struct{}, len(current))

	for _, r := range current {
		k := relationKey{from: r.From, typ: r.Type}
		seen[k] = struct{}{}

		prev, had := m.prevRelations[k]
		if had && prev == r.To && !resync {
			continue
		}
		fromID, okFrom := m.topo.entityID(r.From)
		toID, okTo := m.topo.entityID(r.To)
		if !okFrom || !okTo {
			// An edge between identifiers the platform does not recognise
			// cannot be stored or queried. Counting the suppression is what
			// makes an identity problem visible as a topology gap.
			dropped++
			continue
		}
		em.emitRelation(EventRelationDiscovered, r, fromID, toID, now)
		added++
	}

	if resync {
		return added, removed, dropped
	}
	for k, to := range m.prevRelations {
		if _, still := seen[k]; still {
			continue
		}
		fromID, okFrom := m.topo.entityID(k.from)
		toID, okTo := m.topo.entityID(to)
		if !okFrom || !okTo {
			// Both ends of a removed edge are commonly gone, which is WHY it was
			// removed. There is nothing to report to a consumer that can only
			// address entities by identifier, and the entity-removed events
			// already told it the edge cannot survive.
			continue
		}
		em.emitRelation(EventRelationRemoved,
			relationship{Type: k.typ, From: k.from, To: to}, fromID, toID, now)
		removed++
	}
	return added, removed, dropped
}

// rememberRelations stores the cycle's edges for the next cycle's diff, bounded.
//
// The bound is the reason this is a method rather than an assignment. Without
// it, a host that produced more edges than max_relationships would carry the
// excess forever in the diff map even though they were never emitted — a leak
// that only appears on the hosts least able to absorb it.
func (m *Module) rememberRelations(rs *relationSet, s Settings) {
	limit := s.MaxRelationships
	if limit <= 0 || len(rs.byKey) <= limit {
		next := make(map[relationKey]string, len(rs.byKey))
		for k, r := range rs.byKey {
			next[k] = r.To
		}
		m.prevRelations = next
		return
	}
	// Over the cap: keep a deterministic prefix so that the retained set is the
	// same one every cycle rather than a different slice each time.
	all := rs.all()[:limit]
	next := make(map[relationKey]string, limit)
	for _, r := range all {
		next[relationKey{from: r.From, typ: r.Type}] = r.To
	}
	m.prevRelations = next
}

// resyncDue reports whether this cycle should emit the full inventory.
//
// The FIRST cycle after start is always a resync. A consumer that just connected
// has no state at all, and waiting an hour to tell it what exists would make the
// first hour of every agent's life useless.
func (m *Module) resyncDue(now time.Time, s Settings) bool {
	if m.lastResync.IsZero() {
		return true
	}
	return now.Sub(m.lastResync) >= s.ResyncInterval
}

func serviceStateCounts(services []ServiceFacts) map[ServiceState]int {
	out := make(map[ServiceState]int, len(AllServiceStates))
	for _, st := range AllServiceStates {
		out[st] = 0
	}
	for i := range services {
		out[services[i].State]++
	}
	return out
}

// attrs returns the module's self-attributes plus extras, in a fresh slice.
//
// Fresh, because appending onto a cached slice writes into its backing array and
// corrupts the attribute set for every later caller in the same cycle. That
// defect is invisible in a single-attribute test and obvious at scale, which is
// the worst combination available.
func (m *Module) attrs(extra ...platform.Attr) []platform.Attr {
	out := make([]platform.Attr, 0, len(m.selfAttr)+len(extra))
	out = append(out, m.selfAttr...)
	out = append(out, extra...)
	return out
}

// recordCycle publishes the cycle's own statistics.
func (m *Module) recordCycle(st cycleStats, err error) {
	in := m.inst
	self := m.selfAttr
	in.histograms[MetricCycleDuration].Observe(st.Duration.Seconds(), self...)

	if err != nil {
		in.counters[MetricCycleFailure].Add(1, self...)
		return
	}
	in.counters[MetricCycleSuccess].Add(1, self...)

	in.gauges[MetricProcessesSeen].Set(float64(st.ProcessesSeen), self...)

	add := func(name string, v int64, extra ...platform.Attr) {
		if v <= 0 {
			return
		}
		in.counters[name].Add(v, m.attrs(extra...)...)
	}
	add(MetricEntitiesAdded, int64(st.Added))
	add(MetricEntitiesUpdated, int64(st.Updated))
	add(MetricEntitiesRemoved, int64(st.Removed))
	add(MetricUnresolved, int64(st.Unresolved))
	add(MetricRelationConflicts, st.RelationConflicts)
	add(MetricTelemetryGenerated, st.TelemetryItems)
	add(MetricDropped, int64(st.Dropped), platform.A(AttrReason, DropMaxEntities))
	add(MetricDropped, int64(st.RelationsDropped), platform.A(AttrReason, DropUnresolved))
	add(MetricTelemetryDropped, st.EventsDropped, platform.A(AttrReason, DropMaxEvents))
	add(MetricUnreadable, int64(st.Denied), platform.A(AttrReason, UnreadableDenied))
	add(MetricUnreadable, int64(st.Unreadable), platform.A(AttrReason, UnreadableError))
	add(MetricUnreadable, int64(st.Vanished), platform.A(AttrReason, UnreadableGone))
	if st.Resync {
		add(MetricResync, 1)
	}
}

// itoaU renders an unsigned value for an attribute.
func itoaU(v uint64) string { return strconv.FormatUint(v, 10) }
