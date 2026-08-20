package discovery

import (
	"strconv"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// instruments pre-binds every instrument the module can emit.
//
// Pre-binding removes a map lookup from a path that runs once per kind per
// cycle, and it makes the complete set of names this module can produce visible
// in one place — which is what makes the cardinality policy in metrics.go
// auditable rather than aspirational.
type instruments struct {
	gauges     map[string]platform.Gauge
	counters   map[string]platform.Counter
	histograms map[string]platform.Histogram
	telemetry  platform.Telemetry
}

func newInstruments(t platform.Telemetry) *instruments {
	in := &instruments{
		gauges:     make(map[string]platform.Gauge),
		counters:   make(map[string]platform.Counter),
		histograms: make(map[string]platform.Histogram),
		telemetry:  t,
	}
	gauge := []string{
		MetricEntities, MetricRelationships, MetricServicesByState,
		MetricProcessesSeen, MetricUnsupported,
	}
	counter := []string{
		MetricCycleSuccess, MetricCycleFailure, MetricSourceFailure,
		MetricEntitiesAdded, MetricEntitiesUpdated, MetricEntitiesRemoved,
		MetricDropped, MetricUnresolved, MetricRelationConflicts,
		MetricUnreadable, MetricResync,
		MetricTelemetryGenerated, MetricTelemetryDropped,
	}
	for _, n := range gauge {
		in.gauges[n] = t.Gauge(n)
	}
	for _, n := range counter {
		in.counters[n] = t.Counter(n)
	}
	in.histograms[MetricCycleDuration] = t.Histogram(MetricCycleDuration)
	in.histograms[MetricSourceDuration] = t.Histogram(MetricSourceDuration)
	return in
}

// emitter turns discovery results into telemetry.
//
// It is used only from the single discovery goroutine and is not safe for
// concurrent use; the scratch attribute buffer depends on that.
type emitter struct {
	inst     *instruments
	settings Settings

	// entity is the platform-assigned HOST entity. Metrics are host-scoped, and
	// nothing below ever attaches a DISCOVERED entity's identifier to a metric
	// series — that would recreate exactly the per-entity cardinality the event
	// path exists to avoid.
	entity    platform.Attr
	hasEntity bool

	buf []platform.Attr

	items         int64
	eventsCycle   int
	eventsDropped int64
}

func newEmitter(inst *instruments, s Settings) *emitter {
	return &emitter{inst: inst, settings: s, buf: make([]platform.Attr, 0, 4)}
}

func (e *emitter) setEntity(hostID string) {
	if hostID == "" {
		e.entity = platform.Attr{}
		e.hasEntity = false
		return
	}
	e.entity = platform.A(AttrEntityID, hostID)
	e.hasEntity = true
}

func (e *emitter) with(extra ...platform.Attr) []platform.Attr {
	e.buf = e.buf[:0]
	if e.hasEntity {
		e.buf = append(e.buf, e.entity)
	}
	e.buf = append(e.buf, extra...)
	return e.buf
}

func (e *emitter) enabled(metric string) bool { return !e.settings.DisabledMetrics[metric] }

func (e *emitter) gauge(metric string, v float64, attrs ...platform.Attr) {
	if !e.enabled(metric) {
		return
	}
	g, ok := e.inst.gauges[metric]
	if !ok {
		return
	}
	g.Set(v, e.with(attrs...)...)
	e.items++
}

// emitInventory publishes the aggregate counts.
//
// This is priority zero: the last thing shed and the first thing an operator
// looks at. It is also the module's ENTIRE metric surface for discovered things
// — twelve entity series, six relationship series, six service-state series —
// and that total does not move whether the host has ten entities or ten
// thousand.
//
// Zero counts ARE emitted, unlike unknown values elsewhere in the agent, and the
// difference is real: "there are no containers on this host" is a measurement,
// whereas an absent value is an unknown. A gauge that vanishes at zero is a
// gauge nobody can alert on, and "the container count went to zero" is exactly
// the alert somebody wants.
func (e *emitter) emitInventory(
	byKind map[platform.EntityKind]int,
	byRelation map[RelationType]int,
	byState map[ServiceState]int,
	serviceDomainAvailable bool,
) {
	for _, k := range platform.AllEntityKinds {
		e.gauge(MetricEntities, float64(byKind[k]), platform.A(AttrKind, string(k)))
	}
	for _, t := range AllRelationTypes {
		e.gauge(MetricRelationships, float64(byRelation[t]), platform.A(AttrRelation, t.String()))
	}
	if !serviceDomainAvailable {
		return
	}
	for _, st := range AllServiceStates {
		e.gauge(MetricServicesByState, float64(byState[st]), platform.A(AttrState, st.String()))
	}
}

// beginEvents resets the per-cycle event budget.
func (e *emitter) beginEvents() { e.eventsCycle = 0 }

// emitEvent publishes one event if the cycle's budget allows.
//
// The budget is what stops a topology storm becoming an event storm. A node
// draining five thousand containers, or a resync on a large host, is a real
// thing that happens, and an agent that faithfully emitted every record would do
// more damage than the change it was reporting. What is dropped is counted, and
// the snapshot event reports the totals the individual events could not.
func (e *emitter) emitEvent(ev platform.Event) bool {
	if !e.settings.EventsEnabled {
		return false
	}
	if e.settings.MaxEventsPerCycle > 0 && e.eventsCycle >= e.settings.MaxEventsPerCycle {
		e.eventsDropped++
		return false
	}
	e.eventsCycle++
	e.inst.telemetry.Emit(ev)
	e.items++
	return true
}

// emitEntityChange publishes one entity transition.
//
// This is where per-entity detail lives: names, addresses, mount points, PIDs.
// None of it is a metric attribute, and that separation is the module's central
// cardinality decision — an event is a bounded record with a lifetime, a series
// is forever.
//
// An entity with no resolved identifier is still emitted, carrying its kind and
// its attributes but no entity ID. That is the honest degradation: the operator
// learns that a filesystem was mounted even when the platform could not tell the
// agent what to call it.
func (e *emitter) emitEntityChange(c change, now time.Time) bool {
	name := EventEntityDiscovered
	severity := platform.SeverityInfo
	switch c.Kind {
	case changeUpdated:
		name = EventEntityChanged
	case changeRemoved:
		name = EventEntityRemoved
	}

	attrs := make([]platform.Attr, 0, len(c.Entity.attrs)+4)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	attrs = append(attrs,
		platform.A(AttrEntityKind, string(c.Entity.kind)),
		platform.A(AttrChange, c.Kind.String()),
	)
	if c.Entity.entityID != "" {
		attrs = append(attrs, platform.A(AttrTargetEntity, c.Entity.entityID))
	}
	attrs = append(attrs, c.Entity.attrs...)

	return e.emitEvent(platform.Event{
		Name:      name,
		Severity:  severity,
		Timestamp: now,
		Attrs:     attrs,
	})
}

// emitEntitySnapshot publishes one entity as part of a full resync.
//
// It reuses the discovered event name rather than inventing a third one, because
// a consumer rebuilding state from the stream should handle "here is an entity"
// identically whether it arrived incrementally or in a resync. What distinguishes
// them is the snapshot event that brackets the resync.
func (e *emitter) emitEntitySnapshot(ent *entity, now time.Time) bool {
	return e.emitEntityChange(change{Kind: changeAdded, Entity: ent}, now)
}

// emitRelation publishes one relationship transition.
//
// Both ends must be RESOLVED. An edge between two identifiers the platform does
// not recognise cannot be stored in the entity graph and cannot be queried, so
// emitting it would be sending bytes that no consumer can act on. The
// suppression is counted, which is what makes an unresolved-identity problem
// visible as a topology gap rather than as silence.
func (e *emitter) emitRelation(name string, r relationship, fromID, toID string, now time.Time) bool {
	attrs := relationAttrs(r, fromID, toID)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	return e.emitEvent(platform.Event{
		Name:      name,
		Severity:  platform.SeverityInfo,
		Timestamp: now,
		Attrs:     attrs,
	})
}

// emitSnapshotSummary reports that a full resynchronisation happened.
//
// It is emitted whenever a resync runs and it BYPASSES the per-cycle event
// budget, deliberately: it is one event, and it is the one that tells a consumer
// its inventory is complete as of this moment. Suppressing it under budget
// pressure would remove the only record that makes the incremental stream
// trustworthy — the exact inverse of what the budget is for.
func (e *emitter) emitSnapshotSummary(entities, relationships int, suppressed int64, now time.Time) {
	if !e.settings.EventsEnabled {
		return
	}
	attrs := make([]platform.Attr, 0, 5)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	attrs = append(attrs,
		platform.A(AttrEntityCount, strconv.Itoa(entities)),
		platform.A(AttrRelCount, strconv.Itoa(relationships)),
		platform.A("events_suppressed", strconv.FormatInt(suppressed, 10)),
	)
	e.inst.telemetry.Emit(platform.Event{
		Name:      EventSnapshot,
		Severity:  platform.SeverityInfo,
		Timestamp: now,
		Attrs:     attrs,
	})
	e.items++
}

// emitUnresolved reports that an entity could not be bound to a platform
// identifier.
//
// It exists so that unresolved identity is a VISIBLE condition rather than a
// silently missing attribute. It is rate-limited by the same event budget as
// everything else, because a platform outage would otherwise make every entity
// on every host produce one of these.
func (e *emitter) emitUnresolved(kind platform.EntityKind, count int, now time.Time) {
	if count <= 0 {
		return
	}
	attrs := make([]platform.Attr, 0, 3)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	attrs = append(attrs,
		platform.A(AttrEntityKind, string(kind)),
		platform.A("count", strconv.Itoa(count)),
	)
	e.emitEvent(platform.Event{
		Name:      EventUnresolved,
		Severity:  platform.SeverityWarn,
		Timestamp: now,
		Attrs:     attrs,
	})
}
