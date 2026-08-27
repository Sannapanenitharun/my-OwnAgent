package discovery

// Metric names, event names, and the module's cardinality policy.
//
// Names are part of the operator-facing contract and must not be renamed once
// released; runbooks and dashboards key off them.
//
// THE CARDINALITY DECISION, and it is a stronger one than the process module's.
//
// Phase 3 bounded per-process metrics by rolling them up per EXECUTABLE, so the
// series count tracked the number of distinct programs — dozens — rather than
// the number of processes. Discovery goes further: IT EMITS NO PER-ENTITY METRIC
// SERIES AT ALL. Every metric below is a COUNT over a closed attribute set, so
// the module's entire series footprint is
//
//	entities by kind          12 series (one per platform.EntityKind)
//	relationships by type      6 series (one per RelationType)
//	services by state          6 series
//	self-observability       ~20 series
//	───────────────────────────────────
//	                         ~44 series, on ANY host
//
// A host with ten entities and a host with ten thousand produce the same number
// of series. That is not a cap that someone tuned; it is what falls out of
// deciding that an inventory belongs on the event path.
//
// The reasoning is that an entity is not a measurement. "This filesystem exists"
// has no value to plot over time — it is a record with a beginning and an end,
// which is exactly what an event is and exactly what a time series is not.
// Emitting one gauge per discovered entity would create a permanent series for
// every container a build host ever ran, which is the classic way a discovery
// agent becomes the incident.
//
// Deliberately NOT used as a metric attribute anywhere: entity ID, entity name,
// service name, container ID, pod name, mount point, device, address, port,
// interface name, PID, or any other per-entity value. Every one of them is
// unbounded, and several are chosen by the observed software rather than by the
// operator.
const (
	// MetricEntities is the number of tracked entities. Attrs: kind.
	MetricEntities = "discovery.entities"
	// MetricRelationships is the number of tracked relationships.
	// Attrs: relation.
	MetricRelationships = "discovery.relationships"
	// MetricServicesByState is the service inventory by run state.
	// Attrs: state.
	MetricServicesByState = "discovery.services.by_state"
)

// Self-observability. Small, and every counter answers a question an operator
// actually asks during an incident.
const (
	MetricCycleDuration = "discovery.cycle.duration_seconds"
	MetricCycleSuccess  = "discovery.cycle.success"
	MetricCycleFailure  = "discovery.cycle.failure"

	// MetricSourceDuration times one source. Attrs: domain. Bounded at ten
	// values, and it is the metric that answers "which part of discovery is
	// slow" without which the answer is a guess.
	MetricSourceDuration = "discovery.source.duration_seconds"
	// MetricSourceFailure counts source failures. Attrs: domain.
	MetricSourceFailure = "discovery.source.failure"

	// MetricEntitiesAdded, Updated and Removed are the churn of the topology
	// itself, and are what tell an operator whether an inventory is stable.
	MetricEntitiesAdded   = "discovery.entities.added"
	MetricEntitiesUpdated = "discovery.entities.updated"
	MetricEntitiesRemoved = "discovery.entities.removed"

	// MetricDropped counts entities and relationships not reported.
	// Attrs: reason.
	MetricDropped = "discovery.dropped"
	// MetricUnresolved counts entities the platform could not resolve.
	MetricUnresolved = "discovery.entities.unresolved"
	// MetricRelationConflicts counts violations of the functional-relationship
	// assumption. A non-zero value means evidence is being misread somewhere;
	// see relate.go.
	MetricRelationConflicts = "discovery.relationships.conflicts"

	// MetricProcessesSeen is how many processes were enumerated, as distinct
	// from how many became entities. The gap between the two is the whole
	// structural-promotion argument made visible.
	MetricProcessesSeen = "discovery.processes.seen"
	// MetricUnreadable counts enumeration failures. Attrs: reason.
	MetricUnreadable = "discovery.unreadable"
	// MetricResync counts full resynchronisations.
	MetricResync = "discovery.resync"
	// MetricUnsupported marks an unavailable domain. Attrs: domain.
	MetricUnsupported = "discovery.unsupported"
	// MetricTelemetryGenerated and MetricTelemetryDropped account for the
	// module's own output volume. Attrs on dropped: reason.
	MetricTelemetryGenerated = "discovery.telemetry.generated"
	MetricTelemetryDropped   = "discovery.telemetry.dropped"
)

// Event names.
//
// Events carry per-entity detail — names, addresses, mount points, PIDs —
// because an event is a bounded record with a lifetime, not a series that is
// retained and indexed forever. This is the same trade the process module makes,
// applied to twelve kinds instead of one.
const (
	// EventEntityDiscovered reports an entity observed for the first time.
	EventEntityDiscovered = "discovery.entity.discovered"
	// EventEntityChanged reports an entity whose attributes changed.
	EventEntityChanged = "discovery.entity.changed"
	// EventEntityRemoved reports an entity that is gone.
	EventEntityRemoved = "discovery.entity.removed"

	// EventRelationDiscovered reports a new relationship.
	EventRelationDiscovered = "discovery.relationship.discovered"
	// EventRelationRemoved reports a relationship that no longer holds.
	EventRelationRemoved = "discovery.relationship.removed"

	// EventSnapshot summarises a full resynchronisation, and is the record that
	// tells a consumer its inventory is complete as of a moment.
	EventSnapshot = "discovery.snapshot"
	// EventUnresolved reports that an entity could not be bound to a platform
	// identifier. It exists so that unresolved identity is VISIBLE rather than
	// being a silently missing attribute.
	EventUnresolved = "discovery.entity.unresolved"
)

// Attribute keys used on METRICS. This is the complete set, and every one has a
// closed value domain.
const (
	// AttrKind is a platform.EntityKind: 12 fixed values.
	AttrKind = "kind"
	// AttrRelation is a RelationType: 6 fixed values.
	AttrRelation = "relation"
	// AttrDomain is a Domain: 10 fixed values.
	AttrDomain = "domain"
	// AttrState is a ServiceState: 6 fixed values.
	AttrState = "state"
	// AttrReason is a drop reason: 6 fixed values.
	AttrReason = "reason"
	// AttrEntityID binds telemetry to the platform HOST entity. The value is
	// platform-assigned; the module never generates one.
	AttrEntityID = "entity.id"
)

// Attribute keys used ONLY on events. They are listed separately because that
// separation IS the cardinality policy: every key here would be unbounded, or
// attacker-influenced, or both, as a metric label.
const (
	AttrEntityKind   = "entity.kind"
	AttrTargetEntity = "entity.target.id"
	AttrChange       = "change"

	AttrFromEntity = "from.entity.id"
	AttrToEntity   = "to.entity.id"
	AttrEvidence   = "evidence"
	AttrRole       = "role"

	// Per-kind detail attributes. Each is bounded in LENGTH at the entity
	// boundary and sanitised of control characters; none is bounded in
	// CARDINALITY, which is precisely why none of them may be a metric label.
	AttrName         = "name"
	AttrDisplayName  = "display_name"
	AttrManager      = "manager"
	AttrEnabled      = "enabled"
	AttrPID          = "pid"
	AttrPPID         = "ppid"
	AttrUID          = "uid"
	AttrContainerID  = "container_id"
	AttrContainerImg = "image"
	AttrStatus       = "status"
	AttrPorts        = "ports"
	AttrCreated      = "created"
	AttrRuntimeName  = "runtime"
	AttrPodName      = "pod"
	AttrNamespace    = "namespace"
	AttrPodUID       = "pod_uid"
	AttrNodeName     = "node"
	AttrAddress      = "address"
	AttrPort         = "port"
	AttrProtocol     = "protocol"
	AttrInterface    = "interface"
	AttrMACAddress   = "mac_address"
	AttrMTU          = "mtu"
	AttrUp           = "up"
	AttrMountpoint   = "mountpoint"
	AttrDevice       = "device"
	AttrFSType       = "fstype"
	AttrReadOnly     = "read_only"
	AttrRemote       = "remote"
	AttrHostname     = "hostname"
	AttrOS           = "os"
	AttrDistribution = "distribution"
	AttrVersion      = "version"
	AttrKernel       = "kernel"
	AttrArch         = "arch"
	AttrTimeZone     = "timezone"
	AttrProvider     = "provider"
	AttrInstanceID   = "instance_id"
	AttrVendor       = "vendor"
	AttrProduct      = "product"
	AttrInContainer  = "in_container"
	AttrEntityCount  = "entity_count"
	AttrRelCount     = "relationship_count"
	AttrCycle        = "cycle"
)

// Drop reasons. A closed set, so the `reason` attribute stays bounded.
const (
	DropMaxEntities      = "max_entities"
	DropMaxPerKind       = "max_per_kind"
	DropMaxEvents        = "max_events"
	DropUnresolved       = "unresolved_entity"
	DropRelationConflict = "relation_conflict"
	DropPressure         = "resource_pressure"
)

// AllDropReasons is every drop reason, for tests that assert the attribute is
// bounded.
var AllDropReasons = []string{
	DropMaxEntities, DropMaxPerKind, DropMaxEvents,
	DropUnresolved, DropRelationConflict, DropPressure,
}

// Unreadable reasons. Also closed.
const (
	UnreadableDenied = "permission_denied"
	UnreadableError  = "read_error"
	UnreadableGone   = "vanished"
)

// AllMetrics is every metric this module can emit. It exists so that
// configuration can reject a disable-request for a metric that does not exist,
// rather than silently accepting a typo and leaving the metric enabled.
var AllMetrics = []string{
	MetricEntities, MetricRelationships, MetricServicesByState,
}

var knownMetrics = func() map[string]bool {
	m := make(map[string]bool, len(AllMetrics))
	for _, name := range AllMetrics {
		m[name] = true
	}
	return m
}()

// IsKnownMetric reports whether name is a metric this module emits.
func IsKnownMetric(name string) bool { return knownMetrics[name] }

// Priority is the telemetry priority model that governs what is shed first when
// the agent is asked to back off.
//
// As in the process module it is an ORDERING, not a percentage: whole classes of
// output are dropped, lowest first, so that what survives is coherent. The
// specific ordering here is chosen so that the LAST thing to go is the answer to
// "does this host still exist and roughly what is on it" — a count by kind is
// four hundred bytes and keeps an inventory approximately correct through an
// incident, whereas a resync under memory pressure is the module doing its most
// expensive thing at the worst possible moment.
type Priority int

const (
	// PriorityCounts is the aggregate inventory counts. They survive everything
	// short of the module being stopped.
	PriorityCounts Priority = iota
	// PriorityEntities is entity add/change/remove events.
	PriorityEntities
	// PriorityRelations is relationship events.
	PriorityRelations
	// PriorityResync is the periodic full snapshot, and the expensive optional
	// sources that feed it.
	PriorityResync
)

func (p Priority) String() string {
	switch p {
	case PriorityCounts:
		return "counts"
	case PriorityEntities:
		return "entities"
	case PriorityRelations:
		return "relations"
	case PriorityResync:
		return "resync"
	default:
		return "unknown"
	}
}
