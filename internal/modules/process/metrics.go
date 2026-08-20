package process

// Metric names and the module's cardinality policy.
//
// Names are part of the operator-facing contract and must not be renamed once
// released; runbooks and dashboards key off them.
//
// THE CARDINALITY DECISION. A host with ten thousand processes must not create
// ten thousand series, and the way this module achieves that is structural
// rather than by capping a number: per-process metrics are ROLLED UP BY
// EXECUTABLE NAME. Five hundred nginx workers contribute to one set of series,
// not five hundred. The series count is therefore proportional to the number of
// distinct programs on the host — dozens, in practice — and is flat in the
// quantity that actually grows.
//
// The consequence is that PID IS NEVER A METRIC ATTRIBUTE. Per-instance detail
// exists, and it is genuinely useful, but it belongs on the event path where it
// is a bounded record rather than a permanent time series. That is the trade
// this module makes deliberately, and the runbook says how to get instance-level
// answers when they are needed.
//
// Every attribute below has a stated bound:
//
//	executable  distinct process names, capped at max_executables (default 128)
//	state       7 fixed values
//	feature     10 fixed values, one per capability
//	reason      6 fixed values, one per drop cause
//
// Deliberately NOT used as attributes anywhere: PID, PPID, command line,
// arguments, environment variables, executable paths, user names, file
// descriptors, network endpoints, timestamps or error strings. Each is unbounded
// or attacker-controlled, and an agent that emits either becomes the incident it
// was installed to detect.
const (
	// Aggregate host-level metrics. These are low-cardinality by construction
	// and are the LAST thing shed under pressure: a host that stops reporting
	// per-executable detail is degraded, but a host that stops reporting how
	// many processes exist is blind.
	MetricCount        = "process.count"          // no attrs
	MetricCountByState = "process.count.by_state" // attrs: state

	// Per-executable rollups.
	MetricCPUUtilization = "process.cpu.utilization" // attrs: executable
	MetricMemoryRSS      = "process.memory.rss"      // attrs: executable
	MetricMemoryVirtual  = "process.memory.virtual"  // attrs: executable
	MetricThreadCount    = "process.thread.count"    // attrs: executable
	MetricOpenFiles      = "process.open_files"      // attrs: executable
	MetricIOReadBytes    = "process.io.read_bytes"   // attrs: executable
	MetricIOWriteBytes   = "process.io.write_bytes"  // attrs: executable

	// MetricInstances is what makes every rollup above interpretable. Without
	// it, "nginx is using 4 GB" cannot be told apart from "one nginx worker is
	// using 4 GB" — and those call for opposite responses.
	MetricInstances = "process.instances" // attrs: executable

	// MetricStartTime is the start of the OLDEST live instance of an
	// executable, as a Unix timestamp. A step change means the service was
	// restarted, which is the question start times are asked to answer.
	MetricStartTime = "process.start_time_seconds" // attrs: executable
)

// Self-observability. Deliberately small, and every counter here answers a
// question an operator actually asks during an incident.
const (
	MetricCollectionDuration = "process.collection.duration_seconds"
	MetricCollectionSuccess  = "process.collection.success"
	MetricCollectionFailure  = "process.collection.failure"

	MetricDiscovered = "process.discovered" // gauge: seen this cycle
	MetricSelected   = "process.selected"   // gauge: kept for detailed collection
	MetricFiltered   = "process.filtered"   // gauge: excluded by configuration
	MetricDropped    = "process.dropped"    // counter, attrs: reason

	// MetricUnreadable and MetricChurn are separated on purpose. A process that
	// vanished mid-collection is churn and is normal; a process that could not
	// be read is a fault. Counting them together is how a busy, healthy host
	// gets reported as broken.
	MetricUnreadable = "process.unreadable" // counter, attrs: reason
	MetricChurn      = "process.exited_during_collection"

	MetricStarted  = "process.started_total"
	MetricExited   = "process.exited_total"
	MetricReplaced = "process.replaced_total"

	MetricTelemetryGenerated = "process.telemetry.generated"
	MetricTelemetryDropped   = "process.telemetry.dropped" // attrs: reason
	MetricStateEntries       = "process.state_entries"
	MetricExecutables        = "process.executables"
	MetricUnsupported        = "process.unsupported" // gauge, attrs: feature
	MetricModuleHealth       = "process.module.health"
)

// Lifecycle event names. Events carry per-instance detail — including the PID —
// because an event is a bounded record with a lifetime, not a series that is
// retained and indexed forever.
const (
	EventStarted   = "process.started"
	EventExited    = "process.exited"
	EventReplaced  = "process.replaced"
	EventChurn     = "process.churn"
	EventUnhandled = "process.unresolved"
	EventError     = "process.collection_error"
	EventTop       = "process.top"
)

// Attribute keys. This is the complete set the module may emit on METRICS.
const (
	AttrExecutable = "executable"
	AttrState      = "state"
	AttrFeature    = "feature"
	AttrReason     = "reason"

	// Entity binding. The value is the platform-assigned entity ID; the module
	// never generates one.
	AttrEntityID = "entity.id"
)

// Additional attribute keys used ONLY on events. They are listed separately
// because that separation is the cardinality policy: anything here would be
// unbounded as a metric label.
const (
	AttrPID             = "pid"
	AttrPPID            = "ppid"
	AttrProcessEntityID = "process.entity.id"
	AttrStartTime       = "start_time"
	AttrLifetime        = "lifetime_seconds"
	AttrExecutablePath  = "executable_path"
	AttrCommandLine     = "command_line"
	AttrUID             = "uid"
	AttrCount           = "count"
	AttrCPU             = "cpu_utilization"
	AttrRSS             = "rss_bytes"
)

// Drop reasons. A closed set, so the `reason` attribute stays bounded.
const (
	DropMaxProcesses   = "max_processes"
	DropMaxExecutables = "max_executables"
	DropMaxEvents      = "max_events"
	DropStateCapacity  = "state_capacity"
	DropInvalidName    = "invalid_name"
	DropPressure       = "resource_pressure"
)

// AllDropReasons is every drop reason, for tests that assert the attribute is
// bounded.
var AllDropReasons = []string{
	DropMaxProcesses, DropMaxExecutables, DropMaxEvents,
	DropStateCapacity, DropInvalidName, DropPressure,
}

// Unreadable reasons. Also closed.
const (
	UnreadableDenied  = "permission_denied"
	UnreadableError   = "read_error"
	UnreadableNoStart = "no_start_time"
)

// AllMetrics is every process metric this module can emit. It exists so that
// configuration can reject a disable-request for a metric that does not exist,
// rather than silently accepting a typo and leaving the metric enabled.
var AllMetrics = []string{
	MetricCount, MetricCountByState,
	MetricCPUUtilization, MetricMemoryRSS, MetricMemoryVirtual,
	MetricThreadCount, MetricOpenFiles,
	MetricIOReadBytes, MetricIOWriteBytes,
	MetricInstances, MetricStartTime,
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
// It is an ordering, not a percentage: under pressure the module drops whole
// classes of output, lowest first, so that what survives is always coherent. An
// agent that shed a uniform fraction of everything would produce telemetry that
// is wrong in ways nobody can reason about.
type Priority int

const (
	// PriorityAggregate is the host-level process counts. These survive
	// everything short of the module being stopped.
	PriorityAggregate Priority = iota
	// PriorityLifecycle is start/exit/replace events for tracked processes.
	PriorityLifecycle
	// PriorityRollup is the per-executable metric rollups.
	PriorityRollup
	// PriorityDetail is optional expensive detail: I/O counters, open file
	// counts, executable paths, command lines and top-N observations.
	PriorityDetail
)

func (p Priority) String() string {
	switch p {
	case PriorityAggregate:
		return "aggregate"
	case PriorityLifecycle:
		return "lifecycle"
	case PriorityRollup:
		return "rollup"
	case PriorityDetail:
		return "detail"
	default:
		return "unknown"
	}
}
