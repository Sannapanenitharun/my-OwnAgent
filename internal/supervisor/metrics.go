package supervisor

// Instrument names for the agent's self-observability.
//
// The agent monitors itself through the same Telemetry Plane port every module
// uses; it does not build a parallel monitoring system for itself. Names are
// part of the operator-facing contract and must not be renamed once released.
//
// Cardinality policy for this package: the only attribute ever attached is
// `module`, whose value set is the fixed list of registered module IDs. No PID,
// request ID, path, command line, timestamp or error string is ever used as an
// attribute, because each of those is unbounded and would make the agent the
// source of the cardinality incident it exists to detect.
const (
	// MetricModuleState is the current lifecycle state, as the numeric
	// module.State, per module.
	MetricModuleState = "agent.module.state"
	// MetricModuleStarts counts start attempts per module.
	MetricModuleStarts = "agent.module.starts"
	// MetricModuleStartFailures counts failed starts per module.
	MetricModuleStartFailures = "agent.module.start_failures"
	// MetricModuleRestarts counts automatic restarts per module.
	MetricModuleRestarts = "agent.module.restarts"
	// MetricModuleCrashLoops counts crash-loop quarantines per module.
	MetricModuleCrashLoops = "agent.module.crash_loops"
	// MetricModulePanics counts recovered panics in module code, per module.
	MetricModulePanics = "agent.module.panics"
	// MetricModuleStartLatency records Start duration in seconds, per module.
	MetricModuleStartLatency = "agent.module.start_latency_seconds"
	// MetricModuleStopLatency records Stop duration in seconds, per module.
	MetricModuleStopLatency = "agent.module.stop_latency_seconds"
	// MetricModuleHealthLatency records Health probe duration in seconds.
	MetricModuleHealthLatency = "agent.module.health_latency_seconds"
	// MetricModuleHealthTimeouts counts health probes that exceeded their
	// deadline, per module.
	MetricModuleHealthTimeouts = "agent.module.health_timeouts"
	// MetricModuleHealthStatus is the module's health status as the numeric
	// health.Status, per module.
	MetricModuleHealthStatus = "agent.module.health_status"

	// MetricAgentHealthStatus is the aggregate agent health status.
	MetricAgentHealthStatus = "agent.health_status"
	// MetricAgentGoroutines is the process goroutine count.
	MetricAgentGoroutines = "agent.goroutines"
	// MetricAgentHeapBytes is the process live heap size in bytes.
	MetricAgentHeapBytes = "agent.memory.heap_bytes"
	// MetricAgentStartupLatency records agent startup duration in seconds.
	MetricAgentStartupLatency = "agent.startup_latency_seconds"
	// MetricAgentShutdownLatency records agent shutdown duration in seconds.
	MetricAgentShutdownLatency = "agent.shutdown_latency_seconds"
	// MetricAgentConfigRevision is the currently applied configuration
	// revision.
	MetricAgentConfigRevision = "agent.config.revision"
	// MetricAgentConfigReloads counts successful configuration applies.
	MetricAgentConfigReloads = "agent.config.reloads"
	// MetricAgentConfigRollbacks counts configuration applies that were
	// rolled back.
	MetricAgentConfigRollbacks = "agent.config.rollbacks"
	// MetricAgentDiagnosticsDropped counts diagnostics shed to the retention
	// bound.
	MetricAgentDiagnosticsDropped = "agent.diagnostics.dropped"
)

// Event names emitted through the Telemetry Plane port.
const (
	EventModuleStateChanged = "agent.module.state_changed"
	EventModuleUnsupported  = "agent.module.unsupported"
	EventModuleCrashLoop    = "agent.module.crash_loop"
	EventConfigApplied      = "agent.config.applied"
	EventConfigRolledBack   = "agent.config.rolled_back"
	EventAgentStarted       = "agent.started"
	EventAgentStopped       = "agent.stopped"
)

// AttrModule is the only attribute key this package attaches to telemetry.
const AttrModule = "module"
