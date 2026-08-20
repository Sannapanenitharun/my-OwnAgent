package supervisor

import "github.com/obsagent/observability-agent/internal/platform"

// instruments holds the agent's self-observability instruments.
//
// They are created once at construction rather than looked up per emission:
// instrument lookup on a hot path is a real cost, and pre-binding also means
// the complete set of names the agent can emit is visible in one place, which
// is what makes the cardinality policy in metrics.go auditable.
type instruments struct {
	moduleState platform.Gauge

	starts         platform.Counter
	startFailures  platform.Counter
	restarts       platform.Counter
	crashLoops     platform.Counter
	panics         platform.Counter
	healthTimeouts platform.Counter

	startLatency  platform.Histogram
	stopLatency   platform.Histogram
	healthLatency platform.Histogram
	healthStatus  platform.Gauge

	agentHealth        platform.Gauge
	goroutines         platform.Gauge
	heapBytes          platform.Gauge
	configRevision     platform.Gauge
	diagnosticsDropped platform.Gauge

	startupLatency  platform.Histogram
	shutdownLatency platform.Histogram
	configReloads   platform.Counter
	configRollbacks platform.Counter
}

func newInstruments(t platform.Telemetry) *instruments {
	return &instruments{
		moduleState:    t.Gauge(MetricModuleState),
		starts:         t.Counter(MetricModuleStarts),
		startFailures:  t.Counter(MetricModuleStartFailures),
		restarts:       t.Counter(MetricModuleRestarts),
		crashLoops:     t.Counter(MetricModuleCrashLoops),
		panics:         t.Counter(MetricModulePanics),
		healthTimeouts: t.Counter(MetricModuleHealthTimeouts),

		startLatency:  t.Histogram(MetricModuleStartLatency),
		stopLatency:   t.Histogram(MetricModuleStopLatency),
		healthLatency: t.Histogram(MetricModuleHealthLatency),
		healthStatus:  t.Gauge(MetricModuleHealthStatus),

		agentHealth:        t.Gauge(MetricAgentHealthStatus),
		goroutines:         t.Gauge(MetricAgentGoroutines),
		heapBytes:          t.Gauge(MetricAgentHeapBytes),
		configRevision:     t.Gauge(MetricAgentConfigRevision),
		diagnosticsDropped: t.Gauge(MetricAgentDiagnosticsDropped),

		startupLatency:  t.Histogram(MetricAgentStartupLatency),
		shutdownLatency: t.Histogram(MetricAgentShutdownLatency),
		configReloads:   t.Counter(MetricAgentConfigReloads),
		configRollbacks: t.Counter(MetricAgentConfigRollbacks),
	}
}
