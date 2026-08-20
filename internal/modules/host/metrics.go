package host

// Metric names and the module's cardinality policy.
//
// Names are part of the operator-facing contract and must not be renamed once
// released; runbooks and dashboards key off them.
//
// CARDINALITY POLICY. Each metric below lists every attribute it may carry, and
// nothing else is ever attached. The bound on each attribute's value set is
// stated, because "bounded" is a claim that has to be checked against how the
// value is produced, not asserted:
//
//	state       6 fixed values (user, system, iowait, steal, irq, other)
//	cpu         omitted unless per-core is enabled; then capped at cpu.max
//	device      block devices after exclusion, capped at disk.max
//	interface   interfaces after exclusion, capped at network.max
//	mountpoint  mounts after exclusion, capped at filesystem.max
//	fstype      the host's filesystem types, in practice single digits
//	source      7 fixed values, one per collection source
//	type        2 fixed values (logical, physical)
//
// Deliberately NOT used as attributes anywhere: PID, timestamps, UUIDs, full
// command lines, file paths other than mountpoints, error strings, or device
// serial numbers. Each of those is unbounded, and an agent that emits unbounded
// labels becomes the incident it was installed to detect.
const (
	MetricCPUUtilization = "host.cpu.utilization" // attrs: state, [cpu]
	MetricCPUCount       = "host.cpu.count"       // attrs: type

	MetricMemoryTotal       = "host.memory.total_bytes"
	MetricMemoryUsed        = "host.memory.used_bytes"
	MetricMemoryAvailable   = "host.memory.available_bytes"
	MetricMemoryUtilization = "host.memory.utilization"
	MetricSwapTotal         = "host.memory.swap.total_bytes"
	MetricSwapUsed          = "host.memory.swap.used_bytes"

	MetricDiskReadBytes  = "host.disk.read_bytes"  // attrs: device
	MetricDiskWriteBytes = "host.disk.write_bytes" // attrs: device
	MetricDiskReadOps    = "host.disk.read_ops"    // attrs: device
	MetricDiskWriteOps   = "host.disk.write_ops"   // attrs: device
	MetricDiskIOTime     = "host.disk.io_time_seconds"

	MetricFilesystemTotal       = "host.filesystem.total_bytes"     // attrs: mountpoint, fstype
	MetricFilesystemUsed        = "host.filesystem.used_bytes"      // attrs: mountpoint, fstype
	MetricFilesystemAvailable   = "host.filesystem.available_bytes" // attrs: mountpoint, fstype
	MetricFilesystemUtilization = "host.filesystem.utilization"     // attrs: mountpoint, fstype
	MetricFilesystemInodesUsed  = "host.filesystem.inodes_used"     // attrs: mountpoint, fstype
	MetricFilesystemInodesTotal = "host.filesystem.inodes_total"    // attrs: mountpoint, fstype

	MetricNetworkRxBytes   = "host.network.rx_bytes"   // attrs: interface
	MetricNetworkTxBytes   = "host.network.tx_bytes"   // attrs: interface
	MetricNetworkRxPackets = "host.network.rx_packets" // attrs: interface
	MetricNetworkTxPackets = "host.network.tx_packets" // attrs: interface
	MetricNetworkRxErrors  = "host.network.rx_errors"  // attrs: interface
	MetricNetworkTxErrors  = "host.network.tx_errors"  // attrs: interface
	MetricNetworkRxDropped = "host.network.rx_dropped" // attrs: interface
	MetricNetworkTxDropped = "host.network.tx_dropped" // attrs: interface

	MetricLoad1  = "host.load.1m"
	MetricLoad5  = "host.load.5m"
	MetricLoad15 = "host.load.15m"

	MetricUptime = "host.uptime_seconds"
	MetricInfo   = "host.info" // constant 1; attrs describe the host
)

// Self-observability. Kept small on purpose: a module that reports twenty
// metrics about itself and twelve about the host has the wrong priorities, and
// every self-metric is cost the customer pays to watch the agent watch them.
const (
	MetricCollectionDuration    = "host.collection.duration_seconds" // attrs: source
	MetricCollectionSuccess     = "host.collection.success"          // attrs: source
	MetricCollectionFailure     = "host.collection.failure"          // attrs: source
	MetricCollectionUnsupported = "host.collection.unsupported"      // attrs: source
	MetricCollectionLastSuccess = "host.collection.last_success_seconds"
	MetricTelemetryItems        = "host.telemetry.items"   // attrs: source
	MetricTelemetryDropped      = "host.telemetry.dropped" // attrs: source, reason
	MetricModuleHealth          = "host.module.health"
)

// Attribute keys. This is the complete set the module may emit.
const (
	AttrState      = "state"
	AttrCPU        = "cpu"
	AttrType       = "type"
	AttrDevice     = "device"
	AttrInterface  = "interface"
	AttrMountpoint = "mountpoint"
	AttrFSType     = "fstype"
	AttrSource     = "source"
	AttrReason     = "reason"

	// Entity binding. The value is the platform-assigned host entity ID; the
	// module never generates one.
	AttrEntityID = "entity.id"

	// host.info attribute keys. All are constant for the life of a host, so
	// host.info is exactly one series.
	AttrInfoOS       = "os"
	AttrInfoPlatform = "platform"
	AttrInfoVersion  = "platform_version"
	AttrInfoKernel   = "kernel_version"
	AttrInfoArch     = "architecture"
)

// dropReasonCardinality is the reason recorded when an observation is dropped
// because a source exceeded its configured series cap.
const dropReasonCardinality = "cardinality_limit"

// AllMetrics is every host metric this module can emit. It exists so that
// configuration can reject a disable-request for a metric that does not exist,
// rather than silently accepting a typo and leaving the metric enabled.
var AllMetrics = []string{
	MetricCPUUtilization, MetricCPUCount,
	MetricMemoryTotal, MetricMemoryUsed, MetricMemoryAvailable,
	MetricMemoryUtilization, MetricSwapTotal, MetricSwapUsed,
	MetricDiskReadBytes, MetricDiskWriteBytes, MetricDiskReadOps,
	MetricDiskWriteOps, MetricDiskIOTime,
	MetricFilesystemTotal, MetricFilesystemUsed, MetricFilesystemAvailable,
	MetricFilesystemUtilization, MetricFilesystemInodesUsed, MetricFilesystemInodesTotal,
	MetricNetworkRxBytes, MetricNetworkTxBytes, MetricNetworkRxPackets,
	MetricNetworkTxPackets, MetricNetworkRxErrors, MetricNetworkTxErrors,
	MetricNetworkRxDropped, MetricNetworkTxDropped,
	MetricLoad1, MetricLoad5, MetricLoad15,
	MetricUptime, MetricInfo,
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
