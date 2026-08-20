package host

import (
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// instruments pre-binds every instrument the module can emit.
//
// Pre-binding rather than looking up per emission does two things: it removes a
// map lookup from the hot path, and it makes the complete set of names this
// module can produce visible in one place, which is what makes the cardinality
// policy in metrics.go auditable rather than aspirational.
type instruments struct {
	gauges     map[string]platform.Gauge
	counters   map[string]platform.Counter
	histograms map[string]platform.Histogram
}

func newInstruments(t platform.Telemetry) *instruments {
	in := &instruments{
		gauges:     make(map[string]platform.Gauge),
		counters:   make(map[string]platform.Counter),
		histograms: make(map[string]platform.Histogram),
	}
	gauge := []string{
		MetricCPUUtilization, MetricCPUCount,
		MetricMemoryTotal, MetricMemoryUsed, MetricMemoryAvailable,
		MetricMemoryUtilization, MetricSwapTotal, MetricSwapUsed,
		MetricFilesystemTotal, MetricFilesystemUsed, MetricFilesystemAvailable,
		MetricFilesystemUtilization, MetricFilesystemInodesUsed, MetricFilesystemInodesTotal,
		MetricLoad1, MetricLoad5, MetricLoad15,
		MetricUptime, MetricInfo,
		MetricCollectionLastSuccess, MetricModuleHealth,
	}
	counter := []string{
		MetricDiskReadBytes, MetricDiskWriteBytes, MetricDiskReadOps,
		MetricDiskWriteOps, MetricDiskIOTime,
		MetricNetworkRxBytes, MetricNetworkTxBytes, MetricNetworkRxPackets,
		MetricNetworkTxPackets, MetricNetworkRxErrors, MetricNetworkTxErrors,
		MetricNetworkRxDropped, MetricNetworkTxDropped,
		MetricCollectionSuccess, MetricCollectionFailure,
		MetricCollectionUnsupported, MetricTelemetryItems, MetricTelemetryDropped,
	}
	for _, n := range gauge {
		in.gauges[n] = t.Gauge(n)
	}
	for _, n := range counter {
		in.counters[n] = t.Counter(n)
	}
	in.histograms[MetricCollectionDuration] = t.Histogram(MetricCollectionDuration)
	return in
}

// emitter turns reader output into telemetry.
//
// It is used only from the single collection goroutine and is not safe for
// concurrent use; the scratch attribute buffer depends on that.
type emitter struct {
	inst     *instruments
	settings Settings

	// entity is the platform-assigned host entity attribute. When identity is
	// unresolved this is the zero value and NO entity attribute is attached —
	// the module never synthesises one, because a locally invented entity ID
	// forks the platform's entity graph in a way that is very hard to undo.
	entity   platform.Attr
	hasEntit bool

	diskCounters *counterState
	netCounters  *counterState
	cpu          cpuState

	// buf is a reusable attribute buffer, so a collection cycle does not
	// allocate one slice per observation.
	buf []platform.Attr

	// items counts observations emitted in the current source collection.
	items int64
}

func newEmitter(inst *instruments, s Settings) *emitter {
	return &emitter{
		inst:         inst,
		settings:     s,
		diskCounters: newCounterState(),
		netCounters:  newCounterState(),
		buf:          make([]platform.Attr, 0, 6),
	}
}

// setEntity binds observations to the platform host entity.
func (e *emitter) setEntity(hostID string) {
	if hostID == "" {
		e.entity = platform.Attr{}
		e.hasEntit = false
		return
	}
	e.entity = platform.A(AttrEntityID, hostID)
	e.hasEntit = true
}

// with builds the attribute set for one observation: the entity binding plus
// the caller's attributes.
func (e *emitter) with(extra ...platform.Attr) []platform.Attr {
	e.buf = e.buf[:0]
	if e.hasEntit {
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

func (e *emitter) gaugeU64(metric string, v U64, attrs ...platform.Attr) {
	if !v.OK {
		// Unknown values are not emitted. Emitting zero would be a fabricated
		// measurement, which is the one thing this module must never do.
		return
	}
	e.gauge(metric, float64(v.V), attrs...)
}

func (e *emitter) counter(metric string, delta uint64, attrs ...platform.Attr) {
	if !e.enabled(metric) || delta == 0 {
		return
	}
	c, ok := e.inst.counters[metric]
	if !ok {
		return
	}
	c.Add(int64(delta), e.with(attrs...)...)
	e.items++
}

// emitCPU publishes CPU utilisation and counts.
func (e *emitter) emitCPU(s CPUStats) {
	if s.LogicalCount.OK {
		e.gauge(MetricCPUCount, float64(s.LogicalCount.V), platform.A(AttrType, "logical"))
	}
	if s.PhysicalCount.OK {
		e.gauge(MetricCPUCount, float64(s.PhysicalCount.V), platform.A(AttrType, "physical"))
	}
	if !s.HasTotal {
		return
	}

	busy, user, system, iowait, steal, irq, ok := e.cpu.utilisation(s.Total)
	if !ok {
		// First sample, or the counters did not advance. There is no
		// utilisation to report yet; the baseline has been seeded.
		return
	}
	e.gauge(MetricCPUUtilization, busy, platform.A(AttrState, "busy"))
	e.gauge(MetricCPUUtilization, user, platform.A(AttrState, "user"))
	e.gauge(MetricCPUUtilization, system, platform.A(AttrState, "system"))
	e.gauge(MetricCPUUtilization, iowait, platform.A(AttrState, "iowait"))
	e.gauge(MetricCPUUtilization, steal, platform.A(AttrState, "steal"))
	e.gauge(MetricCPUUtilization, irq, platform.A(AttrState, "irq"))
}

// emitMemory publishes memory and swap usage.
func (e *emitter) emitMemory(s MemoryStats) {
	e.gaugeU64(MetricMemoryTotal, s.Total)
	e.gaugeU64(MetricMemoryUsed, s.Used)
	e.gaugeU64(MetricMemoryAvailable, s.Available)
	e.gaugeU64(MetricSwapTotal, s.SwapTotal)
	e.gaugeU64(MetricSwapUsed, s.SwapUsed)

	if s.Total.OK && s.Used.OK && s.Total.V > 0 {
		e.gauge(MetricMemoryUtilization, float64(s.Used.V)/float64(s.Total.V))
	}
}

// emitDisk publishes block device I/O deltas.
func (e *emitter) emitDisk(devices []DiskStats) int {
	kept, dropped := selectBounded(devices,
		func(d DiskStats) string { return d.Device },
		e.settings.DiskExclude, e.settings.MaxDisks)

	e.diskCounters.beginCycle()
	for _, d := range kept {
		attr := platform.A(AttrDevice, d.Device)
		e.counterFrom(MetricDiskReadBytes, e.diskCounters, d.Device+"|rb", d.ReadBytes, attr)
		e.counterFrom(MetricDiskWriteBytes, e.diskCounters, d.Device+"|wb", d.WriteBytes, attr)
		e.counterFrom(MetricDiskReadOps, e.diskCounters, d.Device+"|ro", d.ReadOps, attr)
		e.counterFrom(MetricDiskWriteOps, e.diskCounters, d.Device+"|wo", d.WriteOps, attr)
		e.counterFrom(MetricDiskIOTime, e.diskCounters, d.Device+"|io", d.IOTime, attr)
	}
	e.diskCounters.endCycle()
	return dropped
}

// emitNetwork publishes interface counter deltas.
func (e *emitter) emitNetwork(ifaces []InterfaceStats) int {
	kept, dropped := selectBounded(ifaces,
		func(i InterfaceStats) string { return i.Name },
		e.settings.NetworkExclude, e.settings.MaxInterfaces)

	e.netCounters.beginCycle()
	for _, n := range kept {
		attr := platform.A(AttrInterface, n.Name)
		e.counterFrom(MetricNetworkRxBytes, e.netCounters, n.Name+"|rb", n.RxBytes, attr)
		e.counterFrom(MetricNetworkTxBytes, e.netCounters, n.Name+"|tb", n.TxBytes, attr)
		e.counterFrom(MetricNetworkRxPackets, e.netCounters, n.Name+"|rp", n.RxPackets, attr)
		e.counterFrom(MetricNetworkTxPackets, e.netCounters, n.Name+"|tp", n.TxPackets, attr)
		e.counterFrom(MetricNetworkRxErrors, e.netCounters, n.Name+"|re", n.RxErrors, attr)
		e.counterFrom(MetricNetworkTxErrors, e.netCounters, n.Name+"|te", n.TxErrors, attr)
		e.counterFrom(MetricNetworkRxDropped, e.netCounters, n.Name+"|rd", n.RxDropped, attr)
		e.counterFrom(MetricNetworkTxDropped, e.netCounters, n.Name+"|td", n.TxDropped, attr)
	}
	e.netCounters.endCycle()
	return dropped
}

func (e *emitter) counterFrom(metric string, state *counterState, key string, v U64, attrs ...platform.Attr) {
	if !v.OK {
		return
	}
	if d, ok := state.delta(key, v.V); ok {
		e.counter(metric, d, attrs...)
	}
}

// emitFilesystems publishes filesystem usage.
func (e *emitter) emitFilesystems(all []FilesystemStats) int {
	kept, dropped := filterFilesystems(all, e.settings)
	for _, fs := range kept {
		attrs := []platform.Attr{
			platform.A(AttrMountpoint, fs.Mountpoint),
			platform.A(AttrFSType, fs.FSType),
		}
		e.gaugeU64(MetricFilesystemTotal, fs.TotalBytes, attrs...)
		e.gaugeU64(MetricFilesystemUsed, fs.UsedBytes, attrs...)
		e.gaugeU64(MetricFilesystemAvailable, fs.AvailBytes, attrs...)

		if fs.TotalBytes.OK && fs.UsedBytes.OK && fs.TotalBytes.V > 0 {
			e.gauge(MetricFilesystemUtilization,
				float64(fs.UsedBytes.V)/float64(fs.TotalBytes.V), attrs...)
		}
		if e.settings.ReportInodeMetrics {
			e.gaugeU64(MetricFilesystemInodesTotal, fs.TotalInode, attrs...)
			e.gaugeU64(MetricFilesystemInodesUsed, fs.UsedInode, attrs...)
		}
	}
	return dropped
}

// emitLoad publishes the load average.
func (e *emitter) emitLoad(s LoadStats) {
	if s.Load1.OK {
		e.gauge(MetricLoad1, s.Load1.V)
	}
	if s.Load5.OK {
		e.gauge(MetricLoad5, s.Load5.V)
	}
	if s.Load15.OK {
		e.gauge(MetricLoad15, s.Load15.V)
	}
}

// emitOS publishes host metadata as a single constant-valued series whose
// attributes carry the information, plus uptime.
//
// host.info is one series per host because every one of its attributes is
// constant for the life of the host. Encoding metadata as attributes of a
// constant gauge is the standard way to make it joinable at query time without
// attaching it to every other series.
func (e *emitter) emitOS(info OSInfo, now time.Time) {
	e.gauge(MetricInfo, 1,
		platform.A(AttrInfoOS, info.OS),
		platform.A(AttrInfoPlatform, info.Platform),
		platform.A(AttrInfoVersion, info.PlatformVersion),
		platform.A(AttrInfoKernel, info.KernelVersion),
		platform.A(AttrInfoArch, info.Architecture),
	)
	if info.HasBootTime {
		uptime := now.Sub(info.BootTime)
		if uptime > 0 {
			e.gauge(MetricUptime, uptime.Seconds())
		}
	}
}
