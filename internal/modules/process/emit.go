package process

import (
	"sort"
	"strconv"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// instruments pre-binds every instrument the module can emit.
//
// Pre-binding removes a map lookup from a path that runs once per executable per
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
		MetricCount, MetricCountByState,
		MetricCPUUtilization, MetricMemoryRSS, MetricMemoryVirtual,
		MetricThreadCount, MetricOpenFiles, MetricInstances, MetricStartTime,
		MetricDiscovered, MetricSelected, MetricFiltered,
		MetricStateEntries, MetricExecutables, MetricUnsupported, MetricModuleHealth,
	}
	counter := []string{
		MetricIOReadBytes, MetricIOWriteBytes,
		MetricCollectionSuccess, MetricCollectionFailure,
		MetricDropped, MetricUnreadable, MetricChurn,
		MetricStarted, MetricExited, MetricReplaced,
		MetricTelemetryGenerated, MetricTelemetryDropped,
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

// rollup is one executable's aggregated figures.
//
// This type IS the cardinality strategy. Ten thousand processes become at most
// max_executables rollups, and the series count therefore tracks the number of
// distinct programs on the host rather than the number of processes.
type rollup struct {
	Name      string
	Instances int64

	CPUUtilization float64
	HasCPU         bool
	RSSBytes       uint64
	HasRSS         bool
	VirtualBytes   uint64
	HasVirtual     bool
	Threads        uint64
	HasThreads     bool
	OpenFiles      uint64
	HasOpenFiles   bool
	IORead         uint64
	IOWrite        uint64
	HasIO          bool

	// OldestStart is the start time of the longest-running instance. A step
	// change in it is what an operator reads as "this service restarted".
	OldestStart time.Time
	HasStart    bool
}

// rollupBy aggregates observations by executable name.
//
// Sums, not averages, for everything additive: five hundred workers using 8 MB
// each is 4 GB of real memory, and reporting the average would hide it. The one
// exception is start time, where the meaningful aggregate is the extremum.
//
// The result is sorted by name so that every downstream step — selection,
// emission, and the tests — sees a deterministic order.
func rollupBy(obs []*observation) []*rollup {
	byName := make(map[string]*rollup, 64)
	for _, o := range obs {
		r, ok := byName[o.Name]
		if !ok {
			r = &rollup{Name: o.Name}
			byName[o.Name] = r
		}
		r.Instances++

		if o.HasCPU {
			r.CPUUtilization += o.CPUUtilization
			r.HasCPU = true
		}
		if o.RSSBytes.OK {
			r.RSSBytes += o.RSSBytes.V
			r.HasRSS = true
		}
		if o.VirtualBytes.OK {
			r.VirtualBytes += o.VirtualBytes.V
			r.HasVirtual = true
		}
		if o.Threads.OK {
			r.Threads += o.Threads.V
			r.HasThreads = true
		}
		if o.OpenFiles.OK {
			r.OpenFiles += o.OpenFiles.V
			r.HasOpenFiles = true
		}
		if o.IOReadDelta.OK {
			r.IORead += o.IOReadDelta.V
			r.HasIO = true
		}
		if o.IOWriteDelta.OK {
			r.IOWrite += o.IOWriteDelta.V
			r.HasIO = true
		}
		if o.HasStartTime && (!r.HasStart || o.StartTime.Before(r.OldestStart)) {
			r.OldestStart = o.StartTime
			r.HasStart = true
		}
	}

	out := make([]*rollup, 0, len(byName))
	for _, r := range byName {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// emitter turns collection results into telemetry.
//
// It is used only from the single collection goroutine and is not safe for
// concurrent use; the scratch attribute buffer depends on that.
type emitter struct {
	inst     *instruments
	settings Settings

	// entity is the platform-assigned HOST entity. Metrics are host-scoped:
	// binding a metric series to a process entity would recreate exactly the
	// per-process cardinality the rollup exists to avoid. Process entities
	// appear on events.
	entity    platform.Attr
	hasEntity bool

	buf []platform.Attr

	// emitted names the executables whose gauges were set last cycle, so the
	// ones that have since gone can be withdrawn. Without it a gauge set once
	// is exported forever: the executable list is a union of everything the
	// host has ever run rather than what is running, and it grows until it
	// fills MaxExecutables with the dead.
	emitted map[string]struct{}

	items         int64
	eventsCycle   int
	eventsDropped int64
}

func newEmitter(inst *instruments, s Settings) *emitter {
	return &emitter{
		inst:     inst,
		settings: s,
		buf:      make([]platform.Attr, 0, 4),
		emitted:  make(map[string]struct{}),
	}
}

// perExecutableGauges is every gauge keyed by executable. All of them have to
// be withdrawn together: retiring the instance count while leaving the memory
// reading behind would show a program with no processes still holding a
// gigabyte.
var perExecutableGauges = []string{
	MetricInstances, MetricCPUUtilization, MetricMemoryRSS,
	MetricMemoryVirtual, MetricThreadCount, MetricOpenFiles, MetricStartTime,
}

// retireVanished withdraws the gauges of executables that were reported last
// cycle and are not in this one.
//
// An executable leaves for two reasons and this treats them the same, which is
// correct: the program exited, or it fell out of the top MaxExecutables. In
// both cases the agent has stopped measuring it, and a latest-value gauge with
// nothing behind it is not data.
//
// Counters are left alone. MetricIOReadBytes is a running total, and a total
// does not stop being true because the process that accumulated it ended.
func (e *emitter) retireVanished(current map[string]struct{}) {
	for name := range e.emitted {
		if _, still := current[name]; still {
			continue
		}
		attr := platform.A(AttrExecutable, name)
		for _, metric := range perExecutableGauges {
			platform.RetireSeries(e.inst.telemetry, metric, attr)
		}
	}
	e.emitted = current
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

// emitAggregate publishes the host-level process counts.
//
// This is priority zero: it is the last thing shed and the first thing an
// operator looks at. It is also exactly two metrics and eight series, which is
// what makes it affordable to keep under any pressure.
//
// Zero counts ARE emitted here, unlike unknown values elsewhere in the agent,
// and the difference is real: "no zombie processes" is a measurement, whereas an
// absent swap figure is an unknown. A gauge that vanishes when it reaches zero
// is a gauge nobody can alert on.
func (e *emitter) emitAggregate(total int, byState map[State]int, stateSupported bool) {
	e.gauge(MetricCount, float64(total))
	if !stateSupported {
		return
	}
	for _, st := range AllStates {
		e.gauge(MetricCountByState, float64(byState[st]), platform.A(AttrState, st.String()))
	}
}

// emitRollups publishes the per-executable metrics.
func (e *emitter) emitRollups(rollups []*rollup) {
	current := make(map[string]struct{}, len(rollups))
	defer func() { e.retireVanished(current) }()

	for _, r := range rollups {
		current[r.Name] = struct{}{}
		attr := platform.A(AttrExecutable, r.Name)
		e.gauge(MetricInstances, float64(r.Instances), attr)
		if r.HasCPU {
			e.gauge(MetricCPUUtilization, r.CPUUtilization, attr)
		}
		if r.HasRSS {
			e.gauge(MetricMemoryRSS, float64(r.RSSBytes), attr)
		}
		if r.HasVirtual {
			e.gauge(MetricMemoryVirtual, float64(r.VirtualBytes), attr)
		}
		if r.HasThreads {
			e.gauge(MetricThreadCount, float64(r.Threads), attr)
		}
		if r.HasOpenFiles {
			e.gauge(MetricOpenFiles, float64(r.OpenFiles), attr)
		}
		if r.HasIO {
			e.counter(MetricIOReadBytes, r.IORead, attr)
			e.counter(MetricIOWriteBytes, r.IOWrite, attr)
		}
		if r.HasStart {
			e.gauge(MetricStartTime, float64(r.OldestStart.Unix()), attr)
		}
	}
}

// beginEvents resets the per-cycle event budget.
func (e *emitter) beginEvents() { e.eventsCycle = 0 }

// emitEvent publishes one event if the cycle's budget allows.
//
// The budget is what stops a churn storm becoming an event storm. Ten thousand
// processes exiting in one cycle is a real thing that happens — a build farm
// finishing a job, a container host draining — and an agent that faithfully
// emitted ten thousand events would do more damage than the churn itself. What
// is dropped is counted, and the churn summary reports the totals that the
// individual events could not.
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

// emitLifecycle publishes one process lifecycle event.
//
// This is where per-instance detail lives: PID, parent PID, start time,
// lifetime and the resolved process entity. None of it is a metric attribute,
// and that separation is the module's central cardinality decision — an event is
// a bounded record with a lifetime, a series is forever.
func (e *emitter) emitLifecycle(c lifecycleChange, now time.Time) bool {
	attrs := make([]platform.Attr, 0, 8)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	attrs = append(attrs,
		platform.A(AttrExecutable, c.Name),
		platform.A(AttrPID, strconv.Itoa(int(c.PID))),
	)
	if c.EntityID != "" {
		attrs = append(attrs, platform.A(AttrProcessEntityID, c.EntityID))
	}
	if c.Kind == EventStarted {
		attrs = append(attrs, platform.A(AttrPPID, strconv.Itoa(int(c.PPID))))
		if c.HasStart {
			attrs = append(attrs, platform.A(AttrStartTime, strconv.FormatInt(c.StartTime.Unix(), 10)))
		}
		if c.Restart {
			attrs = append(attrs, platform.A("restart", "true"))
		}
	}
	if c.HasLifetime {
		attrs = append(attrs, platform.A(AttrLifetime,
			strconv.FormatInt(int64(c.Lifetime.Seconds()), 10)))
	}
	return e.emitEvent(platform.Event{
		Name:      c.Kind,
		Severity:  platform.SeverityInfo,
		Timestamp: now,
		Attrs:     attrs,
	})
}

// emitChurnSummary reports the cycle's aggregate lifecycle activity.
//
// It is emitted whenever anything started or exited, and it is the only record
// that is guaranteed to survive a churn storm. An operator seeing "18,402
// processes started" learns more from this one event than from the five hundred
// individual ones that fitted inside the budget.
func (e *emitter) emitChurnSummary(started, exited, replaced, notEmitted int64, now time.Time) {
	if started == 0 && exited == 0 {
		return
	}
	attrs := make([]platform.Attr, 0, 5)
	if e.hasEntity {
		attrs = append(attrs, e.entity)
	}
	attrs = append(attrs,
		platform.A("started", strconv.FormatInt(started, 10)),
		platform.A("exited", strconv.FormatInt(exited, 10)),
		platform.A("replaced", strconv.FormatInt(replaced, 10)),
		platform.A("events_suppressed", strconv.FormatInt(notEmitted, 10)),
	)
	// Deliberately bypasses the per-cycle budget: it is one event, and it is the
	// one that explains why the others are missing.
	if e.settings.EventsEnabled {
		e.inst.telemetry.Emit(platform.Event{
			Name:      EventChurn,
			Severity:  platform.SeverityInfo,
			Timestamp: now,
			Attrs:     attrs,
		})
		e.items++
	}
}

// emitTop publishes the highest-CPU processes as events.
//
// Off by default. It is the escape hatch for the question the rollup design
// cannot answer — "WHICH nginx worker is eating the CPU?" — and it is opt-in
// because at one event per process per cycle it is the module's most expensive
// output. Answering that question with a metric label would cost a permanent
// series per PID; answering it with a bounded event stream costs N records per
// cycle and nothing thereafter.
func (e *emitter) emitTop(obs []*observation, n int, now time.Time) {
	if n <= 0 || len(obs) == 0 {
		return
	}
	ranked := make([]*observation, len(obs))
	copy(ranked, obs)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.HasCPU != b.HasCPU {
			return a.HasCPU
		}
		if a.HasCPU && a.CPUUtilization != b.CPUUtilization {
			return a.CPUUtilization > b.CPUUtilization
		}
		if a.RSSBytes.V != b.RSSBytes.V {
			return a.RSSBytes.V > b.RSSBytes.V
		}
		return a.PID < b.PID
	})
	if len(ranked) > n {
		ranked = ranked[:n]
	}

	for _, o := range ranked {
		attrs := make([]platform.Attr, 0, 8)
		if e.hasEntity {
			attrs = append(attrs, e.entity)
		}
		attrs = append(attrs,
			platform.A(AttrExecutable, o.Name),
			platform.A(AttrPID, strconv.Itoa(int(o.PID))),
		)
		if o.EntityID != "" {
			attrs = append(attrs, platform.A(AttrProcessEntityID, o.EntityID))
		}
		if o.HasCPU {
			attrs = append(attrs, platform.A(AttrCPU, strconv.FormatFloat(o.CPUUtilization, 'f', 4, 64)))
		}
		if o.RSSBytes.OK {
			attrs = append(attrs, platform.A(AttrRSS, strconv.FormatUint(o.RSSBytes.V, 10)))
		}
		if o.UID.OK {
			attrs = append(attrs, platform.A(AttrUID, strconv.FormatUint(o.UID.V, 10)))
		}
		if o.ExecutablePath != "" {
			attrs = append(attrs, platform.A(AttrExecutablePath, o.ExecutablePath))
		}
		if len(o.CommandLine) > 0 {
			// The command line leaves the module ONLY here, only when explicitly
			// enabled, and only as an event attribute — never as a metric label
			// and never in a diagnostic. Events are the pipeline stage the
			// platform's secret scrubber operates on.
			attrs = append(attrs, platform.A(AttrCommandLine, joinArgs(o.CommandLine)))
		}
		e.emitEvent(platform.Event{
			Name:      EventTop,
			Severity:  platform.SeverityInfo,
			Timestamp: now,
			Attrs:     attrs,
		})
	}
}

// joinArgs renders an argument vector, bounded again at the emission boundary.
//
// The reader already caps what it returns. Capping here as well is not
// redundancy for its own sake: this is the last point before untrusted bytes
// leave the agent, and it is the only bound that still holds if a future reader
// forgets its own.
func joinArgs(args []string) string {
	const maxRendered = 1024
	out := make([]byte, 0, 128)
	for i, a := range args {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, a...)
		if len(out) >= maxRendered {
			return string(out[:maxRendered])
		}
	}
	return string(out)
}
