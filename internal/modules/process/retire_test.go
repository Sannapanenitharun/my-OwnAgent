package process

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// gaugeSeries reports how many series one gauge instrument is carrying.
func gaugeSeries(t *inproc.Telemetry, name string) int {
	n := 0
	for _, p := range t.GaugeSnapshot() {
		if p.Name == name {
			n++
		}
	}
	return n
}

func gaugeValue(t *inproc.Telemetry, name, exe string) (float64, bool) {
	for _, p := range t.GaugeSnapshot() {
		if p.Name != name {
			continue
		}
		for _, a := range p.Attrs {
			if a.Key == AttrExecutable && a.Value == exe {
				return p.Value, true
			}
		}
	}
	return 0, false
}

// TestExitedExecutableStopsBeingReported is the regression test for a leak that
// made the fleet view list 377 programs on a host running 232. A gauge is a
// latest value and nothing tells the store a program exited, so the last
// reading was re-exported forever.
func TestExitedExecutableStopsBeingReported(t *testing.T) {
	tel := inproc.NewTelemetry()
	e := newEmitter(newInstruments(tel), DefaultSettings())

	e.emitRollups([]*rollup{
		{Name: "nginx", Instances: 2, HasRSS: true, RSSBytes: 1024},
		{Name: "cron", Instances: 1, HasRSS: true, RSSBytes: 512},
	})
	if got := gaugeSeries(tel, MetricInstances); got != 2 {
		t.Fatalf("instances series = %d, want 2", got)
	}

	// cron exits. Only nginx is reported now.
	e.emitRollups([]*rollup{
		{Name: "nginx", Instances: 2, HasRSS: true, RSSBytes: 1024},
	})

	if _, ok := gaugeValue(tel, MetricInstances, "cron"); ok {
		t.Error("cron still reports an instance count after exiting")
	}
	// Retiring the count while leaving memory behind would show a program with
	// no processes still holding half a kilobyte.
	if v, ok := gaugeValue(tel, MetricMemoryRSS, "cron"); ok {
		t.Errorf("cron still reports %v bytes of RSS after exiting", v)
	}
	if _, ok := gaugeValue(tel, MetricInstances, "nginx"); !ok {
		t.Error("nginx was retired; only the vanished executable should be")
	}
}

func TestRetirementFreesTheCardinalityBudget(t *testing.T) {
	// The leak's real cost: dead series count against the cap, so a host that
	// churns through short-lived programs eventually fills its budget with
	// things that no longer exist and starts refusing the ones that do.
	tel := inproc.NewTelemetry()
	e := newEmitter(newInstruments(tel), DefaultSettings())

	for i := 0; i < 50; i++ {
		e.emitRollups([]*rollup{{Name: "short-lived-" + itoa(i), Instances: 1}})
	}
	if got := gaugeSeries(tel, MetricInstances); got != 1 {
		t.Errorf("instances series = %d, want 1: each cycle replaces the last", got)
	}
}

func TestExecutableThatComesBackIsReportedAgain(t *testing.T) {
	// Retirement must not be a tombstone. A cron job that runs every minute
	// disappears and returns, and it has to reappear each time.
	tel := inproc.NewTelemetry()
	e := newEmitter(newInstruments(tel), DefaultSettings())

	e.emitRollups([]*rollup{{Name: "backup", Instances: 1}})
	e.emitRollups(nil)
	e.emitRollups([]*rollup{{Name: "backup", Instances: 3}})

	v, ok := gaugeValue(tel, MetricInstances, "backup")
	if !ok {
		t.Fatal("backup did not come back")
	}
	if v != 3 {
		t.Errorf("instances = %v, want the current value 3", v)
	}
}

func TestCountersAreNotRetired(t *testing.T) {
	// A counter is a running total. It does not stop being true because the
	// process that accumulated it ended, and resetting one would look like a
	// counter reset to anything computing a rate.
	tel := inproc.NewTelemetry()
	e := newEmitter(newInstruments(tel), DefaultSettings())

	e.emitRollups([]*rollup{{Name: "gone", HasIO: true, IORead: 4096, IOWrite: 100}})
	e.emitRollups(nil)

	var found bool
	for _, c := range tel.CounterSnapshot() {
		if c.Name == MetricIOReadBytes {
			found = true
			if c.Value != 4096 {
				t.Errorf("io read = %d, want the total preserved at 4096", c.Value)
			}
		}
	}
	if !found {
		t.Error("the IO counter was retired along with the gauges")
	}
}

func TestAggregateGaugesSurviveAnEmptyCycle(t *testing.T) {
	// Only per-executable gauges are retired. The host-level counts are a
	// closed attribute set and a zero there is a measurement, not an absence.
	tel := inproc.NewTelemetry()
	e := newEmitter(newInstruments(tel), DefaultSettings())

	e.emitAggregate(12, map[State]int{}, false)
	e.emitRollups([]*rollup{{Name: "gone", Instances: 1}})
	e.emitRollups(nil)

	var found bool
	for _, p := range tel.GaugeSnapshot() {
		if p.Name == MetricCount {
			found = true
		}
	}
	if !found {
		t.Error("the host-level process count was retired")
	}
}

func TestRetirementSurvivesATelemetryThatCannotForget(t *testing.T) {
	// Retirement is best-effort: an adapter that cannot forget a series is not
	// broken, and the module must not depend on it having worked.
	e := newEmitter(newInstruments(noRetireTelemetry{inproc.NewTelemetry()}), DefaultSettings())
	e.emitRollups([]*rollup{{Name: "a", Instances: 1}})
	e.emitRollups(nil) // must not panic
}

// noRetireTelemetry hides RetireSeries from the emitter.
type noRetireTelemetry struct{ inner *inproc.Telemetry }

func (n noRetireTelemetry) Counter(name string) platform.Counter { return n.inner.Counter(name) }
func (n noRetireTelemetry) Gauge(name string) platform.Gauge     { return n.inner.Gauge(name) }
func (n noRetireTelemetry) Histogram(name string) platform.Histogram {
	return n.inner.Histogram(name)
}
func (n noRetireTelemetry) Emit(ev platform.Event)         { n.inner.Emit(ev) }
func (n noRetireTelemetry) EmitLog(rec platform.LogRecord) { n.inner.EmitLog(rec) }
func (n noRetireTelemetry) IngestTraces(tp platform.TracePayload) {
	n.inner.IngestTraces(tp)
}
