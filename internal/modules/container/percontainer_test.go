package container

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func seriesFor(t *inproc.Telemetry, name string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range t.GaugeSnapshot() {
		if p.Name != name {
			continue
		}
		id := ""
		for _, a := range p.Attrs {
			if a.Key == AttrContainerID {
				id = a.Value
			}
		}
		out[id] = p.Value
	}
	return out
}

func newTestModule(tel *inproc.Telemetry) (*Module, module.Host) {
	m := &Module{}
	m.settings = DefaultSettings()
	return m, module.Host{Telemetry: tel}
}

// TestEachContainerGetsItsOwnSeries is the point of the change. The rollup said
// "21 containers are using 5.3 GB between them", which does not answer the
// question an operator actually has, which is which one.
func TestEachContainerGetsItsOwnSeries(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)

	m.emitPerContainer(h, []sample{
		{ShortID: "a1b2c3d4e5f6", Runtime: "docker", MemoryBytes: 1024, CPUUtil: 0.25},
		{ShortID: "f6e5d4c3b2a1", Runtime: "docker", MemoryBytes: 2048, CPUUtil: 0.50},
	})

	mem := seriesFor(tel, MetricInstanceMemory)
	if len(mem) != 2 {
		t.Fatalf("memory series = %d, want one per container", len(mem))
	}
	if mem["a1b2c3d4e5f6"] != 1024 || mem["f6e5d4c3b2a1"] != 2048 {
		t.Errorf("memory by container = %v", mem)
	}
	if cpu := seriesFor(tel, MetricInstanceCPU); cpu["a1b2c3d4e5f6"] != 0.25 {
		t.Errorf("cpu by container = %v", cpu)
	}
}

// TestPerContainerNamesDoNotCollideWithTheRollup guards the footgun. Two series
// under one metric name, where one is the sum of the others, makes any
// aggregation that does not inspect label sets count every container twice.
func TestPerContainerNamesDoNotCollideWithTheRollup(t *testing.T) {
	for _, rollup := range []string{MetricMemoryUsage, MetricCPUUtilization, MetricRunning} {
		for _, per := range []string{MetricInstanceMemory, MetricInstanceCPU} {
			if rollup == per {
				t.Errorf("per-container metric %q reuses the rollup's name", per)
			}
		}
	}
}

// TestStoppedContainerTakesItsSeriesWithIt is what makes an unbounded label
// affordable. Without retirement every container the host ever ran would leave
// a permanent series holding the memory it had when it died -- which is exactly
// why this module reported only a rollup before.
func TestStoppedContainerTakesItsSeriesWithIt(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)

	m.emitPerContainer(h, []sample{
		{ShortID: "staying", Runtime: "docker", MemoryBytes: 1024, CPUUtil: 0.1},
		{ShortID: "leaving", Runtime: "docker", MemoryBytes: 2048, CPUUtil: 0.2},
	})
	m.emitPerContainer(h, []sample{
		{ShortID: "staying", Runtime: "docker", MemoryBytes: 1024, CPUUtil: 0.1},
	})

	mem := seriesFor(tel, MetricInstanceMemory)
	if _, gone := mem["leaving"]; gone {
		t.Error("a stopped container still reports the memory it had when it died")
	}
	if _, ok := mem["staying"]; !ok {
		t.Error("the running container was retired too")
	}
	if cpu := seriesFor(tel, MetricInstanceCPU); len(cpu) != 1 {
		t.Errorf("cpu series = %d, want only the running container", len(cpu))
	}
}

func TestChurnDoesNotAccumulateSeries(t *testing.T) {
	// A host restarting a container in a crash loop gives every restart a new
	// ID. The live set is what must stay bounded, not the historical one.
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)

	for i := 0; i < 40; i++ {
		m.emitPerContainer(h, []sample{
			{ShortID: "restart-" + itoa(i), Runtime: "docker", MemoryBytes: 512, CPUUtil: 0.1},
		})
	}
	if n := len(seriesFor(tel, MetricInstanceMemory)); n != 1 {
		t.Errorf("memory series = %d after 40 restarts, want 1", n)
	}
}

func TestUnknownCPUIsAbsentNotZero(t *testing.T) {
	// A container whose CPU could not be read must not report 0%, which reads
	// as idle rather than as unknown.
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)

	m.emitPerContainer(h, []sample{
		{ShortID: "nocpu", Runtime: "docker", MemoryBytes: 900, CPUUtil: -1},
	})
	if cpu := seriesFor(tel, MetricInstanceCPU); len(cpu) != 0 {
		t.Errorf("cpu = %v, want no series when utilisation is unknown", cpu)
	}
	if mem := seriesFor(tel, MetricInstanceMemory); mem["nocpu"] != 900 {
		t.Error("memory was dropped along with the unknown CPU")
	}
}

func TestContainerWithNoIDIsSkipped(t *testing.T) {
	// An empty ID would key every such container to the same series.
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)

	m.emitPerContainer(h, []sample{
		{ShortID: "", Runtime: "docker", MemoryBytes: 1},
		{ShortID: "", Runtime: "docker", MemoryBytes: 2},
	})
	if n := len(seriesFor(tel, MetricInstanceMemory)); n != 0 {
		t.Errorf("series = %d, want none: an empty ID is not a key", n)
	}
}

func TestPerContainerCanBeTurnedOff(t *testing.T) {
	if !DefaultSettings().PerContainer {
		t.Error("per-container metrics are off by default; the rollup alone " +
			"cannot say which container is using the memory")
	}
	s, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"per_container": "false"}})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if s.PerContainer {
		t.Error("per_container=false was ignored")
	}
	if _, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"per_containers": "true"}}); err == nil {
		t.Error("a misspelled setting was accepted")
	}
}

func TestRetirementIsBestEffort(t *testing.T) {
	// A telemetry adapter that cannot forget a series is untidy, not broken.
	m := &Module{}
	m.settings = DefaultSettings()
	h := module.Host{Telemetry: noRetire{inproc.NewTelemetry()}}
	m.emitPerContainer(h, []sample{{ShortID: "a", MemoryBytes: 1, CPUUtil: 0.1}})
	m.emitPerContainer(h, nil) // must not panic
}

type noRetire struct{ inner *inproc.Telemetry }

func (n noRetire) Counter(name string) platform.Counter     { return n.inner.Counter(name) }
func (n noRetire) Gauge(name string) platform.Gauge         { return n.inner.Gauge(name) }
func (n noRetire) Histogram(name string) platform.Histogram { return n.inner.Histogram(name) }
func (n noRetire) Emit(ev platform.Event)                   { n.inner.Emit(ev) }
func (n noRetire) EmitLog(rec platform.LogRecord)           { n.inner.EmitLog(rec) }
func (n noRetire) IngestTraces(tp platform.TracePayload)    { n.inner.IngestTraces(tp) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
