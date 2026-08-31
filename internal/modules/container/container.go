// Package container collects Linux cgroup-backed container CPU and memory
// gauges. It never opens a container runtime socket (Docker socket is
// root-equivalent). Per-container series are avoided on purpose: IDs are
// unbounded; discovery already carries inventory on the event path. This
// module emits rollups keyed only by runtime (closed set).
package container

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	ID      module.ID = "container"
	Version           = "1.0.0"
)

const PermissionRead platform.Permission = "container:read"

const (
	MetricRunning        = "container.running"
	MetricMemoryUsage    = "container.memory.usage_bytes"
	MetricCPUUtilization = "container.cpu.utilization"
	// AttrContainerID keys the per-container series. It is the same short ID
	// the log lines carry, so the view joins both to a name the same way.
	AttrContainerID = "container_id"

	// The per-container series get their OWN names rather than adding a
	// container_id label to the rollup. Two series under one name where one is
	// the sum of the others is a footgun: anything that aggregates the metric
	// without inspecting label sets counts every container twice. Renaming the
	// rollup instead was not an option -- metric names are an operator-facing
	// contract, and runbooks key off them.
	MetricInstanceMemory = "container.instance.memory_bytes"
	MetricInstanceCPU    = "container.instance.cpu_utilization"

	// Network is cumulative, so these are counters rather than gauges. The
	// kernel's interface counters restart when a container does, and a
	// counter is the shape that says "this many bytes since I started
	// watching" without a restart reading as negative traffic.
	MetricInstanceNetRx = "container.instance.network.rx_bytes"
	MetricInstanceNetTx = "container.instance.network.tx_bytes"

	MetricCycleOK   = "container.cycle.success"
	MetricCycleFail = "container.cycle.failure"
)

// Module reads cgroup metrics for containers discovered on this host.
type Module struct {
	mu       sync.RWMutex
	settings Settings
	started  bool
	lastOK   time.Time

	// emittedIDs is the set of containers whose series were set last cycle,
	// so the ones that have since stopped can be withdrawn.
	emittedIDs map[string]struct{}
	// lastNet holds the previous cumulative interface counters per container,
	// which is what turns them into per-cycle traffic. Entries are dropped
	// when the container's series are retired.
	lastNet map[string]netCounters
	lastErr string
	cycles  int64

	host   module.Host
	cancel context.CancelFunc
	done   chan struct{}
}

func New() *Module { return &Module{settings: DefaultSettings()} }

func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryCollector,
		Description: "Linux container CPU/memory rollups from cgroups (no runtime socket)",
		Permissions: []platform.Permission{PermissionRead},
		Priority:    module.PriorityNormal,
	}
}

func (m *Module) Start(ctx context.Context, h module.Host) error {
	if !supported() {
		return module.ErrUnsupported
	}
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}
	if err := h.Authorize(ctx, PermissionRead); err != nil {
		return fmt.Errorf("container: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("container: already started")
	}
	m.settings = settings
	m.host = h
	m.started = true
	runCtx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.mu.Unlock()

	go m.loop(runCtx)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return nil
	}
	cancel := m.cancel
	done := m.done
	m.started = false
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Module) Health(_ context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !supported() {
		return health.DegradedReport("container metrics unavailable on this platform")
	}
	if m.lastErr != "" && time.Since(m.lastOK) > 2*m.settings.Interval {
		return health.DegradedReport(m.lastErr)
	}
	return health.OK("collecting")
}

func (m *Module) loop(ctx context.Context) {
	defer close(m.done)
	t := time.NewTicker(m.settings.Interval)
	defer t.Stop()
	m.collect()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.collect()
		}
	}
}

func (m *Module) collect() {
	m.mu.RLock()
	h := m.host
	max := m.settings.Max
	perContainer := m.settings.PerContainer
	m.mu.RUnlock()
	if h.Telemetry == nil {
		return
	}
	samples, err := readSamples(max)
	if err != nil {
		h.Telemetry.Counter(MetricCycleFail).Add(1)
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		return
	}
	type agg struct {
		n, mem int64
		cpuSum float64
		cpuN   int
	}
	by := map[string]*agg{}
	for _, s := range samples {
		a := by[s.Runtime]
		if a == nil {
			a = &agg{}
			by[s.Runtime] = a
		}
		a.n++
		a.mem += s.MemoryBytes
		if s.CPUUtil >= 0 {
			a.cpuSum += s.CPUUtil
			a.cpuN++
		}
	}
	if len(by) == 0 {
		h.Telemetry.Gauge(MetricRunning).Set(0, platform.A("runtime", "none"))
	}
	for rt, a := range by {
		attr := platform.A("runtime", rt)
		h.Telemetry.Gauge(MetricRunning).Set(float64(a.n), attr)
		h.Telemetry.Gauge(MetricMemoryUsage).Set(float64(a.mem), attr)
		if a.cpuN > 0 {
			h.Telemetry.Gauge(MetricCPUUtilization).Set(a.cpuSum/float64(a.cpuN), attr)
		}
	}
	if perContainer {
		m.emitPerContainer(h, samples)
	}
	h.Telemetry.Counter(MetricCycleOK).Add(1)
	m.mu.Lock()
	m.cycles++
	m.lastOK = time.Now()
	m.lastErr = ""
	m.mu.Unlock()
}

var _ module.Module = (*Module)(nil)

// emitPerContainer publishes CPU and memory for each container and withdraws
// the series of any container that is no longer running.
//
// The retirement is what makes this affordable. A container ID is unbounded,
// so without it every container the host ever ran would leave a permanent
// series holding the memory it had when it died -- which is exactly why this
// module reported only a runtime rollup until now.
func (m *Module) emitPerContainer(h module.Host, samples []sample) {
	current := make(map[string]struct{}, len(samples))
	mem := h.Telemetry.Gauge(MetricInstanceMemory)
	cpu := h.Telemetry.Gauge(MetricInstanceCPU)

	for _, s := range samples {
		if s.ShortID == "" {
			continue
		}
		current[s.ShortID] = struct{}{}
		attr := platform.A(AttrContainerID, s.ShortID)
		mem.Set(float64(s.MemoryBytes), attr)
		if s.CPUUtil >= 0 {
			cpu.Set(s.CPUUtil, attr)
		}
		m.emitNetDelta(h, s, attr)
	}

	m.mu.Lock()
	previous := m.emittedIDs
	m.emittedIDs = current
	m.mu.Unlock()

	for id := range previous {
		if _, still := current[id]; still {
			continue
		}
		attr := platform.A(AttrContainerID, id)
		platform.RetireSeries(h.Telemetry, MetricInstanceMemory, attr)
		platform.RetireSeries(h.Telemetry, MetricInstanceCPU, attr)
		platform.RetireSeries(h.Telemetry, MetricInstanceNetRx, attr)
		platform.RetireSeries(h.Telemetry, MetricInstanceNetTx, attr)

		m.mu.Lock()
		delete(m.lastNet, id)
		m.mu.Unlock()
	}
}

// emitNetDelta publishes the traffic since the previous cycle.
//
// The kernel counter is cumulative within one network namespace, and a
// container that restarts gets a new namespace starting from zero. A drop
// below the previous reading is therefore a restart, not negative traffic:
// the correct response is to re-baseline and publish nothing for that cycle,
// because the bytes between the two readings were sent by a container that no
// longer exists.
func (m *Module) emitNetDelta(h module.Host, s sample, attr platform.Attr) {
	if !s.Net.OK {
		// Host-networked, or no readable process. Absent rather than zero:
		// zero would claim the container sent nothing, which is a measurement
		// this module did not make.
		return
	}
	m.mu.Lock()
	if m.lastNet == nil {
		m.lastNet = map[string]netCounters{}
	}
	prev, seen := m.lastNet[s.ShortID]
	m.lastNet[s.ShortID] = s.Net
	m.mu.Unlock()

	if !seen {
		// First sighting establishes the baseline. Publishing the counter's
		// absolute value here would report the container's whole lifetime as
		// one cycle's traffic.
		return
	}
	if s.Net.RxBytes >= prev.RxBytes {
		h.Telemetry.Counter(MetricInstanceNetRx).Add(int64(s.Net.RxBytes-prev.RxBytes), attr)
	}
	if s.Net.TxBytes >= prev.TxBytes {
		h.Telemetry.Counter(MetricInstanceNetTx).Add(int64(s.Net.TxBytes-prev.TxBytes), attr)
	}
}
