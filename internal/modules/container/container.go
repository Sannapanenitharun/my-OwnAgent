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
	MetricCycleOK        = "container.cycle.success"
	MetricCycleFail      = "container.cycle.failure"
)

// Module reads cgroup metrics for containers discovered on this host.
type Module struct {
	mu       sync.RWMutex
	settings Settings
	started  bool
	lastOK   time.Time
	lastErr  string
	cycles   int64

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
	h.Telemetry.Counter(MetricCycleOK).Add(1)
	m.mu.Lock()
	m.cycles++
	m.lastOK = time.Now()
	m.lastErr = ""
	m.mu.Unlock()
}

var _ module.Module = (*Module)(nil)
