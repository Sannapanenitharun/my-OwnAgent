// Package httpcheck is an agent collector that probes configured HTTP
// endpoints and emits up / latency gauges through the Telemetry port.
//
// It is the smallest example of a custom data collector on this agent: one
// goroutine, bounded targets, no third-party deps, and no inventing of host
// identity.
package httpcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/guard"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	ID      module.ID = "httpcheck"
	Version           = "1.0.0"
)

const PermissionProbe platform.Permission = "httpcheck:probe"

const maxEffectiveInterval = 30 * time.Minute

// Module probes HTTP targets on a single collection goroutine.
type Module struct {
	mu       sync.RWMutex
	settings Settings
	staged   *Settings
	pressure module.PressureLevel
	started  bool
	entityID string

	host   module.Host
	client *http.Client

	successes map[string]int64
	failures  map[string]int64
	lastErr   map[string]string
	lastOK    map[string]time.Time

	cancel      context.CancelFunc
	done        chan struct{}
	reconfigure chan struct{}
}

func New() *Module {
	return &Module{
		settings:  DefaultSettings(),
		successes: map[string]int64{},
		failures:  map[string]int64{},
		lastErr:   map[string]string{},
		lastOK:    map[string]time.Time{},
	}
}

func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryCollector,
		Description: "HTTP endpoint checks: up/down and latency",
		Permissions: []platform.Permission{PermissionProbe},
		Priority:    module.PriorityLow,
	}
}

func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}
	if len(settings.Targets) == 0 {
		return module.Unsupported("no httpcheck targets configured; set modules.httpcheck.settings.targets")
	}
	if err := h.Authorize(ctx, PermissionProbe); err != nil {
		return fmt.Errorf("httpcheck: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("httpcheck: already started")
	}
	m.settings = settings
	m.host = h
	m.client = &http.Client{Timeout: settings.Timeout}
	m.started = true
	m.reconfigure = make(chan struct{}, 1)
	m.done = make(chan struct{})
	m.mu.Unlock()

	m.resolveEntity(ctx)

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	go m.run(runCtx)
	return nil
}

func (m *Module) resolveEntity(ctx context.Context) {
	id, err := m.host.Identity.HostID(ctx)
	if err != nil {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnresolvedIdentity,
			Severity:    diagnostics.Warn,
			Message:     "host entity ID could not be resolved; httpcheck metrics omit entity binding",
			Remediation: "verify platform identity configuration",
		})
		return
	}
	m.mu.Lock()
	m.entityID = id
	m.mu.Unlock()
}

func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.started = false
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("httpcheck: collection goroutine did not exit: %w", ctx.Err())
	}
}

func (m *Module) run(ctx context.Context) {
	defer close(m.done)
	clock := m.host.Clock
	for {
		m.probeAll(ctx)
		wait := m.effectiveInterval()
		select {
		case <-ctx.Done():
			return
		case <-clock.After(wait):
		case <-m.reconfigure:
		}
	}
}

func (m *Module) probeAll(ctx context.Context) {
	m.mu.RLock()
	targets := append([]Target(nil), m.settings.Targets...)
	timeout := m.settings.Timeout
	expect := m.settings.ExpectStatus
	client := m.client
	tel := m.host.Telemetry
	entity := m.entityID
	m.mu.RUnlock()

	for _, t := range targets {
		begin := m.host.Clock.Now()
		up, code, latency, err := m.probeOne(ctx, client, timeout, t.URL, expect)
		dur := m.host.Clock.Now().Sub(begin).Seconds()
		attr := platform.A(AttrTarget, t.Name)
		attrs := []platform.Attr{attr}
		if entity != "" {
			attrs = append(attrs, platform.A("entity.id", entity))
		}

		tel.Histogram(MetricCollectionDuration).Observe(dur, attr)
		tel.Gauge(MetricUp).Set(up, attrs...)
		tel.Gauge(MetricLatency).Set(latency, attrs...)
		tel.Gauge(MetricStatusCode).Set(float64(code), attrs...)

		m.mu.Lock()
		if err != nil {
			m.failures[t.Name]++
			m.lastErr[t.Name] = err.Error()
			m.mu.Unlock()
			tel.Counter(MetricCollectionFailure).Add(1, attr)
			continue
		}
		m.successes[t.Name]++
		m.lastOK[t.Name] = m.host.Clock.Now()
		m.lastErr[t.Name] = ""
		m.mu.Unlock()
		tel.Counter(MetricCollectionSuccess).Add(1, attr)
	}
}

func (m *Module) probeOne(ctx context.Context, client *http.Client, timeout time.Duration, rawURL string, expect int) (up float64, status int, latency float64, err error) {
	start := m.host.Clock.Now()
	callErr, _ := guard.Call(ctx, timeout, func(cctx context.Context) error {
		req, e := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
		if e != nil {
			return e
		}
		req.Header.Set("User-Agent", "observability-agent-httpcheck/"+Version)
		resp, e := client.Do(req)
		if e != nil {
			return e
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		status = resp.StatusCode
		if resp.StatusCode != expect {
			return fmt.Errorf("status %d, want %d", resp.StatusCode, expect)
		}
		return nil
	})
	latency = m.host.Clock.Now().Sub(start).Seconds()
	if callErr != nil {
		return 0, status, latency, callErr
	}
	return 1, status, latency, nil
}

func (m *Module) effectiveInterval() time.Duration {
	m.mu.RLock()
	base := m.settings.Interval
	p := m.pressure
	m.mu.RUnlock()
	factor := 1.0
	switch p {
	case module.PressureModerate:
		factor = 2
	case module.PressureHigh:
		factor = 4
	case module.PressureCritical:
		factor = 8
	}
	d := time.Duration(float64(base) * factor)
	if d > maxEffectiveInterval {
		d = maxEffectiveInterval
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.settings.Targets) == 0 {
		return health.UnhealthyReport("no targets configured")
	}
	var failing, ok int
	for _, t := range m.settings.Targets {
		if m.lastErr[t.Name] != "" {
			failing++
		} else if m.successes[t.Name] > 0 {
			ok++
		}
	}
	switch {
	case failing == len(m.settings.Targets) && failing > 0:
		return health.UnhealthyReport("every httpcheck target is failing")
	case failing > 0:
		return health.DegradedReport(fmt.Sprintf("%d httpcheck targets are failing", failing))
	case ok == 0:
		return health.DegradedReport("httpcheck has not completed a successful probe yet")
	case m.entityID == "":
		return health.DegradedReport("host entity ID is unresolved")
	default:
		return health.OK("httpcheck targets are reachable")
	}
}

func (m *Module) PrepareConfig(_ context.Context, mc config.ModuleConfig) error {
	s, err := ParseSettings(mc)
	if err != nil {
		return err
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("httpcheck: targets must not be empty while the module is enabled")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := s.Clone()
	m.staged = &staged
	return nil
}

func (m *Module) CommitConfig(context.Context) error {
	m.mu.Lock()
	if m.staged == nil {
		m.mu.Unlock()
		return nil
	}
	m.settings = *m.staged
	m.staged = nil
	m.client = &http.Client{Timeout: m.settings.Timeout}
	ch := m.reconfigure
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return nil
}

func (m *Module) RollbackConfig(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged = nil
	return nil
}

func (m *Module) Throttle(_ context.Context, level module.PressureLevel) error {
	m.mu.Lock()
	m.pressure = level
	m.mu.Unlock()
	return nil
}

var (
	_ module.Module       = (*Module)(nil)
	_ module.Configurable = (*Module)(nil)
	_ module.Throttleable = (*Module)(nil)
)
