// Package otelengine is the agent's OTLP/HTTP receiver.
//
// Instrumented applications on the same host send traces (and optionally logs
// and metrics) to 127.0.0.1:4318. The module enriches nothing itself: it
// forwards bounded payloads through the Telemetry port, and the OTLP adapter
// attaches host resource attributes. gRPC :4317 and eBPF auto-instrumentation
// are out of scope.
package otelengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	ID      module.ID = "otel-engine"
	Version           = "1.0.0"
)

const PermissionReceive platform.Permission = "otel:receive"

// Listener counts. Two gauges rather than one, because "bound 11" only means
// something next to "configured 12" -- the gap is the alert, and a single
// number cannot express it.
const (
	MetricListenersBound      = "otel.receiver.listeners_bound"
	MetricListenersConfigured = "otel.receiver.listeners_configured"
)

const (
	defaultListen   = "127.0.0.1:4318"
	defaultMaxBody  = 4 << 20
	defaultMaxQueue = 256
)

// Settings is decoded from module settings. Unknown keys are rejected.
type Settings struct {
	// Listen is one or more comma-separated host:port addresses.
	//
	// More than one, because of where the senders are. A container on a
	// user-defined Docker network cannot route to the host's loopback, and it
	// cannot route to another network's bridge gateway either -- each network
	// reaches the host only at its OWN gateway address. A host running six
	// bridges therefore has six private addresses its containers can reach,
	// and a single listener serves at most one of them.
	//
	// The alternative is 0.0.0.0, and that is the thing to avoid: this
	// receiver takes unauthenticated OTLP, so on any host whose firewall
	// permits the port it would accept spans, metrics and logs from the
	// internet. Binding the specific private addresses reaches every container
	// while remaining unroutable from outside.
	Listen   []string
	MaxBody  int
	MaxQueue int
}

func DefaultSettings() Settings {
	return Settings{Listen: []string{defaultListen}, MaxBody: defaultMaxBody, MaxQueue: defaultMaxQueue}
}

func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	for k := range mc.Settings {
		switch k {
		case "listen", "max.body_bytes", "max.queue":
		default:
			return Settings{}, fmt.Errorf("otel-engine: unknown setting %q", k)
		}
	}
	if v, ok := mc.Settings["listen"]; ok {
		addrs := make([]string, 0, 4)
		seen := map[string]bool{}
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(part); err != nil {
				return Settings{}, fmt.Errorf("otel-engine: listen %q: %w", part, err)
			}
			// A repeated address would fail to bind the second time and take
			// the module down over a typo in a list.
			if seen[part] {
				continue
			}
			seen[part] = true
			addrs = append(addrs, part)
		}
		if len(addrs) == 0 {
			return Settings{}, fmt.Errorf("otel-engine: listen must not be empty")
		}
		s.Listen = addrs
	}
	if v, ok := mc.Settings["max.body_bytes"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Settings{}, fmt.Errorf("otel-engine: max.body_bytes must be a positive integer")
		}
		s.MaxBody = n
	}
	if v, ok := mc.Settings["max.queue"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Settings{}, fmt.Errorf("otel-engine: max.queue must be a positive integer")
		}
		s.MaxQueue = n
	}
	return s, nil
}

// Module receives OTLP/HTTP from local applications.
type Module struct {
	mu       sync.RWMutex
	settings Settings
	staged   *Settings
	started  bool
	accepted int64
	dropped  int64
	inflight atomic.Int64

	host module.Host
	srv  *http.Server
	lns  []net.Listener

	cancel context.CancelFunc
	done   chan struct{}
}

func New() *Module { return &Module{settings: DefaultSettings()} }

func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryProcessing,
		Description: "OTLP/HTTP receiver for application traces, logs and metrics",
		Permissions: []platform.Permission{PermissionReceive},
		Priority:    module.PriorityHigh,
	}
}

func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}
	if err := h.Authorize(ctx, PermissionReceive); err != nil {
		return fmt.Errorf("otel-engine: authorization refused: %w", err)
	}

	// Bind what can be bound, and report what could not.
	//
	// This used to be all-or-nothing, on the reasoning that a partial bind
	// leaves the receiver reachable from some networks and not others, and the
	// containers that could not reach it would look like containers that are
	// not instrumented. The reasoning was right and the remedy was wrong. The
	// addresses here are Docker bridge gateways, and those come and go: a
	// network is removed, or has not been recreated yet at boot. One absent
	// address then took the whole receiver down -- so instead of some
	// containers being unable to reach it, EVERY container was, and the module
	// crash-looped until it exhausted its restart budget and stayed dead.
	//
	// Refusing to serve eleven working addresses because a twelfth is gone is
	// not caution. What the original concern actually needs is visibility, so
	// every failure raises a diagnostic naming the address and the count of
	// bound addresses is published as a metric. An operator can then see
	// "11 of 12" rather than either silence or an outage.
	lns := make([]net.Listener, 0, len(settings.Listen))
	var failed []string
	for _, addr := range settings.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			failed = append(failed, addr)
			h.Diagnostics.Record(diagnostics.Record{
				Code:     diagnostics.CodeDependencyUnavailable,
				Severity: diagnostics.Warn,
				Message:  "OTLP receiver could not bind " + addr,
				Remediation: "the address is usually a Docker bridge gateway; " +
					"remove it from otel-engine listen if the network is gone, " +
					"or containers on other networks will still be served",
				Attrs: map[string]string{"addr": addr, "error": err.Error()},
			})
			h.Logger.Warn("otlp http receiver could not bind", "addr", addr, "error", err)
			continue
		}
		lns = append(lns, ln)
	}
	// Nothing bound is a real failure: there is no receiver at all.
	if len(lns) == 0 {
		return fmt.Errorf("otel-engine: no listen address could be bound (tried %d): %s",
			len(settings.Listen), strings.Join(failed, ", "))
	}
	h.Telemetry.Gauge(MetricListenersBound).Set(float64(len(lns)))
	h.Telemetry.Gauge(MetricListenersConfigured).Set(float64(len(settings.Listen)))

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
		return errors.New("otel-engine: already started")
	}
	m.settings = settings
	m.host = h
	m.lns = lns
	m.started = true
	m.done = make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", m.handle("traces"))
	mux.HandleFunc("/v1/logs", m.handle("logs"))
	mux.HandleFunc("/v1/metrics", m.handle("metrics"))
	m.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	m.mu.Unlock()

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()

	// One goroutine per listener, all serving the same mux. done closes when
	// the last of them returns, so Stop waits for all of them.
	//
	// srv and done are captured here rather than read from the module inside
	// the goroutines. Stop sets m.srv to nil, and a goroutine that had not yet
	// been scheduled would then call Serve on a nil server and panic -- a race
	// that needs only a Start immediately followed by a Stop, which is exactly
	// what a failing start and a test both do.
	srv, done := m.srv, m.done
	var wg sync.WaitGroup
	for _, ln := range lns {
		h.Logger.Info("otlp http receiver listening", "addr", ln.Addr().String())
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			err := srv.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) && runCtx.Err() == nil {
				h.ReportFailure(err)
			}
		}(ln)
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return nil
}

func (m *Module) handle(signal string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		m.mu.RLock()
		maxBody := m.settings.MaxBody
		maxQueue := m.settings.MaxQueue
		tel := m.host.Telemetry
		m.mu.RUnlock()

		n := m.inflight.Add(1)
		defer m.inflight.Add(-1)
		if int(n) > maxQueue {
			m.mu.Lock()
			m.dropped++
			m.mu.Unlock()
			tel.Counter("otel.receiver.dropped").Add(1, platform.A("signal", signal), platform.A("reason", "queue"))
			m.host.Diagnostics.Record(diagnostics.Record{
				Code:        diagnostics.CodeDropped,
				Severity:    diagnostics.Warn,
				Message:     "OTLP receiver queue is full; payload dropped",
				Remediation: "raise otel-engine max.queue or reduce application export rate",
				Attrs:       map[string]string{"signal": signal},
			})
			http.Error(w, "queue full", http.StatusTooManyRequests)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBody)+1))
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if len(body) > maxBody {
			m.mu.Lock()
			m.dropped++
			m.mu.Unlock()
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		tel.IngestTraces(platform.TracePayload{
			ContentType: r.Header.Get("Content-Type"),
			Body:        body,
			Signal:      signal,
		})
		m.mu.Lock()
		m.accepted++
		m.mu.Unlock()
		tel.Counter("otel.receiver.accepted").Add(1, platform.A("signal", signal))
		w.WriteHeader(http.StatusOK)
	}
}

func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	srv := m.srv
	cancel := m.cancel
	done := m.done
	m.srv = nil
	m.cancel = nil
	m.started = false
	m.mu.Unlock()
	if srv == nil {
		return nil
	}
	if cancel != nil {
		cancel()
	}
	_ = srv.Shutdown(ctx)
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.started {
		return health.UnhealthyReport("receiver is not listening")
	}
	if m.dropped > 0 {
		return health.DegradedReport(fmt.Sprintf("receiver dropped %d payloads to the queue bound", m.dropped))
	}
	return health.OK("OTLP/HTTP receiver is listening on " + strings.Join(m.settings.Listen, ", "))
}

func (m *Module) PrepareConfig(_ context.Context, mc config.ModuleConfig) error {
	s, err := ParseSettings(mc)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := s
	m.staged = &staged
	return nil
}

func (m *Module) CommitConfig(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.staged == nil {
		return nil
	}
	// Listen address changes require a restart; keep the live listener and
	// apply body/queue bounds immediately.
	m.settings.MaxBody = m.staged.MaxBody
	m.settings.MaxQueue = m.staged.MaxQueue
	m.staged = nil
	return nil
}

func (m *Module) RollbackConfig(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged = nil
	return nil
}

func (m *Module) Throttle(context.Context, module.PressureLevel) error { return nil }

var (
	_ module.Module       = (*Module)(nil)
	_ module.Configurable = (*Module)(nil)
	_ module.Throttleable = (*Module)(nil)
)
