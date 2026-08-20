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

const (
	defaultListen   = "127.0.0.1:4318"
	defaultMaxBody  = 4 << 20
	defaultMaxQueue = 256
)

// Settings is decoded from module settings. Unknown keys are rejected.
type Settings struct {
	Listen   string
	MaxBody  int
	MaxQueue int
}

func DefaultSettings() Settings {
	return Settings{Listen: defaultListen, MaxBody: defaultMaxBody, MaxQueue: defaultMaxQueue}
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
		v = strings.TrimSpace(v)
		if v == "" {
			return Settings{}, fmt.Errorf("otel-engine: listen must not be empty")
		}
		if _, _, err := net.SplitHostPort(v); err != nil {
			return Settings{}, fmt.Errorf("otel-engine: listen: %w", err)
		}
		s.Listen = v
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
	ln   net.Listener

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

	ln, err := net.Listen("tcp", settings.Listen)
	if err != nil {
		return fmt.Errorf("otel-engine: listen %s: %w", settings.Listen, err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		_ = ln.Close()
		return errors.New("otel-engine: already started")
	}
	m.settings = settings
	m.host = h
	m.ln = ln
	m.started = true
	m.done = make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", m.handle("traces"))
	mux.HandleFunc("/v1/logs", m.handle("logs"))
	mux.HandleFunc("/v1/metrics", m.handle("metrics"))
	m.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	m.mu.Unlock()

	h.Logger.Info("otlp http receiver listening", "addr", ln.Addr().String())

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	go func() {
		defer close(m.done)
		err := m.srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && runCtx.Err() == nil {
			h.ReportFailure(err)
		}
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
	return health.OK("OTLP/HTTP receiver is listening on " + m.settings.Listen)
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
