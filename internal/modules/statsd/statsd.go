// Package statsd is an optional UDP StatsD receiver.
//
// It accepts the common StatsD wire format (counters, gauges, timers) plus
// optional Datadog-style #tags, and maps them onto the Telemetry port. Listen
// defaults to off (empty); operators must set listen explicitly.
package statsd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	ID      module.ID = "statsd"
	Version           = "1.0.0"
)

const PermissionReceive platform.Permission = "statsd:receive"

const (
	defaultMaxPacket = 8192
	MetricAccepted   = "statsd.packets.accepted"
	MetricDropped    = "statsd.packets.dropped"
)

// Settings is decoded from module settings. Empty Listen disables the module
// at Start (returns a soft no-op healthy state).
type Settings struct {
	Listen    string
	MaxPacket int
}

func DefaultSettings() Settings {
	return Settings{Listen: "", MaxPacket: defaultMaxPacket}
}

func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	for k := range mc.Settings {
		switch k {
		case "listen", "max.packet_bytes":
		default:
			return Settings{}, fmt.Errorf("statsd: unknown setting %q", k)
		}
	}
	if v, ok := mc.Settings["listen"]; ok {
		v = strings.TrimSpace(v)
		if v != "" {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return Settings{}, fmt.Errorf("statsd: listen: %w", err)
			}
		}
		s.Listen = v
	}
	if v, ok := mc.Settings["max.packet_bytes"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return Settings{}, fmt.Errorf("statsd: max.packet_bytes must be a positive integer")
		}
		s.MaxPacket = n
	}
	return s, nil
}

// Module receives StatsD UDP datagrams.
type Module struct {
	mu       sync.RWMutex
	settings Settings
	started  bool
	accepted atomic.Int64
	dropped  atomic.Int64

	host   module.Host
	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan struct{}
}

func New() *Module { return &Module{settings: DefaultSettings()} }

func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryProcessing,
		Description: "Optional StatsD UDP ingest",
		Permissions: []platform.Permission{PermissionReceive},
		Priority:    module.PriorityLow,
	}
}

func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}
	if settings.Listen == "" {
		m.mu.Lock()
		m.settings = settings
		m.host = h
		m.started = true
		m.done = make(chan struct{})
		close(m.done) // idle
		m.mu.Unlock()
		return nil
	}
	if err := h.Authorize(ctx, PermissionReceive); err != nil {
		return fmt.Errorf("statsd: authorization refused: %w", err)
	}
	addr, err := net.ResolveUDPAddr("udp", settings.Listen)
	if err != nil {
		return fmt.Errorf("statsd: resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("statsd: listen %s: %w", settings.Listen, err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		_ = conn.Close()
		return errors.New("statsd: already started")
	}
	m.settings = settings
	m.host = h
	m.conn = conn
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
	conn := m.conn
	done := m.done
	m.started = false
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
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
	listen := m.settings.Listen
	m.mu.RUnlock()
	if listen == "" {
		return health.OK("disabled (set listen to enable)")
	}
	return health.OK(fmt.Sprintf("listening udp %s accepted=%d dropped=%d", listen, m.accepted.Load(), m.dropped.Load()))
}

func (m *Module) loop(ctx context.Context) {
	defer close(m.done)
	m.mu.RLock()
	conn := m.conn
	max := m.settings.MaxPacket
	tel := m.host.Telemetry
	m.mu.RUnlock()
	buf := make([]byte, max)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.dropped.Add(1)
				if tel != nil {
					tel.Counter(MetricDropped).Add(1)
				}
				continue
			}
		}
		if !applyPacket(tel, string(buf[:n])) {
			m.dropped.Add(1)
			if tel != nil {
				tel.Counter(MetricDropped).Add(1)
			}
			continue
		}
		m.accepted.Add(1)
		if tel != nil {
			tel.Counter(MetricAccepted).Add(1)
		}
	}
}

// applyPacket parses one or more newline-separated StatsD lines.
func applyPacket(tel platform.Telemetry, packet string) bool {
	if tel == nil {
		return false
	}
	ok := false
	for _, line := range strings.Split(packet, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if applyLine(tel, line) {
			ok = true
		}
	}
	return ok
}

func applyLine(tel platform.Telemetry, line string) bool {
	// name:value|type[|@rate][#tag:val,...]
	main, tagsPart, _ := strings.Cut(line, "#")
	parts := strings.Split(main, "|")
	if len(parts) < 2 {
		return false
	}
	nv := strings.SplitN(parts[0], ":", 2)
	if len(nv) != 2 {
		return false
	}
	name := strings.TrimSpace(nv[0])
	if name == "" || strings.ContainsAny(name, " \t") {
		return false
	}
	val, err := strconv.ParseFloat(strings.TrimSpace(nv[1]), 64)
	if err != nil {
		return false
	}
	typ := strings.TrimSpace(parts[1])
	attrs := parseTags(tagsPart)
	switch typ {
	case "c":
		tel.Counter(name).Add(int64(val), attrs...)
	case "g":
		tel.Gauge(name).Set(val, attrs...)
	case "ms", "h":
		tel.Histogram(name).Observe(val, attrs...)
	default:
		return false
	}
	return true
}

func parseTags(s string) []platform.Attr {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []platform.Attr
	for i, part := range strings.Split(s, ",") {
		if i >= 8 {
			break
		}
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			k, v = part, "true"
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out = append(out, platform.A(k, strings.TrimSpace(v)))
	}
	return out
}

var _ module.Module = (*Module)(nil)
