// Package logs is the log collector: file tails, systemd journald on Linux,
// and the Windows Event Log. Bodies are truncated and redacted before they
// reach the Telemetry port. A source a platform cannot provide is absent,
// not empty.
package logs

import (
	"context"
	"errors"
	"fmt"
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
	ID      module.ID = "logs"
	Version           = "1.0.0"
)

const PermissionRead platform.Permission = "logs:read"

const maxEffectiveInterval = 5 * time.Minute

// Module collects host logs.
type Module struct {
	set Set

	mu       sync.RWMutex
	settings Settings
	staged   *Settings
	pressure module.PressureLevel
	started  bool
	status   map[Source]*sourceStatus
	entityID string

	host module.Host
	inst *instruments

	cancel      context.CancelFunc
	done        chan struct{}
	reconfigure chan struct{}
}

type sourceStatus struct {
	available   bool
	reason      string
	successes   int64
	failures    int64
	lines       int64
	dropped     int64
	lastSuccess time.Time
	lastErr     string
}

type instruments struct {
	lines, dropped, redacted, truncated, success, failure platform.Counter
	duration                                              platform.Histogram
	health                                                platform.Gauge
	tel                                                   platform.Telemetry
}

func newInstruments(t platform.Telemetry) *instruments {
	return &instruments{
		lines:     t.Counter(MetricLines),
		dropped:   t.Counter(MetricDropped),
		redacted:  t.Counter(MetricRedacted),
		truncated: t.Counter(MetricTruncated),
		success:   t.Counter(MetricCollectionSuccess),
		failure:   t.Counter(MetricCollectionFailure),
		duration:  t.Histogram(MetricCollectionDuration),
		health:    t.Gauge(MetricModuleHealth),
		tel:       t,
	}
}

func New() *Module { return NewWithSet(platformSet()) }

func NewWithSet(set Set) *Module {
	m := &Module{set: set, settings: DefaultSettings(), status: map[Source]*sourceStatus{}}
	for _, src := range AllSources {
		st := &sourceStatus{available: set.Has(src)}
		if !st.available {
			for _, u := range set.Unsupported {
				if u.Source == src {
					st.reason = u.Reason
				}
			}
		}
		m.status[src] = st
	}
	return m
}

func (m *Module) Manifest() module.Manifest {
	return module.Manifest{
		ID:          ID,
		Version:     Version,
		Category:    module.CategoryCollector,
		Description: "host logs: files, journald, Windows Event Log",
		Permissions: []platform.Permission{PermissionRead},
		Priority:    module.PriorityNormal,
	}
}

func (m *Module) Start(ctx context.Context, h module.Host) error {
	settings, err := ParseSettings(h.Config)
	if err != nil {
		return err
	}
	if m.collectableCount(settings) == 0 {
		return module.Unsupported("no log sources are available on this platform")
	}
	if err := h.Authorize(ctx, PermissionRead); err != nil {
		return fmt.Errorf("logs: authorization refused: %w", err)
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("logs: already started")
	}
	m.settings = settings
	m.host = h
	m.inst = newInstruments(h.Telemetry)
	m.started = true
	m.reconfigure = make(chan struct{}, 1)
	m.done = make(chan struct{})
	m.mu.Unlock()

	m.resolveEntity(ctx)
	m.recordUnsupported()

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	go m.run(runCtx)
	return nil
}

func (m *Module) collectableCount(s Settings) int {
	n := 0
	for _, src := range AllSources {
		if m.set.Has(src) && !s.DisabledSources[src] {
			n++
		}
	}
	return n
}

func (m *Module) resolveEntity(ctx context.Context) {
	id, err := m.host.Identity.HostID(ctx)
	if err != nil {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnresolvedIdentity,
			Severity:    diagnostics.Warn,
			Message:     "host entity ID could not be resolved; log records are emitted without entity binding",
			Remediation: "verify platform identity configuration",
		})
		return
	}
	m.mu.Lock()
	m.entityID = id
	m.mu.Unlock()
}

func (m *Module) recordUnsupported() {
	for _, u := range m.set.Unsupported {
		m.host.Diagnostics.Record(diagnostics.Record{
			Code:        diagnostics.CodeUnsupported,
			Severity:    diagnostics.Warn,
			Message:     u.Reason,
			Remediation: "no action required; this source is unavailable in this environment",
			Attrs:       map[string]string{AttrSource: u.Source.String()},
		})
	}
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
		return fmt.Errorf("logs: collection goroutine did not exit: %w", ctx.Err())
	}
}

func (m *Module) run(ctx context.Context) {
	defer close(m.done)
	clock := m.host.Clock
	due := make(map[Source]time.Time)
	now := clock.Now()
	for _, src := range m.collectable() {
		due[src] = now
	}
	for {
		now = clock.Now()
		for _, src := range m.collectable() {
			at, ok := due[src]
			if !ok || !at.After(now) {
				m.collect(ctx, src)
				due[src] = now.Add(m.effectiveInterval())
			}
		}
		wait := m.timeUntilNext(due, clock.Now())
		select {
		case <-ctx.Done():
			return
		case <-clock.After(wait):
		case <-m.reconfigure:
			for src := range due {
				due[src] = clock.Now()
			}
		}
	}
}

func (m *Module) collectable() []Source {
	m.mu.RLock()
	disabled := m.settings.DisabledSources
	m.mu.RUnlock()
	var out []Source
	for _, src := range AllSources {
		if m.set.Has(src) && !disabled[src] {
			out = append(out, src)
		}
	}
	return out
}

func (m *Module) timeUntilNext(due map[Source]time.Time, now time.Time) time.Duration {
	next := time.Duration(-1)
	for _, src := range m.collectable() {
		at, ok := due[src]
		if !ok {
			return 0
		}
		d := at.Sub(now)
		if d < 0 {
			d = 0
		}
		if next < 0 || d < next {
			next = d
		}
	}
	if next < 0 {
		return time.Minute
	}
	return next
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
	if d < 200*time.Millisecond {
		d = 200 * time.Millisecond
	}
	return d
}

func (m *Module) collect(ctx context.Context, src Source) {
	begin := m.host.Clock.Now()
	m.mu.RLock()
	timeout := m.settings.CollectionTimeout
	settings := m.settings.Clone()
	entity := m.entityID
	m.mu.RUnlock()

	rdr := m.set.Reader(src)
	if rdr == nil {
		return
	}
	var recs []Record
	err, _ := guard.Call(ctx, timeout, func(cctx context.Context) error {
		var e error
		recs, e = rdr.Read(cctx, settings)
		return e
	})
	srcAttr := platform.A(AttrSource, src.String())
	m.inst.duration.Observe(m.host.Clock.Now().Sub(begin).Seconds(), srcAttr)

	m.mu.Lock()
	st := m.status[src]
	if err != nil {
		st.failures++
		st.lastErr = err.Error()
		m.mu.Unlock()
		m.inst.failure.Add(1, srcAttr)
		return
	}
	st.successes++
	st.lastSuccess = m.host.Clock.Now()
	st.lastErr = ""
	m.mu.Unlock()
	m.inst.success.Add(1, srcAttr)

	emitted := m.emit(recs, settings, entity)
	m.mu.Lock()
	m.status[src].lines += int64(emitted)
	m.mu.Unlock()
}

func (m *Module) emit(recs []Record, s Settings, entity string) int {
	n := 0
	for _, rec := range recs {
		body, truncated := Truncate(rec.Body, s.MaxLineBytes)
		redacted := Redact(body)
		srcAttr := platform.A(AttrSource, rec.Source.String())
		if truncated {
			m.inst.truncated.Add(1, srcAttr)
		}
		if redacted != body {
			m.inst.redacted.Add(1, srcAttr)
		}
		attrs := []platform.Attr{srcAttr}
		if rec.File != "" {
			attrs = append(attrs, platform.A("file", rec.File))
		}
		if rec.Channel != "" {
			attrs = append(attrs, platform.A("channel", rec.Channel))
		}
		if entity != "" {
			attrs = append(attrs, platform.A("entity.id", entity))
		}
		m.inst.tel.EmitLog(platform.LogRecord{
			Timestamp: m.host.Clock.Now(),
			Severity:  platform.SeverityInfo,
			Body:      redacted,
			Attrs:     attrs,
		})
		m.inst.lines.Add(1, srcAttr)
		n++
	}
	return n
}

func (m *Module) Health(context.Context) health.Report {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var available, succeeding, failing int
	for _, src := range AllSources {
		st := m.status[src]
		if !st.available {
			continue
		}
		available++
		if st.failures > 0 && st.lastErr != "" {
			failing++
		} else if !st.lastSuccess.IsZero() || st.successes > 0 {
			succeeding++
		}
	}
	switch {
	case available == 0:
		return health.UnhealthyReport("no log sources are available")
	case succeeding == 0 && failing > 0:
		return health.UnhealthyReport("every available log source is failing")
	case failing > 0:
		return health.DegradedReport(fmt.Sprintf("%d log sources are failing", failing))
	case available < len(AllSources):
		return health.DegradedReport(fmt.Sprintf("%d of %d log sources are unavailable on this platform", len(AllSources)-available, len(AllSources)))
	case m.entityID == "":
		return health.DegradedReport("host entity ID is unresolved")
	default:
		return health.OK("log sources are collecting")
	}
}

func (m *Module) PrepareConfig(_ context.Context, mc config.ModuleConfig) error {
	s, err := ParseSettings(mc)
	if err != nil {
		return err
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
