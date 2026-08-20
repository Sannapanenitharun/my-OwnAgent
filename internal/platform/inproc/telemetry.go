// Package inproc provides in-process reference implementations of the platform
// ports.
//
// These exist so the agent can be built, tested and benchmarked before the
// enterprise platform adapters are wired in, and so that tests can assert on
// emitted telemetry. They are NOT a second telemetry pipeline: they terminate
// telemetry in memory and export nothing. Replacing them with real platform
// adapters must not require changes outside internal/platform. See ADR-0001.
package inproc

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// DefaultMaxSeriesPerInstrument bounds how many distinct attribute
// combinations a single instrument may create before new combinations are
// dropped. This is the agent's last line of defence against a cardinality
// explosion originating inside the agent itself.
const DefaultMaxSeriesPerInstrument = 1000

// Telemetry is an in-memory platform.Telemetry with a hard cardinality bound.
//
// Once an instrument reaches its series limit, further distinct attribute
// combinations are dropped and counted rather than allocated. Dropping is
// preferable to unbounded growth: an agent must never destabilise its host, and
// a silently-truncated metric with a loud diagnostic is recoverable where an
// OOM is not.
type Telemetry struct {
	maxSeries int

	mu            sync.Mutex
	counters      map[string]map[string]int64
	gauges        map[string]map[string]float64
	histogram     map[string]map[string]*Distribution
	events        []platform.Event
	maxEvents     int
	logs          []platform.LogRecord
	maxLogs       int
	traces        []platform.TracePayload
	maxTraces     int
	droppedLogs   int64
	droppedTraces int64

	// dropped counts series rejected by the cardinality bound, keyed by
	// instrument name. It is itself bounded by the number of instruments.
	dropped map[string]int64
}

// Distribution is a minimal summary of observed values. It intentionally stores
// aggregates rather than raw samples so that memory is O(1) per series.
type Distribution struct {
	Count int64
	Sum   float64
	Min   float64
	Max   float64
}

// TelemetryOption configures a Telemetry.
type TelemetryOption func(*Telemetry)

// WithMaxSeries sets the per-instrument series bound.
func WithMaxSeries(n int) TelemetryOption {
	return func(t *Telemetry) {
		if n > 0 {
			t.maxSeries = n
		}
	}
}

// WithMaxEvents bounds the retained event ring. Older events are discarded.
func WithMaxEvents(n int) TelemetryOption {
	return func(t *Telemetry) {
		if n > 0 {
			t.maxEvents = n
		}
	}
}

// WithMaxLogs bounds retained log records. Excess records are dropped.
func WithMaxLogs(n int) TelemetryOption {
	return func(t *Telemetry) {
		if n > 0 {
			t.maxLogs = n
		}
	}
}

// WithMaxTraces bounds retained OTLP trace payloads. Excess payloads are dropped.
func WithMaxTraces(n int) TelemetryOption {
	return func(t *Telemetry) {
		if n > 0 {
			t.maxTraces = n
		}
	}
}

// NewTelemetry returns an in-memory Telemetry.
func NewTelemetry(opts ...TelemetryOption) *Telemetry {
	t := &Telemetry{
		maxSeries: DefaultMaxSeriesPerInstrument,
		maxEvents: 1024,
		maxLogs:   1024,
		maxTraces: 128,
		counters:  make(map[string]map[string]int64),
		gauges:    make(map[string]map[string]float64),
		histogram: make(map[string]map[string]*Distribution),
		dropped:   make(map[string]int64),
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

func (t *Telemetry) Counter(name string) platform.Counter {
	return &counter{t: t, name: name}
}

func (t *Telemetry) Gauge(name string) platform.Gauge {
	return &gauge{t: t, name: name}
}

func (t *Telemetry) Histogram(name string) platform.Histogram {
	return &histogram{t: t, name: name}
}

func (t *Telemetry) Emit(ev platform.Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) >= t.maxEvents {
		copy(t.events, t.events[1:])
		t.events = t.events[:len(t.events)-1]
	}
	t.events = append(t.events, ev)
}

func (t *Telemetry) EmitLog(rec platform.LogRecord) {
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.logs) >= t.maxLogs {
		copy(t.logs, t.logs[1:])
		t.logs = t.logs[:len(t.logs)-1]
		t.droppedLogs++
	}
	t.logs = append(t.logs, rec)
}

func (t *Telemetry) IngestTraces(payload platform.TracePayload) {
	if len(payload.Body) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.traces) >= t.maxTraces {
		t.droppedTraces++
		return
	}
	t.traces = append(t.traces, payload)
}

// seriesKey renders an attribute set into a stable, order-independent key.
func seriesKey(attrs []platform.Attr) string {
	if len(attrs) == 0 {
		return ""
	}
	sorted := make([]platform.Attr, len(attrs))
	copy(sorted, attrs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Key == sorted[j].Key {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].Key < sorted[j].Key
	})
	var b strings.Builder
	for i, a := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value)
	}
	return b.String()
}

// admitLocked reports whether a series may be created. Existing series are
// always admitted; new ones are admitted only below the bound.
func admitLocked[V any](t *Telemetry, m map[string]map[string]V, name, key string) (map[string]V, bool) {
	series, ok := m[name]
	if !ok {
		series = make(map[string]V)
		m[name] = series
	}
	if _, exists := series[key]; exists {
		return series, true
	}
	if len(series) >= t.maxSeries {
		t.dropped[name]++
		return series, false
	}
	return series, true
}

type counter struct {
	t    *Telemetry
	name string
}

func (c *counter) Add(delta int64, attrs ...platform.Attr) {
	key := seriesKey(attrs)
	c.t.mu.Lock()
	defer c.t.mu.Unlock()
	series, ok := admitLocked(c.t, c.t.counters, c.name, key)
	if !ok {
		return
	}
	series[key] += delta
}

type gauge struct {
	t    *Telemetry
	name string
}

func (g *gauge) Set(value float64, attrs ...platform.Attr) {
	key := seriesKey(attrs)
	g.t.mu.Lock()
	defer g.t.mu.Unlock()
	series, ok := admitLocked(g.t, g.t.gauges, g.name, key)
	if !ok {
		return
	}
	series[key] = value
}

type histogram struct {
	t    *Telemetry
	name string
}

func (h *histogram) Observe(value float64, attrs ...platform.Attr) {
	key := seriesKey(attrs)
	h.t.mu.Lock()
	defer h.t.mu.Unlock()
	series, ok := admitLocked(h.t, h.t.histogram, h.name, key)
	if !ok {
		return
	}
	d := series[key]
	if d == nil {
		d = &Distribution{Min: value, Max: value}
		series[key] = d
	}
	d.Count++
	d.Sum += value
	if value < d.Min {
		d.Min = value
	}
	if value > d.Max {
		d.Max = value
	}
}

// CounterValue returns the value of a counter series, and whether it exists.
func (t *Telemetry) CounterValue(name string, attrs ...platform.Attr) (int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.counters[name][seriesKey(attrs)]
	return v, ok
}

// GaugeValue returns the value of a gauge series, and whether it exists.
func (t *Telemetry) GaugeValue(name string, attrs ...platform.Attr) (float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.gauges[name][seriesKey(attrs)]
	return v, ok
}

// HistogramValue returns a copy of a histogram series, and whether it exists.
func (t *Telemetry) HistogramValue(name string, attrs ...platform.Attr) (Distribution, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.histogram[name][seriesKey(attrs)]
	if !ok || d == nil {
		return Distribution{}, false
	}
	return *d, true
}

// SeriesCount reports how many distinct series an instrument has created.
func (t *Telemetry) SeriesCount(name string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.counters[name]) + len(t.gauges[name]) + len(t.histogram[name])
}

// DroppedSeries reports how many series an instrument shed to the cardinality
// bound. This is the agent's cardinality diagnostic.
func (t *Telemetry) DroppedSeries(name string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropped[name]
}

// Events returns a copy of the retained events.
func (t *Telemetry) Events() []platform.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]platform.Event, len(t.events))
	copy(out, t.events)
	return out
}

// EventSnapshot implements platform.EventSnapshotter.
func (t *Telemetry) EventSnapshot() []platform.Event {
	return t.Events()
}

// GaugeSnapshot implements platform.GaugeSnapshotter.
func (t *Telemetry) GaugeSnapshot() []platform.GaugePoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []platform.GaugePoint
	for name, series := range t.gauges {
		for key, val := range series {
			out = append(out, platform.GaugePoint{
				Name:  name,
				Value: val,
				Attrs: attrsFromSeriesKey(key),
			})
		}
	}
	return out
}

// CounterSnapshot implements platform.CounterSnapshotter.
func (t *Telemetry) CounterSnapshot() []platform.CounterPoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []platform.CounterPoint
	for name, series := range t.counters {
		for key, val := range series {
			out = append(out, platform.CounterPoint{
				Name:  name,
				Value: val,
				Attrs: attrsFromSeriesKey(key),
			})
		}
	}
	return out
}

// HistogramSnapshot implements platform.HistogramSnapshotter.
func (t *Telemetry) HistogramSnapshot() []platform.HistogramPoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []platform.HistogramPoint
	for name, series := range t.histogram {
		for key, d := range series {
			if d == nil {
				continue
			}
			out = append(out, platform.HistogramPoint{
				Name:  name,
				Count: d.Count,
				Sum:   d.Sum,
				Min:   d.Min,
				Max:   d.Max,
				Attrs: attrsFromSeriesKey(key),
			})
		}
	}
	return out
}

// LogSnapshot implements platform.LogSnapshotter (peek, no drain).
func (t *Telemetry) LogSnapshot() []platform.LogRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]platform.LogRecord, len(t.logs))
	copy(out, t.logs)
	return out
}

// TraceSnapshot implements platform.TraceSnapshotter (peek, no drain).
func (t *Telemetry) TraceSnapshot() []platform.TracePayload {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]platform.TracePayload, len(t.traces))
	copy(out, t.traces)
	return out
}

// DrainLogs returns and clears retained log records.
func (t *Telemetry) DrainLogs() []platform.LogRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.logs
	t.logs = nil
	return out
}

// DrainTraces returns and clears retained trace payloads.
func (t *Telemetry) DrainTraces() []platform.TracePayload {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.traces
	t.traces = nil
	return out
}

// DroppedLogs reports log records shed to the retention bound.
func (t *Telemetry) DroppedLogs() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.droppedLogs
}

// DroppedTraces reports trace payloads shed to the retention bound.
func (t *Telemetry) DroppedTraces() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.droppedTraces
}

func attrsFromSeriesKey(key string) []platform.Attr {
	if key == "" {
		return nil
	}
	parts := strings.Split(key, ",")
	out := make([]platform.Attr, 0, len(parts))
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			continue
		}
		out = append(out, platform.Attr{Key: k, Value: v})
	}
	return out
}

var (
	_ platform.Telemetry            = (*Telemetry)(nil)
	_ platform.GaugeSnapshotter     = (*Telemetry)(nil)
	_ platform.CounterSnapshotter   = (*Telemetry)(nil)
	_ platform.HistogramSnapshotter = (*Telemetry)(nil)
)
