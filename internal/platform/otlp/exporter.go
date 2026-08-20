package otlp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	signalMetrics = "metrics"
	signalLogs    = "logs"
	signalTraces  = "traces"

	maxRetries = 3
)

// Config is the exporter's runtime configuration. It is a copy of the
// operator-facing config fragment so this package does not import
// internal/config (platform adapters must not depend on agent config).
type Config struct {
	Endpoint string
	Protocol string
	Headers  map[string]string
	Timeout  time.Duration
	Interval time.Duration
	MaxBatch int
	Resource []platform.Attr
}

// Exporter is a platform.Telemetry that records locally (via Inner) and
// periodically POSTs OTLP/HTTP to Endpoint.
type Exporter struct {
	inner  platform.Telemetry
	cfg    Config
	client *http.Client
	now    func() time.Time

	mu            sync.Mutex
	logs          []platform.LogRecord
	traces        []platform.TracePayload
	droppedLogs   int64
	droppedTraces int64
	droppedExport int64

	cancel context.CancelFunc
	done   chan struct{}
}

// New wraps inner with an OTLP exporter. Inner must be non-nil: the local UI
// and tests read snapshots from it. The export loop does not start until Start.
func New(inner platform.Telemetry, cfg Config) *Exporter {
	if inner == nil {
		inner = discard{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 512
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "http/protobuf"
	}
	return &Exporter{
		inner:  inner,
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		now:    time.Now,
		done:   make(chan struct{}),
	}
}

// Start launches the flush loop. It is safe to call once.
func (e *Exporter) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	go e.loop(ctx)
}

func (e *Exporter) loop(ctx context.Context) {
	defer close(e.done)
	t := time.NewTicker(e.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.flush(context.Background())
			return
		case <-t.C:
			e.flush(ctx)
		}
	}
}

// Shutdown implements platform.Shutdowner.
func (e *Exporter) Shutdown(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
		select {
		case <-e.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		e.flush(ctx)
	}
	if s, ok := e.inner.(platform.Shutdowner); ok {
		return s.Shutdown(ctx)
	}
	return nil
}

func (e *Exporter) Counter(name string) platform.Counter { return e.inner.Counter(name) }
func (e *Exporter) Gauge(name string) platform.Gauge     { return e.inner.Gauge(name) }
func (e *Exporter) Histogram(name string) platform.Histogram {
	return e.inner.Histogram(name)
}

func (e *Exporter) Emit(ev platform.Event) { e.inner.Emit(ev) }

func (e *Exporter) EmitLog(rec platform.LogRecord) {
	e.inner.EmitLog(rec)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.logs) >= e.cfg.MaxBatch*2 {
		e.droppedLogs++
		e.droppedExport++
		return
	}
	e.logs = append(e.logs, rec)
}

func (e *Exporter) IngestTraces(payload platform.TracePayload) {
	e.inner.IngestTraces(payload)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.traces) >= e.cfg.MaxBatch {
		e.droppedTraces++
		e.droppedExport++
		return
	}
	e.traces = append(e.traces, payload)
}

// GaugeSnapshot implements platform.GaugeSnapshotter by delegating to Inner.
func (e *Exporter) GaugeSnapshot() []platform.GaugePoint {
	return platform.SnapshotGauges(e.inner)
}

func (e *Exporter) LogSnapshot() []platform.LogRecord {
	return platform.SnapshotLogs(e.inner)
}

func (e *Exporter) TraceSnapshot() []platform.TracePayload {
	return platform.SnapshotTraces(e.inner)
}

func (e *Exporter) EventSnapshot() []platform.Event {
	return platform.SnapshotEvents(e.inner)
}

func (e *Exporter) flush(ctx context.Context) {
	now := e.now()
	e.exportMetrics(ctx, now)
	e.exportLogs(ctx)
	e.exportTraces(ctx)
}

func (e *Exporter) exportMetrics(ctx context.Context, now time.Time) {
	var gauges []platform.GaugePoint
	var counters []platform.CounterPoint
	var hist []platform.HistogramPoint
	if s, ok := e.inner.(platform.GaugeSnapshotter); ok {
		gauges = s.GaugeSnapshot()
	}
	if s, ok := e.inner.(platform.CounterSnapshotter); ok {
		counters = s.CounterSnapshot()
	}
	if s, ok := e.inner.(platform.HistogramSnapshotter); ok {
		hist = s.HistogramSnapshot()
	}
	body := encodeMetricsRequest(e.cfg.Resource, gauges, counters, hist, now)
	if len(body) == 0 {
		return
	}
	e.post(ctx, signalMetrics, body)
}

func (e *Exporter) exportLogs(ctx context.Context) {
	e.mu.Lock()
	batch := e.logs
	e.logs = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if len(batch) > e.cfg.MaxBatch {
		e.mu.Lock()
		e.droppedLogs += int64(len(batch) - e.cfg.MaxBatch)
		e.droppedExport += int64(len(batch) - e.cfg.MaxBatch)
		e.mu.Unlock()
		batch = batch[:e.cfg.MaxBatch]
	}
	body := encodeLogsRequest(e.cfg.Resource, batch)
	e.post(ctx, signalLogs, body)
}

func (e *Exporter) exportTraces(ctx context.Context) {
	e.mu.Lock()
	batch := e.traces
	e.traces = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	bySignal := map[string][]platform.TracePayload{}
	for _, p := range batch {
		sig := p.Signal
		if sig == "" {
			sig = signalTraces
		}
		bySignal[sig] = append(bySignal[sig], p)
	}
	if traces := bySignal[signalTraces]; len(traces) > 0 {
		body := encodePassthroughTraces(e.cfg.Resource, traces)
		if len(body) > 0 {
			e.post(ctx, signalTraces, body)
		}
	}
	if logs := bySignal[signalLogs]; len(logs) > 0 {
		// App-originated OTLP logs: forward the last payload (already a full
		// request) after resource injection.
		for _, p := range logs {
			body := p.Body
			if isJSON(p.ContentType, body) {
				// JSON logs are forwarded as protobuf only when we can wrap
				// them as a traces-shaped envelope; otherwise POST original.
				e.post(ctx, signalLogs, body)
				continue
			}
			e.post(ctx, signalLogs, injectResourceSpans(body, e.cfg.Resource))
		}
	}
	if metrics := bySignal[signalMetrics]; len(metrics) > 0 {
		for _, p := range metrics {
			e.post(ctx, signalMetrics, p.Body)
		}
	}
}

func (e *Exporter) post(ctx context.Context, signal string, body []byte) {
	if len(body) == 0 || e.cfg.Endpoint == "" {
		return
	}
	u, err := exportURL(e.cfg.Endpoint, signal)
	if err != nil {
		e.noteFailure(signal)
		return
	}
	var last error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(50*(1<<attempt))*time.Millisecond + time.Duration(rand.Intn(40))*time.Millisecond
			select {
			case <-ctx.Done():
				e.noteFailure(signal)
				return
			case <-time.After(delay):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		if err != nil {
			last = err
			continue
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		for k, v := range e.cfg.Headers {
			req.Header.Set(k, v)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			last = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			e.inner.Counter("agent.export.success").Add(1, platform.A("signal", signal))
			return
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			last = fmt.Errorf("status %d", resp.StatusCode)
			break
		}
		last = fmt.Errorf("status %d", resp.StatusCode)
	}
	_ = last
	e.noteFailure(signal)
}

func (e *Exporter) noteFailure(signal string) {
	e.inner.Counter("agent.export.failure").Add(1, platform.A("signal", signal))
	e.mu.Lock()
	e.droppedExport++
	e.mu.Unlock()
}

func exportURL(endpoint, signal string) (string, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/" + signal
	return u.String(), nil
}

// Dropped reports how many log/trace items were shed to the queue bound.
func (e *Exporter) Dropped() (logs, traces, export int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.droppedLogs, e.droppedTraces, e.droppedExport
}

var (
	_ platform.Telemetry        = (*Exporter)(nil)
	_ platform.Shutdowner       = (*Exporter)(nil)
	_ platform.GaugeSnapshotter = (*Exporter)(nil)
)

// discard is used only if New is called with a nil inner, which is a
// programming error we still tolerate so tests can construct an exporter
// without a full inproc adapter.
type discard struct{}

func (discard) Counter(string) platform.Counter     { return nop{} }
func (discard) Gauge(string) platform.Gauge         { return nop{} }
func (discard) Histogram(string) platform.Histogram { return nop{} }
func (discard) Emit(platform.Event)                 {}
func (discard) EmitLog(platform.LogRecord)          {}
func (discard) IngestTraces(platform.TracePayload)  {}

type nop struct{}

func (nop) Add(int64, ...platform.Attr)       {}
func (nop) Set(float64, ...platform.Attr)     {}
func (nop) Observe(float64, ...platform.Attr) {}
