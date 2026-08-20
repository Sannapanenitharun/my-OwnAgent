package native

import (
	"bytes"
	"compress/gzip"
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
	maxBody    = 4 << 20
)

// Config is a copy of the operator-facing native exporter fragment. This
// package does not import internal/config.
type Config struct {
	Endpoint    string
	Headers     map[string]string
	Timeout     time.Duration
	Interval    time.Duration
	MaxBatch    int
	Compression string
	Resource    []platform.Attr
}

// Exporter records locally (via Inner) and POSTs gzip JSON to Endpoint.
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

// New wraps inner. Export does not start until Start.
func New(inner platform.Telemetry, cfg Config) *Exporter {
	if inner == nil {
		inner = discard{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 1000
	}
	if strings.TrimSpace(cfg.Compression) == "" {
		cfg.Compression = "gzip"
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
	if payload.Signal != "" && payload.Signal != signalTraces {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.traces) >= e.cfg.MaxBatch {
		e.droppedTraces++
		e.droppedExport++
		return
	}
	e.traces = append(e.traces, payload)
}

func (e *Exporter) GaugeSnapshot() []platform.GaugePoint {
	return platform.SnapshotGauges(e.inner)
}

func (e *Exporter) CounterSnapshot() []platform.CounterPoint {
	if s, ok := e.inner.(platform.CounterSnapshotter); ok {
		return s.CounterSnapshot()
	}
	return nil
}

func (e *Exporter) HistogramSnapshot() []platform.HistogramPoint {
	if s, ok := e.inner.(platform.HistogramSnapshotter); ok {
		return s.HistogramSnapshot()
	}
	return nil
}

func (e *Exporter) flush(ctx context.Context) {
	now := e.now()
	e.exportMetrics(ctx, now)
	e.exportLogs(ctx, now)
	e.exportTraces(ctx, now)
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
	body := encodeMetrics(e.cfg.Resource, gauges, counters, hist, now)
	if len(body) == 0 {
		return
	}
	e.post(ctx, signalMetrics, body)
}

func (e *Exporter) exportLogs(ctx context.Context, now time.Time) {
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
	body := encodeLogs(e.cfg.Resource, batch, now)
	e.post(ctx, signalLogs, body)
}

func (e *Exporter) exportTraces(ctx context.Context, now time.Time) {
	e.mu.Lock()
	batch := e.traces
	e.traces = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	body := encodeTraces(e.cfg.Resource, batch, now)
	if len(body) == 0 {
		return
	}
	e.post(ctx, signalTraces, body)
}

func (e *Exporter) post(ctx context.Context, signal string, body []byte) {
	if len(body) == 0 || e.cfg.Endpoint == "" {
		return
	}
	payload, encoding := compress(body, e.cfg.Compression)
	if len(payload) > maxBody {
		e.noteFailure(signal)
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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
		if err != nil {
			last = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "observability-agent")
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
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
			e.inner.Counter("agent.export.success").Add(1, platform.A("signal", signal), platform.A("exporter", "native"))
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
	e.inner.Counter("agent.export.failure").Add(1, platform.A("signal", signal), platform.A("exporter", "native"))
	e.mu.Lock()
	e.droppedExport++
	e.mu.Unlock()
}

func compress(body []byte, mode string) ([]byte, string) {
	if strings.EqualFold(strings.TrimSpace(mode), "none") {
		return body, ""
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return body, ""
	}
	if err := zw.Close(); err != nil {
		return body, ""
	}
	return buf.Bytes(), "gzip"
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
	_ platform.Telemetry            = (*Exporter)(nil)
	_ platform.Shutdowner           = (*Exporter)(nil)
	_ platform.GaugeSnapshotter     = (*Exporter)(nil)
	_ platform.CounterSnapshotter   = (*Exporter)(nil)
	_ platform.HistogramSnapshotter = (*Exporter)(nil)
)

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
