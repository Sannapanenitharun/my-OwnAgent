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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

const maxSpoolFiles = 64

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
	// SpoolDir, when set, persists failed export payloads to disk and replays
	// them when the circuit is closed again.
	SpoolDir string
	// CircuitOpenFor is how long the exporter refuses new posts after tripping.
	// Zero selects 30s.
	CircuitOpenFor time.Duration
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

	failures  int
	openUntil time.Time

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
	if cfg.CircuitOpenFor <= 0 {
		cfg.CircuitOpenFor = 30 * time.Second
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
	e.replaySpool(ctx)
	e.exportMetrics(ctx, now)
	e.exportLogs(ctx, now)
	e.exportTraces(ctx, now)
}

func (e *Exporter) circuitOpen() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now().Before(e.openUntil)
}

func (e *Exporter) noteSuccess() {
	e.mu.Lock()
	e.failures = 0
	e.openUntil = time.Time{}
	e.mu.Unlock()
}

func (e *Exporter) tripCircuit() {
	e.mu.Lock()
	e.failures++
	if e.failures >= 5 {
		e.openUntil = e.now().Add(e.cfg.CircuitOpenFor)
		e.failures = 0
		e.inner.Counter("agent.export.circuit_open").Add(1, platform.A("exporter", "native"))
	}
	e.mu.Unlock()
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
	if e.circuitOpen() {
		e.spool(signal, body)
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
				e.spool(signal, body)
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
			e.noteSuccess()
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
	e.tripCircuit()
	e.spool(signal, body)
}

func (e *Exporter) noteFailure(signal string) {
	e.inner.Counter("agent.export.failure").Add(1, platform.A("signal", signal), platform.A("exporter", "native"))
	e.mu.Lock()
	e.droppedExport++
	e.mu.Unlock()
}

func (e *Exporter) spool(signal string, body []byte) {
	dir := strings.TrimSpace(e.cfg.SpoolDir)
	if dir == "" || len(body) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	name := fmt.Sprintf("%s-%d.spool", signal, e.now().UnixNano())
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o640); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	e.trimSpool(dir)
	e.inner.Counter("agent.export.spooled").Add(1, platform.A("signal", signal), platform.A("exporter", "native"))
}

func (e *Exporter) trimSpool(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= maxSpoolFiles {
		return
	}
	type fileAge struct {
		name string
		mod  time.Time
	}
	var files []fileAge
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".spool") {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		files = append(files, fileAge{name: ent.Name(), mod: info.ModTime()})
	}
	for len(files) > maxSpoolFiles {
		oldest := 0
		for i := 1; i < len(files); i++ {
			if files[i].mod.Before(files[oldest].mod) {
				oldest = i
			}
		}
		_ = os.Remove(filepath.Join(dir, files[oldest].name))
		files = append(files[:oldest], files[oldest+1:]...)
	}
}

func (e *Exporter) replaySpool(ctx context.Context) {
	dir := strings.TrimSpace(e.cfg.SpoolDir)
	if dir == "" || e.circuitOpen() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".spool") {
			continue
		}
		if e.circuitOpen() {
			return
		}
		name := ent.Name()
		signal := strings.SplitN(name, "-", 2)[0]
		switch signal {
		case signalMetrics, signalLogs, signalTraces:
		default:
			continue
		}
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil || len(body) == 0 {
			_ = os.Remove(path)
			continue
		}
		if !e.postOnce(ctx, signal, body) {
			return
		}
		_ = os.Remove(path)
		e.inner.Counter("agent.export.replay").Add(1, platform.A("signal", signal), platform.A("exporter", "native"))
	}
}

// postOnce sends one payload without spooling on failure (used by replay).
func (e *Exporter) postOnce(ctx context.Context, signal string, body []byte) bool {
	payload, encoding := compress(body, e.cfg.Compression)
	if len(payload) > maxBody {
		return true // drop corrupt/oversized spool entry
	}
	u, err := exportURL(e.cfg.Endpoint, signal)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return false
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
		e.tripCircuit()
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		e.noteSuccess()
		return true
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
		return true // drop permanent client errors
	}
	e.tripCircuit()
	return false
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
	_ platform.LogSnapshotter       = (*Exporter)(nil)
	_ platform.TraceSnapshotter     = (*Exporter)(nil)
	_ platform.EventSnapshotter     = (*Exporter)(nil)
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
