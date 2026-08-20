package otlp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestExporterPostsMetricsLogsTraces(t *testing.T) {
	var (
		mu      sync.Mutex
		gotPath []string
		gotCT   []string
		gotBody [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath = append(gotPath, r.URL.Path)
		gotCT = append(gotCT, r.Header.Get("Content-Type"))
		gotBody = append(gotBody, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	inner := inproc.NewTelemetry()
	inner.Gauge("host.memory.utilization").Set(0.4, platform.A("module", "host"))
	exp := New(inner, Config{
		Endpoint: srv.URL,
		Timeout:  time.Second,
		Interval: time.Hour,
		MaxBatch: 32,
		Resource: []platform.Attr{platform.A("host.id", "i-0abc"), platform.A("cloud.provider", "aws")},
	})
	exp.client = srv.Client()
	exp.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	exp.EmitLog(platform.LogRecord{
		Timestamp: time.Unix(1_700_000_000, 0),
		Severity:  platform.SeverityInfo,
		Body:      "ready",
		Attrs:     []platform.Attr{platform.A("source", "files")},
	})
	exp.IngestTraces(platform.TracePayload{
		ContentType: "application/json",
		Body:        []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"bbbbbbbbbbbbbbbb","name":"GET /","startTimeUnixNano":"1","endTimeUnixNano":"2"}]}]}]}`),
	})
	exp.flush(t.Context())

	mu.Lock()
	defer mu.Unlock()
	if len(gotPath) != 3 {
		t.Fatalf("posts = %d (%v), want 3 (metrics, logs, traces)", len(gotPath), gotPath)
	}
	want := map[string]bool{"/v1/metrics": true, "/v1/logs": true, "/v1/traces": true}
	for _, p := range gotPath {
		if !want[p] {
			t.Errorf("unexpected path %s", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing paths %v", want)
	}
	for i, ct := range gotCT {
		if ct != "application/x-protobuf" {
			t.Errorf("content-type[%d] = %q", i, ct)
		}
	}
	// Resource attribute host.id must appear in the metrics payload.
	if !bytesContains(gotBody[indexOf(gotPath, "/v1/metrics")], []byte("host.id")) {
		t.Error("metrics payload missing host.id resource attribute")
	}
	if !bytesContains(gotBody[indexOf(gotPath, "/v1/logs")], []byte("ready")) {
		t.Error("logs payload missing body")
	}
}

func TestExporterDropsWhenQueueIsFull(t *testing.T) {
	inner := inproc.NewTelemetry()
	exp := New(inner, Config{MaxBatch: 2, Interval: time.Hour, Timeout: time.Second})
	for i := 0; i < 10; i++ {
		exp.IngestTraces(platform.TracePayload{ContentType: "application/x-protobuf", Body: []byte{1, 2, 3}})
	}
	_, traces, _ := exp.Dropped()
	if traces < 8 {
		t.Fatalf("dropped traces = %d, want at least 8", traces)
	}
}

func TestExporterRetriesThenCountsFailure(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	inner := inproc.NewTelemetry()
	inner.Gauge("x").Set(1)
	exp := New(inner, Config{Endpoint: srv.URL, Timeout: 200 * time.Millisecond, Interval: time.Hour})
	exp.client = srv.Client()
	exp.flush(t.Context())
	if hits != maxRetries {
		t.Fatalf("attempts = %d, want %d", hits, maxRetries)
	}
	if v, ok := inner.CounterValue("agent.export.failure", platform.A("signal", "metrics")); !ok || v < 1 {
		t.Fatalf("failure counter = %d, ok=%v", v, ok)
	}
}

func TestExportURLRejectsNonHTTP(t *testing.T) {
	if _, err := exportURL("ftp://x", "metrics"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestInjectResourceDoesNotOverwrite(t *testing.T) {
	// A payload that already has host.id must keep the app's value.
	orig := encodePassthroughTraces(nil, []platform.TracePayload{{
		ContentType: "application/json",
		Body:        []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"host.id","value":{"stringValue":"app-host"}}]},"scopeSpans":[{"spans":[{"name":"x","traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"bbbbbbbbbbbbbbbb","startTimeUnixNano":"1","endTimeUnixNano":"2"}]}]}]}`),
	}})
	got := injectResourceSpans(orig, []platform.Attr{platform.A("host.id", "i-agent"), platform.A("cloud.provider", "aws")})
	if !bytesContains(got, []byte("app-host")) {
		t.Fatal("existing host.id was overwritten")
	}
	if !bytesContains(got, []byte("cloud.provider")) {
		t.Fatal("cloud.provider was not added")
	}
}

func TestEncodeMetricsRoundTripShape(t *testing.T) {
	body := encodeMetricsRequest(
		[]platform.Attr{platform.A("service.name", "observability-agent")},
		[]platform.GaugePoint{{Name: "host.cpu.utilization", Value: 0.2, Attrs: []platform.Attr{platform.A("state", "busy")}}},
		[]platform.CounterPoint{{Name: "host.network.rx_bytes", Value: 99, Attrs: []platform.Attr{platform.A("interface", "eth0")}}},
		nil,
		time.Unix(100, 0),
	)
	if len(body) < 20 {
		t.Fatalf("encoded length %d, want a real protobuf payload", len(body))
	}
	if !bytesContains(body, []byte("host.cpu.utilization")) {
		t.Fatal("missing metric name")
	}
	if !bytesContains(body, []byte("service.name")) {
		t.Fatal("missing resource attribute")
	}
}

func indexOf(paths []string, want string) int {
	for i, p := range paths {
		if p == want {
			return i
		}
	}
	return 0
}

func bytesContains(b, sub []byte) bool {
	return strings.Contains(string(b), string(sub))
}
