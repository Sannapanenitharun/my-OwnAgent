package native

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestExporterPostsGzipJSON(t *testing.T) {
	var (
		mu      sync.Mutex
		gotPath []string
		gotCT   []string
		gotCE   []string
		gotBody [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Errorf("gzip: %v", err)
			} else {
				body, _ = io.ReadAll(zr)
				_ = zr.Close()
			}
		}
		mu.Lock()
		gotPath = append(gotPath, r.URL.Path)
		gotCT = append(gotCT, r.Header.Get("Content-Type"))
		gotCE = append(gotCE, r.Header.Get("Content-Encoding"))
		gotBody = append(gotBody, body)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	inner := inproc.NewTelemetry()
	inner.Gauge("host.memory.utilization").Set(0.4, platform.A("module", "host"))
	exp := New(inner, Config{
		Endpoint:    srv.URL,
		Timeout:     time.Second,
		Interval:    time.Hour,
		MaxBatch:    32,
		Compression: "gzip",
		Headers:     map[string]string{"X-API-Key": "secret"},
		Resource:    []platform.Attr{platform.A("host.id", "i-0abc"), platform.A("cloud.provider", "aws")},
	})
	exp.client = srv.Client()
	exp.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	exp.EmitLog(platform.LogRecord{
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
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
		t.Fatalf("posts = %d (%v), want 3", len(gotPath), gotPath)
	}
	want := map[string]bool{"/v1/metrics": true, "/v1/logs": true, "/v1/traces": true}
	for i, p := range gotPath {
		if !want[p] {
			t.Errorf("unexpected path %s", p)
		}
		if gotCT[i] != "application/json" {
			t.Errorf("content-type[%d] = %q", i, gotCT[i])
		}
		if gotCE[i] != "gzip" {
			t.Errorf("content-encoding[%d] = %q", i, gotCE[i])
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing paths %v", want)
	}

	logs := envelopeOf(t, gotBody, gotPath, "/v1/logs")
	if logs.Host != "i-0abc" || logs.Schema != payloadSchema {
		t.Fatalf("logs envelope = %+v", logs)
	}
	if len(logs.Logs) != 1 || logs.Logs[0].Message != "ready" || logs.Logs[0].Source != "files" {
		t.Fatalf("logs = %+v", logs.Logs)
	}
	traces := envelopeOf(t, gotBody, gotPath, "/v1/traces")
	if len(traces.Traces) != 1 || traces.Traces[0].Name != "GET /" {
		t.Fatalf("spans = %+v", traces.Traces)
	}
	metrics := envelopeOf(t, gotBody, gotPath, "/v1/metrics")
	if metrics.Metrics == nil || len(metrics.Metrics.Gauges) == 0 {
		t.Fatalf("metrics = %+v", metrics.Metrics)
	}
}

func envelopeOf(t *testing.T, bodies [][]byte, paths []string, want string) envelope {
	t.Helper()
	for i, p := range paths {
		if p == want {
			var env envelope
			if err := json.Unmarshal(bodies[i], &env); err != nil {
				t.Fatalf("json %s: %v\n%s", want, err, bodies[i])
			}
			return env
		}
	}
	t.Fatalf("no body for %s", want)
	return envelope{}
}
