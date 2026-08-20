package native

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestExporterSpoolsOnFailureAndReplays(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	inner := inproc.NewTelemetry()
	inner.Gauge("host.memory.utilization").Set(0.5)
	exp := New(inner, Config{
		Endpoint:       srv.URL,
		Timeout:        time.Second,
		Interval:       time.Hour,
		MaxBatch:       32,
		Compression:    "none",
		SpoolDir:       dir,
		CircuitOpenFor: 50 * time.Millisecond,
		Resource:       []platform.Attr{platform.A("host.id", "i-spool")},
	})
	exp.client = srv.Client()
	exp.now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }

	exp.flush(t.Context())
	entries, _ := os.ReadDir(dir)
	spooled := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".spool" {
			spooled++
		}
	}
	if spooled == 0 {
		t.Fatal("expected spool files after failed export")
	}

	fail.Store(false)
	time.Sleep(60 * time.Millisecond)
	exp.now = func() time.Time { return time.Unix(1_700_000_200, 0).UTC() }
	before := hits.Load()
	exp.flush(t.Context())
	if hits.Load() <= before {
		t.Fatalf("hits did not increase on replay: before=%d after=%d", before, hits.Load())
	}
}
