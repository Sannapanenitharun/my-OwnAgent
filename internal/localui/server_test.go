package localui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestAddrEnabled(t *testing.T) {
	if !AddrEnabled("127.0.0.1:8181") {
		t.Fatal("expected enabled")
	}
	for _, a := range []string{"", "off", "OFF", "-", "false"} {
		if AddrEnabled(a) {
			t.Fatalf("%q should disable the UI", a)
		}
	}
}

func TestStatusJSONIncludesIdentityAndGauges(t *testing.T) {
	tel := inproc.NewTelemetry()
	tel.Gauge("host.cpu.utilization").Set(12.5, platform.A("state", "busy"))
	tel.Gauge("host.memory.utilization").Set(40)
	s := &Server{
		Identity:  inproc.NewIdentity("agent-1", "", "i-0abc123def4567890"),
		Telemetry: tel,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body Status
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Identity.HostID != "i-0abc123def4567890" {
		t.Fatalf("host_id = %q", body.Identity.HostID)
	}
	if body.Identity.TenantID != "" {
		t.Fatal("unresolved tenant must stay empty, not invented")
	}
	if len(body.Highlights) < 2 {
		t.Fatalf("highlights = %#v", body.Highlights)
	}
	tel.EmitLog(platform.LogRecord{Body: "hello from files", Severity: platform.SeverityInfo})
	tel.IngestTraces(platform.TracePayload{Signal: "traces", ContentType: "application/json", Body: []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"GET /"}]}]}]}`)})
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var body2 Status
	if err := json.NewDecoder(rec2.Body).Decode(&body2); err != nil {
		t.Fatal(err)
	}
	if len(body2.Logs) != 1 || body2.Logs[0].Body != "hello from files" {
		t.Fatalf("logs = %#v", body2.Logs)
	}
	if len(body2.Traces) != 1 || body2.Traces[0].Summary == "" {
		t.Fatalf("traces = %#v", body2.Traces)
	}
}

func TestUIPageServesHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %s", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"Hosts", "Traces", "Logs", "Metrics", "CPU Usage", "Containers", "Applications"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ui missing %q", want)
		}
	}
}
