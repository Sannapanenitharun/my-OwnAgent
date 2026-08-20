package statsd

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestApplyLineGaugeCounter(t *testing.T) {
	tel := inproc.NewTelemetry()
	if !applyLine(tel, "app.requests:3|c|#env:prod,region:us") {
		t.Fatal("counter rejected")
	}
	if !applyLine(tel, "app.latency:12.5|ms") {
		t.Fatal("timer rejected")
	}
	if !applyLine(tel, "app.heap:1024|g") {
		t.Fatal("gauge rejected")
	}
	gauges := platform.SnapshotGauges(tel)
	found := false
	for _, g := range gauges {
		if g.Name == "app.heap" && g.Value == 1024 {
			found = true
		}
	}
	if !found {
		t.Fatalf("gauge missing: %+v", gauges)
	}
}

func TestApplyLineRejectsJunk(t *testing.T) {
	tel := inproc.NewTelemetry()
	if applyLine(tel, "not-a-metric") {
		t.Fatal("expected reject")
	}
	if applyLine(tel, "bad name:1|c") {
		t.Fatal("expected reject spaced name")
	}
}
