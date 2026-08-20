package httpcheck_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/modules/httpcheck"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/clockfake"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestModuleProbesTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	clk := clockfake.New(time.Unix(1_700_000_000, 0))
	tel := inproc.NewTelemetry()
	diag := diagnostics.NewRecorder(32)
	mod := httpcheck.New()

	host := module.Host{
		ID:          httpcheck.ID,
		Telemetry:   tel,
		Clock:       clk,
		Identity:    inproc.NewIdentity("a", "t", "i-test"),
		Diagnostics: diagnostics.Scoped(string(httpcheck.ID), diag),
		Authorize:   func(context.Context, platform.Permission) error { return nil },
		Config: config.ModuleConfig{
			Enabled: true,
			Settings: map[string]string{
				"interval": "30s",
				"timeout":  "2s",
				"targets":  "probe=" + srv.URL + "/",
			},
		},
	}

	if err := mod.Start(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mod.Stop(t.Context()) })

	deadline := time.Now().Add(2 * time.Second)
	for {
		var up float64
		found := false
		for _, g := range tel.GaugeSnapshot() {
			if g.Name == httpcheck.MetricUp {
				up = g.Value
				found = true
			}
		}
		if found && up == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("up gauge not set; snapshot=%v", tel.GaugeSnapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStartRequiresTargets(t *testing.T) {
	mod := httpcheck.New()
	err := mod.Start(t.Context(), module.Host{
		ID:          httpcheck.ID,
		Telemetry:   inproc.NewTelemetry(),
		Clock:       clockfake.New(time.Now()),
		Identity:    inproc.NewIdentity("a", "t", "h"),
		Diagnostics: diagnostics.Scoped(string(httpcheck.ID), diagnostics.NewRecorder(8)),
		Authorize:   func(context.Context, platform.Permission) error { return nil },
		Config:      config.ModuleConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("expected unsupported")
	}
}
