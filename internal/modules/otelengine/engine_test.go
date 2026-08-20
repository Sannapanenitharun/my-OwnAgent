package otelengine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

func TestParseSettingsRejectsUnknown(t *testing.T) {
	_, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"listn": "127.0.0.1:1"}})
	if err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestReceiverAcceptsLocalhostTraces(t *testing.T) {
	addr := freeAddr(t)
	tel := inproc.NewTelemetry()
	m := New()
	host := testHost(t, tel, config.ModuleConfig{
		Enabled:  true,
		Settings: map[string]string{"listen": addr, "max.queue": "8", "max.body_bytes": "1024"},
	})
	if err := m.Start(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	waitListening(t, addr)

	body := []byte(`{"resourceSpans":[]}`)
	resp, err := http.Post("http://"+addr+"/v1/traces", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	payloads := tel.DrainTraces()
	if len(payloads) != 1 || payloads[0].Signal != "traces" {
		t.Fatalf("payloads = %#v", payloads)
	}
}

func TestReceiverRejectsOversizedBody(t *testing.T) {
	addr := freeAddr(t)
	m := New()
	host := testHost(t, inproc.NewTelemetry(), config.ModuleConfig{
		Enabled:  true,
		Settings: map[string]string{"listen": addr, "max.body_bytes": "8"},
	})
	if err := m.Start(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	waitListening(t, addr)

	resp, err := http.Post("http://"+addr+"/v1/traces", "application/json", bytes.NewReader([]byte("0123456789")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
}

func TestReceiverBindsLocalhostByDefault(t *testing.T) {
	s := DefaultSettings()
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != "4318" {
		t.Fatalf("default listen = %s, want 127.0.0.1:4318", s.Listen)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("receiver did not listen on %s", addr)
}

func testHost(t *testing.T, tel platform.Telemetry, mc config.ModuleConfig) module.Host {
	t.Helper()
	return module.Host{
		ID:            ID,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:     tel,
		Clock:         platform.NewSystemClock(),
		Identity:      inproc.NewIdentity("a", "t", "h"),
		Diagnostics:   diagnostics.NewRecorder(8),
		Authorize:     func(context.Context, platform.Permission) error { return nil },
		ReportFailure: func(error) {},
		Config:        mc,
	}
}
