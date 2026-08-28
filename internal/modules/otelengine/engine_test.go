package otelengine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
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
	// The default must stay loopback-only. This receiver takes unauthenticated
	// OTLP, so a default that reached further would publish an open ingest
	// endpoint on every host the agent is installed on.
	s := DefaultSettings()
	if len(s.Listen) != 1 {
		t.Fatalf("default listen = %v, want exactly one address", s.Listen)
	}
	host, port, err := net.SplitHostPort(s.Listen[0])
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != "4318" {
		t.Fatalf("default listen = %s, want 127.0.0.1:4318", s.Listen[0])
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

func TestReceiverServesEveryConfiguredAddress(t *testing.T) {
	// A container on a user-defined Docker network reaches the host only at
	// that network's own gateway. One listener serves one of them, so a host
	// with six bridges needs six addresses -- and the alternative, 0.0.0.0,
	// publishes an unauthenticated ingest endpoint.
	a, b := freeAddr(t), freeAddr(t)
	m := New()
	h := testHost(t, inproc.NewTelemetry(), config.ModuleConfig{Settings: map[string]string{"listen": a + ", " + b}})
	if err := m.Start(context.Background(), h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })

	for _, addr := range []string{a, b} {
		resp, err := http.Post("http://"+addr+"/v1/traces", "application/json",
			strings.NewReader(`{"resourceSpans":[]}`))
		if err != nil {
			t.Fatalf("post to %s: %v", addr, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d, want 200", addr, resp.StatusCode)
		}
	}
}

func TestListenListIsParsedAndDeduplicated(t *testing.T) {
	s, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{
		"listen": " 127.0.0.1:4318 , 172.17.0.1:4318 ,, 127.0.0.1:4318 ",
	}})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	// A repeat would fail to bind the second time and take the module down
	// over a typo in a list.
	want := []string{"127.0.0.1:4318", "172.17.0.1:4318"}
	if len(s.Listen) != len(want) {
		t.Fatalf("listen = %v, want %v", s.Listen, want)
	}
	for i := range want {
		if s.Listen[i] != want[i] {
			t.Errorf("listen[%d] = %q, want %q", i, s.Listen[i], want[i])
		}
	}
}

func TestABadAddressInTheListIsRejected(t *testing.T) {
	// Rejected at parse time, so a typo is a config error rather than a
	// receiver that is silently reachable from fewer networks than intended.
	for _, bad := range []string{"127.0.0.1:4318, nonsense", "", "   ,  "} {
		if _, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"listen": bad}}); err == nil {
			t.Errorf("listen %q was accepted", bad)
		}
	}
}

func TestAPartialBindStartsNothing(t *testing.T) {
	// Half a receiver is worse than none: the containers that could not reach
	// it would be indistinguishable from containers that are not instrumented.
	taken := freeAddr(t)
	blocker, err := net.Listen("tcp", taken)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Close() }()

	free := freeAddr(t)
	m := New()
	h := testHost(t, inproc.NewTelemetry(), config.ModuleConfig{Settings: map[string]string{"listen": free + "," + taken}})
	if err := m.Start(context.Background(), h); err == nil {
		_ = m.Stop(context.Background())
		t.Fatal("Start succeeded with one address unavailable")
	}
	// The address that did bind must have been released, not leaked.
	ln, err := net.Listen("tcp", free)
	if err != nil {
		t.Errorf("the successfully bound address was leaked: %v", err)
	} else {
		_ = ln.Close()
	}
}
