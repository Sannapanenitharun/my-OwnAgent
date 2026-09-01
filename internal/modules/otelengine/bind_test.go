package otelengine

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// unbindable is in TEST-NET-1, which is guaranteed not to be a local address,
// so binding it fails exactly the way a removed bridge gateway does.
const unbindable = "192.0.2.1:4320"

func bindHost(t *testing.T, tel *inproc.Telemetry, listen string) (module.Host, *diagnostics.Recorder) {
	t.Helper()
	h := testHost(t, tel, config.ModuleConfig{Settings: map[string]string{"listen": listen}})
	rec := diagnostics.NewRecorder(32)
	h.Diagnostics = rec
	return h, rec
}

func gaugeValue(tel *inproc.Telemetry, name string) (float64, bool) {
	for _, p := range tel.GaugeSnapshot() {
		if p.Name == name {
			return p.Value, true
		}
	}
	return 0, false
}

// TestOneUnbindableAddressDoesNotTakeTheReceiverDown is the defect this
// replaced. These addresses are Docker bridge gateways, which come and go: a
// network is removed, or has not been recreated yet at boot. Refusing to start
// meant that instead of SOME containers being unable to reach the receiver,
// every container was -- and the module crash-looped until it exhausted its
// restart budget and stayed dead, which is what happened on a live host.
func TestOneUnbindableAddressDoesNotTakeTheReceiverDown(t *testing.T) {
	good := freeAddr(t)
	tel := inproc.NewTelemetry()
	h, rec := bindHost(t, tel, good+","+unbindable)
	m := New()
	if err := m.Start(context.Background(), h); err != nil {
		t.Fatalf("Start refused to run with one bad address: %v", err)
	}
	defer func() { _ = m.Stop(context.Background()) }()

	if v, ok := gaugeValue(tel, MetricListenersBound); !ok || v != 1 {
		t.Errorf("listeners_bound = %v ok=%v, want 1", v, ok)
	}
	if v, _ := gaugeValue(tel, MetricListenersConfigured); v != 2 {
		t.Errorf("listeners_configured = %v, want 2: the gap is the alert", v)
	}

	// Silence is the other way to get this wrong.
	var found bool
	for _, d := range rec.Records() {
		if strings.Contains(d.Message, "192.0.2.1") {
			found = true
		}
	}
	if !found {
		t.Error("the address that could not be bound was not reported")
	}
}

// TestNoBindableAddressIsStillAFailure. Degrading is not the same as
// pretending: with nothing bound there is no receiver at all.
func TestNoBindableAddressIsStillAFailure(t *testing.T) {
	h, _ := bindHost(t, inproc.NewTelemetry(), unbindable+",192.0.2.2:4320")
	m := New()
	if err := m.Start(context.Background(), h); err == nil {
		_ = m.Stop(context.Background())
		t.Fatal("Start succeeded with no listener bound")
	} else if !strings.Contains(err.Error(), "no listen address") {
		t.Errorf("error = %q, want it to say nothing could be bound", err)
	}
}

// TestTheBoundAddressStillServes. Degrading must not mean starting a receiver
// that answers nowhere.
func TestTheBoundAddressStillServes(t *testing.T) {
	good := freeAddr(t)
	tel := inproc.NewTelemetry()
	h, _ := bindHost(t, tel, good+","+unbindable)
	m := New()
	if err := m.Start(context.Background(), h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop(context.Background()) }()

	waitListening(t, good)
	c, err := net.Dial("tcp", good)
	if err != nil {
		t.Fatalf("the bound address does not answer: %v", err)
	}
	_ = c.Close()
}
