package architecture

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
	"github.com/obsagent/observability-agent/internal/platform/native"
	"github.com/obsagent/observability-agent/internal/platform/otlp"
	"github.com/obsagent/observability-agent/internal/platform/scrub"
)

// TestEveryTelemetryWrapperForwardsRetirement guards a capability that is only
// as strong as the least diligent wrapper in the chain.
//
// platform.SeriesRetirer is optional, discovered by type assertion, and a
// no-op when unsupported -- which is right, because an adapter that cannot
// forget a series is untidy rather than broken. The hazard is that a WRAPPER
// which fails to relay it is indistinguishable from an adapter that cannot
// support it. That is not theoretical: the agent composes
// inproc -> scrub -> native, and scrub did not forward. Retirement was accepted
// by the exporter, swallowed in the middle, and never reached the store. The
// process module went on exporting executables that had exited, and nothing
// anywhere failed.
//
// Every wrapper is exercised here against a real store, so a new one that
// forgets to forward fails this test rather than quietly losing the capability.
func TestEveryTelemetryWrapperForwardsRetirement(t *testing.T) {
	const metric = "process.memory.rss"
	attr := platform.A("executable", "doomed")

	wrappers := map[string]func(platform.Telemetry) platform.Telemetry{
		"scrub": scrub.Wrap,
		"native": func(inner platform.Telemetry) platform.Telemetry {
			return native.New(inner, native.Config{})
		},
		"otlp": func(inner platform.Telemetry) platform.Telemetry {
			return otlp.New(inner, otlp.Config{})
		},
		// The composition the agent actually builds. A chain is where a single
		// non-forwarding link does its damage.
		"scrub+native": func(inner platform.Telemetry) platform.Telemetry {
			return native.New(scrub.Wrap(inner), native.Config{})
		},
	}

	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			store := inproc.NewTelemetry()
			tel := wrap(store)

			tel.Gauge(metric).Set(1024, attr)
			if !hasSeries(store, metric) {
				t.Fatal("the gauge never reached the store; this test proves nothing")
			}

			platform.RetireSeries(tel, metric, attr)

			if hasSeries(store, metric) {
				t.Errorf("%s accepted a retirement and did not forward it: the "+
					"series is still in the store", name)
			}
		})
	}
}

func hasSeries(store *inproc.Telemetry, metric string) bool {
	for _, p := range store.GaugeSnapshot() {
		if p.Name == metric {
			return true
		}
	}
	return false
}
