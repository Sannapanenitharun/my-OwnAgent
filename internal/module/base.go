package module

import (
	"context"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
)

// Base is an embeddable partial implementation of the module contract.
//
// It supplies conservative defaults for the optional parts of the contract so
// that a module only writes the behaviour it actually has. Embedding Base does
// NOT satisfy Module: Manifest, Start, Stop and Health remain the module
// author's responsibility, which keeps the required surface impossible to
// forget.
type Base struct {
	host Host
}

// Init stores the host. Modules embedding Base should call it first in Start.
func (b *Base) Init(host Host) { b.host = host }

// Host returns the stored host. It is the zero value before Init.
func (b *Base) Host() Host { return b.host }

// Diagnostics returns no on-demand diagnostics. Modules with constraints to
// report should override this.
func (b *Base) Diagnostics(context.Context) []diagnostics.Record { return nil }

// Statistics returns empty statistics.
func (b *Base) Statistics(context.Context) Statistics {
	return Statistics{Counters: map[string]int64{}, Gauges: map[string]float64{}}
}

// Capabilities returns no declared capabilities.
func (b *Base) Capabilities(context.Context) []Capability { return nil }

// NoopStop is a Stop implementation for modules that own no resources.
func NoopStop(context.Context) error { return nil }

// AlwaysHealthy is a Health implementation for modules with nothing to report.
// It is intended for trivial modules; anything that can fail should report
// real health instead.
func AlwaysHealthy(context.Context) health.Report { return health.OK("") }

// StaticConfigurable is an embeddable Configurable for modules that accept
// configuration only at start. Prepare rejects any change, which is the honest
// answer for a module that cannot reconfigure in place: the operator learns the
// reload was refused instead of believing it took effect.
type StaticConfigurable struct{}

// PrepareConfig always reports that runtime reconfiguration is unsupported.
func (StaticConfigurable) PrepareConfig(context.Context, config.ModuleConfig) error {
	return Unsupported("module does not support runtime reconfiguration; restart the agent to apply changes")
}

// CommitConfig is a no-op; PrepareConfig never succeeds.
func (StaticConfigurable) CommitConfig(context.Context) error { return nil }

// RollbackConfig is a no-op; PrepareConfig never stages anything.
func (StaticConfigurable) RollbackConfig(context.Context) error { return nil }
