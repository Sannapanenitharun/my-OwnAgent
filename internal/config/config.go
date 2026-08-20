// Package config defines the agent's versioned configuration model.
//
// Two properties are load-bearing:
//
//   - Configuration is VERSIONED. Every successfully applied configuration
//     carries a monotonically increasing revision so that operators, telemetry
//     and rollback all refer to the same thing.
//
//   - Configuration NEVER PARTIALLY APPLIES. Applying a configuration is a
//     three-phase transaction (prepare / commit / rollback) driven by the
//     supervisor. A module that rejects its fragment during prepare aborts the
//     whole reload, and every module that already prepared is rolled back. A
//     half-applied configuration is the worst possible state for an agent: it
//     is neither the old behaviour an operator expects nor the new behaviour
//     they asked for.
//
// Encoding is JSON via the standard library. The agent has no third-party
// dependencies at Stage 1; a YAML surface is a packaging concern deferred to
// Stage 15 and would be a decoding shim over this same model.
package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that decodes from a Go duration string ("30s")
// or from an integer count of nanoseconds.
type Duration time.Duration

// D returns a Duration from a time.Duration.
func D(d time.Duration) Duration { return Duration(d) }

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", v, err)
		}
		*d = Duration(parsed)
		return nil
	case float64:
		*d = Duration(time.Duration(v))
		return nil
	default:
		return fmt.Errorf("invalid duration %s", strconv.Quote(string(b)))
	}
}

// Config is the complete agent configuration.
type Config struct {
	// Revision is assigned by the loader and increases monotonically across
	// successful applies within a process. It is not read from the file.
	Revision uint64 `json:"-"`

	// SchemaVersion identifies the configuration schema. An unknown version is
	// rejected rather than best-effort decoded.
	SchemaVersion int `json:"schema_version"`

	Agent   AgentConfig             `json:"agent"`
	Export  ExportConfig            `json:"export"`
	Modules map[string]ModuleConfig `json:"modules"`
}

// ExportConfig configures how collected telemetry leaves the host.
//
// Empty endpoints mean no export: telemetry terminates in the in-process
// adapter (tests, --check, local UI). Native is the agent's own HTTPS JSON
// writer (Datadog-style). OTLP is optional interoperability with collectors.
type ExportConfig struct {
	Native NativeConfig `json:"native"`
	OTLP   OTLPConfig   `json:"otlp"`
}

// NativeConfig is the first-party HTTPS JSON exporter.
//
// Collectors never see this. The entrypoint constructs the adapter. Payloads
// are the agent's own JSON (logs, metrics, traces), gzip-compressed by default,
// POSTed to {endpoint}/v1/logs|metrics|traces. That is the same shape as
// Datadog's Agent: a proprietary intake, not OTLP.
type NativeConfig struct {
	// Endpoint is the intake base URL, e.g. "https://intake.example.com".
	// Empty disables the native exporter.
	Endpoint string `json:"endpoint"`
	// Headers are extra HTTP headers (API key). Values are never logged.
	Headers  map[string]string `json:"headers,omitempty"`
	Timeout  Duration          `json:"timeout"`
	Interval Duration          `json:"interval"`
	MaxBatch int               `json:"max_batch"`
	// Compression is "gzip" (default) or "none".
	Compression string `json:"compression"`
}

// OTLPConfig is the OTLP/HTTP exporter.
type OTLPConfig struct {
	// Endpoint is the collector base URL, e.g. "http://alloy.internal:4318".
	// Paths /v1/metrics, /v1/logs and /v1/traces are appended. Empty disables
	// export.
	Endpoint string `json:"endpoint"`
	// Protocol is "http/protobuf" (default) or "http/json".
	Protocol string `json:"protocol"`
	// Headers are extra HTTP headers (for example an ingest token). Values are
	// operator-supplied; they are never logged.
	Headers map[string]string `json:"headers,omitempty"`
	// Timeout bounds a single export HTTP round trip.
	Timeout Duration `json:"timeout"`
	// Interval is how often metrics are flushed. Logs and traces flush as
	// soon as a batch is ready, and at least this often.
	Interval Duration `json:"interval"`
	// MaxBatch is the maximum number of log records or trace payloads in one
	// export. Excess is dropped and counted.
	MaxBatch int `json:"max_batch"`
}

// CurrentSchemaVersion is the only schema version this build accepts.
const CurrentSchemaVersion = 1

// AgentConfig configures the agent shell and supervisor.
type AgentConfig struct {
	// ShutdownTimeout bounds the entire graceful shutdown sequence.
	ShutdownTimeout Duration `json:"shutdown_timeout"`
	// ModuleStopTimeout bounds a single module's Stop call.
	ModuleStopTimeout Duration `json:"module_stop_timeout"`
	// ModuleStartTimeout bounds a single module's Start call.
	ModuleStartTimeout Duration `json:"module_start_timeout"`
	// HealthInterval is how often the supervisor probes module health.
	HealthInterval Duration `json:"health_interval"`
	// HealthProbeTimeout bounds a single module's Health call.
	HealthProbeTimeout Duration `json:"health_probe_timeout"`
	// Restart configures crash-loop protection.
	Restart RestartConfig `json:"restart"`
	// DiagnosticsRetention bounds how many diagnostic records are retained.
	DiagnosticsRetention int `json:"diagnostics_retention"`
}

// RestartConfig configures module restart and crash-loop protection.
type RestartConfig struct {
	// Enabled turns automatic restart on. When false, a failed module stays
	// failed and the agent continues without it.
	Enabled bool `json:"enabled"`
	// InitialBackoff is the delay before the first restart attempt.
	InitialBackoff Duration `json:"initial_backoff"`
	// MaxBackoff caps the exponential backoff.
	MaxBackoff Duration `json:"max_backoff"`
	// JitterFraction randomises each delay by +/- this fraction of the
	// computed backoff, in [0,1). Jitter prevents every module of a fleet
	// from retrying in lockstep after a shared dependency fails.
	JitterFraction float64 `json:"jitter_fraction"`
	// MaxRestarts is how many restarts are permitted inside Window before the
	// module is quarantined as crash-looping.
	MaxRestarts int `json:"max_restarts"`
	// Window is the sliding window over which MaxRestarts is counted.
	Window Duration `json:"window"`
}

// ModuleConfig is a single module's configuration fragment.
type ModuleConfig struct {
	// Enabled controls whether the supervisor starts the module at all. A
	// disabled module is not registered with the Capability Runtime and
	// consumes no resources.
	Enabled bool `json:"enabled"`
	// Required marks the module as necessary for agent health. An optional
	// module's failure can only degrade the agent, never make it unhealthy.
	Required bool `json:"required"`
	// Settings are module-specific key/value settings. The module validates
	// them during prepare; the agent core does not interpret them.
	Settings map[string]string `json:"settings,omitempty"`
}

// Setting returns a setting value and whether it was present.
func (m ModuleConfig) Setting(key string) (string, bool) {
	v, ok := m.Settings[key]
	return v, ok
}

// ModuleFor returns the configuration for a module. Modules absent from the
// configuration are disabled: enabling a collector is an explicit operator
// decision, never a default that appears because a binary was upgraded.
func (c Config) ModuleFor(id string) ModuleConfig {
	if mc, ok := c.Modules[id]; ok {
		return mc
	}
	return ModuleConfig{Enabled: false}
}

// Clone returns a deep copy. The supervisor holds a snapshot across a reload
// so that a rollback restores exactly the previous configuration.
func (c Config) Clone() Config {
	out := c
	if c.Export.OTLP.Headers != nil {
		out.Export.OTLP.Headers = make(map[string]string, len(c.Export.OTLP.Headers))
		for k, v := range c.Export.OTLP.Headers {
			out.Export.OTLP.Headers[k] = v
		}
	}
	if c.Export.Native.Headers != nil {
		out.Export.Native.Headers = make(map[string]string, len(c.Export.Native.Headers))
		for k, v := range c.Export.Native.Headers {
			out.Export.Native.Headers[k] = v
		}
	}
	if c.Modules != nil {
		out.Modules = make(map[string]ModuleConfig, len(c.Modules))
		for k, v := range c.Modules {
			mc := v
			if v.Settings != nil {
				mc.Settings = make(map[string]string, len(v.Settings))
				for sk, sv := range v.Settings {
					mc.Settings[sk] = sv
				}
			}
			out.Modules[k] = mc
		}
	}
	return out
}

// Default returns the built-in configuration.
//
// The defaults are deliberately conservative: restart enabled with a tight
// crash-loop budget, health probing every 15s, and a 30s shutdown ceiling that
// fits inside the default systemd and Windows service stop timeouts. An agent
// that a service manager has to SIGKILL loses in-flight telemetry.
func Default() Config {
	return Config{
		SchemaVersion: CurrentSchemaVersion,
		Agent: AgentConfig{
			ShutdownTimeout:    D(30 * time.Second),
			ModuleStopTimeout:  D(10 * time.Second),
			ModuleStartTimeout: D(30 * time.Second),
			HealthInterval:     D(15 * time.Second),
			HealthProbeTimeout: D(5 * time.Second),
			Restart: RestartConfig{
				Enabled:        true,
				InitialBackoff: D(1 * time.Second),
				MaxBackoff:     D(5 * time.Minute),
				JitterFraction: 0.2,
				MaxRestarts:    5,
				Window:         D(10 * time.Minute),
			},
			DiagnosticsRetention: 256,
		},
		Export: ExportConfig{
			Native: NativeConfig{
				Timeout:     D(10 * time.Second),
				Interval:    D(5 * time.Second),
				MaxBatch:    1000,
				Compression: "gzip",
			},
			OTLP: OTLPConfig{
				Protocol: "http/protobuf",
				Timeout:  D(10 * time.Second),
				Interval: D(10 * time.Second),
				MaxBatch: 512,
			},
		},
		Modules: map[string]ModuleConfig{},
	}
}

// ApplyOTLPDefaults fills empty OTLP fields with the built-in values. A file
// that states only an endpoint must not zero the rest of the exporter.
func (c *OTLPConfig) ApplyOTLPDefaults() {
	if strings.TrimSpace(c.Protocol) == "" {
		c.Protocol = "http/protobuf"
	}
	if c.Timeout.Std() <= 0 {
		c.Timeout = D(10 * time.Second)
	}
	if c.Interval.Std() <= 0 {
		c.Interval = D(10 * time.Second)
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = 512
	}
}

// ApplyNativeDefaults fills empty native-exporter fields.
func (c *NativeConfig) ApplyNativeDefaults() {
	if c.Timeout.Std() <= 0 {
		c.Timeout = D(10 * time.Second)
	}
	if c.Interval.Std() <= 0 {
		c.Interval = D(5 * time.Second)
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = 1000
	}
	if strings.TrimSpace(c.Compression) == "" {
		c.Compression = "gzip"
	}
}
