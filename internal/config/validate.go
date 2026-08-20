package config

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ValidationError reports every problem found in a configuration.
//
// All problems are reported at once rather than the first one. An operator
// fixing a configuration in a maintenance window should not have to make N
// round trips to discover N mistakes.
type ValidationError struct {
	Problems []Problem
}

// Problem is a single validation failure, located by a dotted field path.
type Problem struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "config: invalid"
	}
	parts := make([]string, 0, len(e.Problems))
	for _, p := range e.Problems {
		parts = append(parts, fmt.Sprintf("%s: %s", p.Field, p.Message))
	}
	return "config: " + strings.Join(parts, "; ")
}

type validator struct {
	problems []Problem
}

func (v *validator) fail(field, format string, args ...any) {
	v.problems = append(v.problems, Problem{Field: field, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) positive(field string, d Duration) {
	if d.Std() <= 0 {
		v.fail(field, "must be greater than zero, got %s", d)
	}
}

// Validate checks a configuration for internal consistency.
//
// Validation is total and side-effect free: it never touches the filesystem,
// never contacts the platform, and never mutates the input. That is what makes
// it safe to run against a candidate configuration before deciding to apply it.
func Validate(c Config) error {
	v := &validator{}

	if c.SchemaVersion != CurrentSchemaVersion {
		v.fail("schema_version", "unsupported schema version %d, this build accepts %d",
			c.SchemaVersion, CurrentSchemaVersion)
	}

	a := c.Agent
	v.positive("agent.shutdown_timeout", a.ShutdownTimeout)
	v.positive("agent.module_stop_timeout", a.ModuleStopTimeout)
	v.positive("agent.module_start_timeout", a.ModuleStartTimeout)
	v.positive("agent.health_interval", a.HealthInterval)
	v.positive("agent.health_probe_timeout", a.HealthProbeTimeout)

	// A module stop timeout that exceeds the whole shutdown budget means the
	// last modules in the stop order can never be given their full allowance,
	// so shutdown would silently truncate rather than behave as configured.
	if a.ModuleStopTimeout.Std() > a.ShutdownTimeout.Std() {
		v.fail("agent.module_stop_timeout", "must not exceed agent.shutdown_timeout (%s)", a.ShutdownTimeout)
	}
	// Probing more slowly than the probe deadline is fine; probing faster than
	// the deadline lets probes overlap and pile up.
	if a.HealthProbeTimeout.Std() > a.HealthInterval.Std() {
		v.fail("agent.health_probe_timeout", "must not exceed agent.health_interval (%s)", a.HealthInterval)
	}
	if a.DiagnosticsRetention <= 0 {
		v.fail("agent.diagnostics_retention", "must be greater than zero, got %d", a.DiagnosticsRetention)
	}

	if a.Restart.Enabled {
		r := a.Restart
		v.positive("agent.restart.initial_backoff", r.InitialBackoff)
		v.positive("agent.restart.max_backoff", r.MaxBackoff)
		v.positive("agent.restart.window", r.Window)
		if r.InitialBackoff.Std() > r.MaxBackoff.Std() {
			v.fail("agent.restart.initial_backoff", "must not exceed agent.restart.max_backoff (%s)", r.MaxBackoff)
		}
		if r.MaxRestarts <= 0 {
			v.fail("agent.restart.max_restarts", "must be greater than zero when restart is enabled, got %d", r.MaxRestarts)
		}
		if r.JitterFraction < 0 || r.JitterFraction >= 1 {
			v.fail("agent.restart.jitter_fraction", "must be in [0,1), got %v", r.JitterFraction)
		}
		// A restart budget that cannot be consumed inside its own window makes
		// crash-loop detection unreachable: the module would restart forever.
		if r.MaxRestarts > 0 && r.Window.Std() > 0 {
			minSpan := time.Duration(r.MaxRestarts) * r.InitialBackoff.Std()
			if minSpan > r.Window.Std() {
				v.fail("agent.restart.window",
					"must be at least %s so that %d restarts at %s backoff can be observed",
					minSpan, r.MaxRestarts, r.InitialBackoff)
			}
		}
	}

	ids := make([]string, 0, len(c.Modules))
	for id := range c.Modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		field := "modules." + id
		if id == "" {
			v.fail("modules", "module ID must not be empty")
			continue
		}
		if strings.TrimSpace(id) != id {
			v.fail(field, "module ID must not have leading or trailing whitespace")
		}
		mc := c.Modules[id]
		// A module that is required for agent health but disabled can never
		// become healthy, so the agent would be permanently unhealthy.
		if mc.Required && !mc.Enabled {
			v.fail(field, "cannot be required and disabled at the same time")
		}
		for k := range mc.Settings {
			if k == "" {
				v.fail(field+".settings", "setting key must not be empty")
			}
		}
	}

	c.Export.OTLP.ApplyOTLPDefaults()
	c.Export.Native.ApplyNativeDefaults()
	otlp := c.Export.OTLP
	switch strings.ToLower(strings.TrimSpace(otlp.Protocol)) {
	case "http/protobuf", "http/json":
	default:
		v.fail("export.otlp.protocol", "must be http/protobuf or http/json, got %q", otlp.Protocol)
	}
	if otlp.Timeout.Std() <= 0 {
		v.fail("export.otlp.timeout", "must be greater than zero, got %s", otlp.Timeout)
	}
	if otlp.Interval.Std() <= 0 {
		v.fail("export.otlp.interval", "must be greater than zero, got %s", otlp.Interval)
	}
	if otlp.MaxBatch <= 0 {
		v.fail("export.otlp.max_batch", "must be greater than zero, got %d", otlp.MaxBatch)
	}
	if ep := strings.TrimSpace(otlp.Endpoint); ep != "" {
		if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
			v.fail("export.otlp.endpoint", "must be an http or https URL, got %q", ep)
		}
	}
	for k, val := range otlp.Headers {
		if strings.TrimSpace(k) == "" {
			v.fail("export.otlp.headers", "header name must not be empty")
		}
		if strings.TrimSpace(val) == "" {
			v.fail("export.otlp.headers."+k, "header value must not be empty")
		}
	}

	native := c.Export.Native
	switch strings.ToLower(strings.TrimSpace(native.Compression)) {
	case "gzip", "none":
	default:
		v.fail("export.native.compression", "must be gzip or none, got %q", native.Compression)
	}
	if native.Timeout.Std() <= 0 {
		v.fail("export.native.timeout", "must be greater than zero, got %s", native.Timeout)
	}
	if native.Interval.Std() <= 0 {
		v.fail("export.native.interval", "must be greater than zero, got %s", native.Interval)
	}
	if native.MaxBatch <= 0 {
		v.fail("export.native.max_batch", "must be greater than zero, got %d", native.MaxBatch)
	}
	if ep := strings.TrimSpace(native.Endpoint); ep != "" {
		if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
			v.fail("export.native.endpoint", "must be an http or https URL, got %q", ep)
		}
	}
	for k, val := range native.Headers {
		if strings.TrimSpace(k) == "" {
			v.fail("export.native.headers", "header name must not be empty")
		}
		if strings.TrimSpace(val) == "" {
			v.fail("export.native.headers."+k, "header value must not be empty")
		}
	}

	if listen := strings.TrimSpace(c.ModuleFor("otel-engine").Settings["listen"]); listen != "" {
		if strings.TrimSpace(otlp.Endpoint) != "" && otlpLoopbackCollision(listen, otlp.Endpoint) {
			v.fail("export.otlp.endpoint", "must not equal otel-engine listen address %s (that would export traces into the agent itself)", listen)
		}
		if strings.TrimSpace(native.Endpoint) != "" && otlpLoopbackCollision(listen, native.Endpoint) {
			v.fail("export.native.endpoint", "must not equal otel-engine listen address %s (that would export into the agent itself)", listen)
		}
	}

	if len(v.problems) > 0 {
		return &ValidationError{Problems: v.problems}
	}
	return nil
}

// otlpLoopbackCollision reports whether the OTLP exporter would POST to the
// agent's own OTLP receiver, which would loop traces until the queue dropped
// them.
func otlpLoopbackCollision(listen, endpoint string) bool {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Host == "" {
		return false
	}
	return canonicalHostPort(listen) == canonicalHostPort(u.Host)
}

func canonicalHostPort(s string) string {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return strings.ToLower(s)
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		host = "127.0.0.1"
	}
	return strings.ToLower(host) + ":" + port
}
