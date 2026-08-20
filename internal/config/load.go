package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// EnvPrefix namespaces every environment override.
const EnvPrefix = "OBSAGENT_"

// EnvConfigPath names the environment variable holding the configuration path.
const EnvConfigPath = EnvPrefix + "CONFIG"

// Loader produces validated configurations and assigns revisions.
//
// Revisions come from the loader rather than the file so that they are
// monotonic within a process even if an operator reverts to an older file. Two
// different applies are always distinguishable in telemetry and logs.
type Loader struct {
	revision atomic.Uint64
	// LookupEnv is the environment source. Tests substitute it; production
	// leaves it nil and os.LookupEnv is used.
	LookupEnv func(string) (string, bool)
}

// NewLoader returns a Loader starting at revision zero.
func NewLoader() *Loader { return &Loader{} }

func (l *Loader) lookupEnv(key string) (string, bool) {
	if l.LookupEnv != nil {
		return l.LookupEnv(key)
	}
	return os.LookupEnv(key)
}

// LoadFile reads, decodes, overlays environment overrides, validates and
// stamps a configuration read from path.
//
// An empty path yields the built-in defaults with environment overrides
// applied, which is what a fresh install runs before an operator supplies a
// file.
func (l *Loader) LoadFile(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: open %s: %w", path, err)
		}
		defer f.Close()
		cfg, err = l.decode(f)
		if err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
	}
	if err := l.applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	cfg.Revision = l.revision.Add(1)
	return cfg, nil
}

// LoadBytes decodes, overlays, validates and stamps a configuration from raw
// JSON. It exists for tests and for future remote configuration delivery.
func (l *Loader) LoadBytes(b []byte) (Config, error) {
	cfg, err := l.decode(bytes.NewReader(b))
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if err := l.applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	cfg.Revision = l.revision.Add(1)
	return cfg, nil
}

// decode layers the file over the defaults so that a partial file is legal and
// an operator only states what they are changing. Unknown fields are rejected:
// a misspelled key that is silently ignored is how an agent ends up running a
// configuration nobody intended.
func (l *Loader) decode(r io.Reader) (Config, error) {
	cfg := Default()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode: %w", err)
	}
	// Reject trailing content rather than ignoring it; two concatenated JSON
	// documents almost always mean a botched edit or a partial write.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("decode: unexpected trailing content after configuration document")
		}
		return Config{}, fmt.Errorf("decode: %w", err)
	}
	if cfg.Modules == nil {
		cfg.Modules = map[string]ModuleConfig{}
	}
	cfg.Export.OTLP.ApplyOTLPDefaults()
	cfg.Export.Native.ApplyNativeDefaults()
	return cfg, nil
}

// applyEnv overlays a fixed allowlist of environment overrides.
//
// The allowlist is deliberate. Generic "any field via any variable" mapping
// makes an agent's effective configuration impossible to reason about from the
// file alone, and turns every environment variable on a host into part of the
// agent's attack surface. Credentials are never accepted here — they are passed
// by secure reference only.
func (l *Loader) applyEnv(cfg *Config) error {
	var problems []Problem

	setDuration := func(name string, dst *Duration) {
		raw, ok := l.lookupEnv(EnvPrefix + name)
		if !ok {
			return
		}
		var d Duration
		if err := d.UnmarshalJSON([]byte(strconv.Quote(raw))); err != nil {
			problems = append(problems, Problem{Field: EnvPrefix + name, Message: err.Error()})
			return
		}
		*dst = d
	}

	setDuration("SHUTDOWN_TIMEOUT", &cfg.Agent.ShutdownTimeout)
	setDuration("MODULE_STOP_TIMEOUT", &cfg.Agent.ModuleStopTimeout)
	setDuration("MODULE_START_TIMEOUT", &cfg.Agent.ModuleStartTimeout)
	setDuration("HEALTH_INTERVAL", &cfg.Agent.HealthInterval)
	setDuration("HEALTH_PROBE_TIMEOUT", &cfg.Agent.HealthProbeTimeout)

	if raw, ok := l.lookupEnv(EnvPrefix + "RESTART_ENABLED"); ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			problems = append(problems, Problem{
				Field:   EnvPrefix + "RESTART_ENABLED",
				Message: fmt.Sprintf("invalid boolean %q", raw),
			})
		} else {
			cfg.Agent.Restart.Enabled = b
		}
	}

	// Per-module enable/disable: OBSAGENT_MODULE_<ID>_ENABLED, where <ID> is
	// the module ID uppercased with '-' replaced by '_'. Only modules already
	// present in the configuration can be toggled, so the environment cannot
	// conjure a module the operator never declared.
	ids := make([]string, 0, len(cfg.Modules))
	for id := range cfg.Modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		key := EnvPrefix + "MODULE_" + strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_ENABLED"
		raw, ok := l.lookupEnv(key)
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(raw)
		if err != nil {
			problems = append(problems, Problem{Field: key, Message: fmt.Sprintf("invalid boolean %q", raw)})
			continue
		}
		mc := cfg.Modules[id]
		mc.Enabled = b
		cfg.Modules[id] = mc
	}

	if raw, ok := l.lookupEnv(EnvPrefix + "OTLP_ENDPOINT"); ok {
		cfg.Export.OTLP.Endpoint = strings.TrimSpace(raw)
	}
	if raw, ok := l.lookupEnv(EnvPrefix + "OTLP_HEADERS"); ok {
		headers, err := parseHeaderList(raw)
		if err != nil {
			problems = append(problems, Problem{Field: EnvPrefix + "OTLP_HEADERS", Message: err.Error()})
		} else {
			cfg.Export.OTLP.Headers = headers
		}
	}
	if raw, ok := l.lookupEnv(EnvPrefix + "EXPORT_ENDPOINT"); ok {
		cfg.Export.Native.Endpoint = strings.TrimSpace(raw)
	}
	if raw, ok := l.lookupEnv(EnvPrefix + "EXPORT_HEADERS"); ok {
		headers, err := parseHeaderList(raw)
		if err != nil {
			problems = append(problems, Problem{Field: EnvPrefix + "EXPORT_HEADERS", Message: err.Error()})
		} else {
			cfg.Export.Native.Headers = headers
		}
	}

	cfg.Export.OTLP.ApplyOTLPDefaults()
	cfg.Export.Native.ApplyNativeDefaults()

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// Marshal renders a configuration as indented JSON. It is used by the
// diagnostics surface and by tests; it never includes credentials because the
// model has no credential fields by construction.
func Marshal(c Config) ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// parseHeaderList decodes "k=v,k2=v2" into a header map. Empty values are
// rejected: an ingest header with no value is almost always a botched secret
// injection.
func parseHeaderList(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("invalid header %q, want key=value", part)
		}
		out[k] = v
	}
	return out, nil
}
