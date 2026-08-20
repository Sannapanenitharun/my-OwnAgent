package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Validate(Default()); err != nil {
		t.Fatalf("built-in defaults are invalid: %v", err)
	}
}

func TestDurationDecoding(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{`"30s"`, 30 * time.Second, false},
		{`"5m"`, 5 * time.Minute, false},
		{`"1h30m"`, 90 * time.Minute, false},
		{`1000000000`, time.Second, false},
		{`"nonsense"`, 0, true},
		{`true`, 0, true},
	}
	for _, tc := range tests {
		var d Duration
		err := json.Unmarshal([]byte(tc.in), &d)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: expected an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if d.Std() != tc.want {
			t.Errorf("%s = %v, want %v", tc.in, d.Std(), tc.want)
		}
	}
}

func TestDurationRoundTrips(t *testing.T) {
	orig := D(90 * time.Second)
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got Duration
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got != orig {
		t.Fatalf("round trip = %v, want %v", got, orig)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	// An operator fixing config in a maintenance window should not need N
	// round trips to find N mistakes.
	cfg := Default()
	cfg.Agent.ShutdownTimeout = D(0)
	cfg.Agent.HealthInterval = D(-1)
	cfg.Agent.DiagnosticsRetention = 0

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not a *ValidationError: %T", err)
	}
	if len(ve.Problems) < 3 {
		t.Fatalf("reported %d problems, want at least 3: %v", len(ve.Problems), ve.Problems)
	}
}

func TestValidateRejectsUnsupportedSchemaVersion(t *testing.T) {
	cfg := Default()
	cfg.SchemaVersion = 99
	if err := Validate(cfg); err == nil {
		t.Fatal("an unknown schema version must be rejected, not best-effort decoded")
	}
}

func TestValidateRejectsRequiredButDisabledModule(t *testing.T) {
	// Such a module can never become healthy, so the agent would be
	// permanently unhealthy through no runtime fault.
	cfg := Default()
	cfg.Modules["host"] = ModuleConfig{Enabled: false, Required: true}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "required and disabled") {
		t.Fatalf("expected a required-and-disabled rejection, got %v", err)
	}
}

func TestValidateRejectsUnreachableCrashLoopBudget(t *testing.T) {
	// If MaxRestarts * InitialBackoff exceeds the window, the budget can never
	// be consumed and crash-loop detection is unreachable.
	cfg := Default()
	cfg.Agent.Restart.MaxRestarts = 100
	cfg.Agent.Restart.InitialBackoff = D(time.Minute)
	cfg.Agent.Restart.Window = D(time.Minute)

	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "restart.window") {
		t.Fatalf("expected an unreachable-budget rejection, got %v", err)
	}
}

func TestValidateRejectsStopTimeoutExceedingShutdownBudget(t *testing.T) {
	cfg := Default()
	cfg.Agent.ModuleStopTimeout = D(time.Hour)
	if err := Validate(cfg); err == nil {
		t.Fatal("a per-module stop timeout larger than the whole shutdown budget must be rejected")
	}
}

func TestValidateRejectsBadJitter(t *testing.T) {
	for _, j := range []float64{-0.1, 1.0, 5} {
		cfg := Default()
		cfg.Agent.Restart.JitterFraction = j
		if err := Validate(cfg); err == nil {
			t.Errorf("jitter %v should be rejected", j)
		}
	}
}

func TestModuleForDefaultsToDisabled(t *testing.T) {
	// Enabling a collector must be an explicit operator decision, never a
	// default that appears because a binary was upgraded.
	cfg := Default()
	if cfg.ModuleFor("never-declared").Enabled {
		t.Fatal("an undeclared module defaulted to enabled")
	}
}

func TestCloneIsDeep(t *testing.T) {
	cfg := Default()
	cfg.Modules["host"] = ModuleConfig{Enabled: true, Settings: map[string]string{"interval": "10s"}}

	clone := cfg.Clone()
	clone.Modules["host"].Settings["interval"] = "60s"
	clone.Modules["logs"] = ModuleConfig{Enabled: true}

	if got := cfg.Modules["host"].Settings["interval"]; got != "10s" {
		t.Fatalf("mutating the clone changed the original setting: %q", got)
	}
	if _, ok := cfg.Modules["logs"]; ok {
		t.Fatal("mutating the clone added a module to the original")
	}
}

func TestLoadFileLayersOverDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	body := `{"schema_version":1,"agent":{"health_interval":"7s"},"modules":{"host":{"enabled":true,"required":true}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := NewLoader().LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Agent.HealthInterval.Std(); got != 7*time.Second {
		t.Fatalf("health_interval = %v, want 7s", got)
	}
	// Unstated fields must keep their defaults, so a partial file is legal.
	if got := cfg.Agent.ShutdownTimeout.Std(); got != 30*time.Second {
		t.Fatalf("shutdown_timeout = %v, want the default 30s", got)
	}
	if !cfg.Modules["host"].Enabled {
		t.Fatal("host module should be enabled")
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	// A silently ignored typo is how an agent ends up running a configuration
	// nobody intended.
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"agnet":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLoader().LoadFile(path); err == nil {
		t.Fatal("a misspelled key must be rejected")
	}
}

func TestLoadFileRejectsTrailingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1}{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLoader().LoadFile(path); err == nil {
		t.Fatal("trailing content must be rejected; it usually means a partial write")
	}
}

func TestLoadFileMissingPath(t *testing.T) {
	if _, err := NewLoader().LoadFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("expected an error for a missing configuration file")
	}
}

func TestEmptyPathYieldsDefaults(t *testing.T) {
	cfg, err := NewLoader().LoadFile("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version = %d", cfg.SchemaVersion)
	}
}

func TestRevisionsAreMonotonic(t *testing.T) {
	// Revisions come from the loader so that reverting to an older file still
	// produces a distinguishable, increasing revision.
	l := NewLoader()
	var last uint64
	for i := 0; i < 5; i++ {
		cfg, err := l.LoadFile("")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Revision <= last {
			t.Fatalf("revision %d did not increase over %d", cfg.Revision, last)
		}
		last = cfg.Revision
	}
}

func TestEnvOverrides(t *testing.T) {
	env := map[string]string{
		EnvPrefix + "HEALTH_INTERVAL":     "42s",
		EnvPrefix + "RESTART_ENABLED":     "false",
		EnvPrefix + "MODULE_HOST_ENABLED": "false",
		EnvPrefix + "MODULE_EBPF_ENABLED": "true",
	}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	cfg, err := l.LoadBytes([]byte(`{"schema_version":1,"modules":{"host":{"enabled":true},"ebpf":{"enabled":false}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Agent.HealthInterval.Std(); got != 42*time.Second {
		t.Fatalf("health_interval = %v, want 42s", got)
	}
	if cfg.Agent.Restart.Enabled {
		t.Fatal("restart should have been disabled by the environment")
	}
	if cfg.Modules["host"].Enabled {
		t.Fatal("host should have been disabled by the environment")
	}
	if !cfg.Modules["ebpf"].Enabled {
		t.Fatal("ebpf should have been enabled by the environment")
	}
}

func TestEnvCannotConjureUndeclaredModules(t *testing.T) {
	// The environment may toggle what the operator declared; it must not add
	// collectors the operator never opted into.
	env := map[string]string{EnvPrefix + "MODULE_SECURITY_ENABLED": "true"}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	cfg, err := l.LoadBytes([]byte(`{"schema_version":1,"modules":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Modules["security"]; ok {
		t.Fatal("the environment created a module that was never declared")
	}
}

func TestEnvRejectsMalformedValues(t *testing.T) {
	env := map[string]string{EnvPrefix + "HEALTH_INTERVAL": "not-a-duration"}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	if _, err := l.LoadFile(""); err == nil {
		t.Fatal("a malformed environment override must be rejected, not ignored")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Modules["host"] = ModuleConfig{Enabled: true, Required: true}

	b, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewLoader().LoadBytes(b)
	if err != nil {
		t.Fatalf("marshalled configuration did not load back: %v", err)
	}
	if got.Agent.ShutdownTimeout != cfg.Agent.ShutdownTimeout {
		t.Fatal("shutdown timeout did not survive the round trip")
	}
	if !got.Modules["host"].Required {
		t.Fatal("module fragment did not survive the round trip")
	}
}

func TestSettingLookup(t *testing.T) {
	mc := ModuleConfig{Settings: map[string]string{"interval": "10s"}}
	if v, ok := mc.Setting("interval"); !ok || v != "10s" {
		t.Fatalf("Setting(interval) = %q, %v", v, ok)
	}
	if _, ok := mc.Setting("absent"); ok {
		t.Fatal("Setting reported a value that does not exist")
	}
}

func TestOTLPEndpointFromEnv(t *testing.T) {
	env := map[string]string{EnvPrefix + "OTLP_ENDPOINT": "http://collector:4318"}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	cfg, err := l.LoadFile("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Export.OTLP.Endpoint != "http://collector:4318" {
		t.Fatalf("endpoint = %q", cfg.Export.OTLP.Endpoint)
	}
	if cfg.Export.OTLP.Protocol != "http/protobuf" {
		t.Fatalf("protocol default lost: %q", cfg.Export.OTLP.Protocol)
	}
}

func TestOTLPHeadersFromEnv(t *testing.T) {
	env := map[string]string{EnvPrefix + "OTLP_HEADERS": "Authorization=Bearer tok,X-Scope=a"}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	cfg, err := l.LoadFile("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Export.OTLP.Headers["Authorization"] != "Bearer tok" || cfg.Export.OTLP.Headers["X-Scope"] != "a" {
		t.Fatalf("headers = %#v", cfg.Export.OTLP.Headers)
	}
}

func TestNativeEndpointFromEnv(t *testing.T) {
	env := map[string]string{EnvPrefix + "EXPORT_ENDPOINT": "https://intake.example.com"}
	l := NewLoader()
	l.LookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	cfg, err := l.LoadFile("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Export.Native.Endpoint != "https://intake.example.com" {
		t.Fatalf("endpoint = %q", cfg.Export.Native.Endpoint)
	}
	if cfg.Export.Native.Compression != "gzip" {
		t.Fatalf("compression default lost: %q", cfg.Export.Native.Compression)
	}
}

func TestOTLPRejectsNonHTTPEndpoint(t *testing.T) {
	cfg := Default()
	cfg.Export.OTLP.Endpoint = "ftp://collector"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestOTLPRejectsLoopbackCollision(t *testing.T) {
	cfg := Default()
	cfg.Export.OTLP.Endpoint = "http://127.0.0.1:4318"
	cfg.Modules["otel-engine"] = ModuleConfig{
		Enabled:  true,
		Settings: map[string]string{"listen": "127.0.0.1:4318"},
	}
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "otel-engine listen") {
		t.Fatalf("expected loopback collision, got %v", err)
	}
}

func TestLoadFileOTLPEndpointKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	body := `{"schema_version":1,"export":{"otlp":{"endpoint":"http://alloy:4318"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewLoader().LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Export.OTLP.Timeout.Std() != 10*time.Second {
		t.Fatalf("timeout = %s, want default 10s", cfg.Export.OTLP.Timeout)
	}
}
