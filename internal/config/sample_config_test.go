package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadJSON(t *testing.T, body string) Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := NewLoader().LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return cfg
}

// TestTraceSampleRateIsAcceptedAndDefaultsToKeepingEverything. An unset rate
// must not silently discard every span: zero is "not configured", not "drop
// all", and the only safe reading of an absent field is to keep the traces.
func TestTraceSampleRateIsAcceptedAndDefaultsToKeepingEverything(t *testing.T) {
	cfg := loadJSON(t, `{
		"schema_version": 1,
		"export": {"native": {"endpoint": "http://127.0.0.1:8090", "trace_sample_rate": 0.25}}
	}`)
	if got := cfg.Export.Native.TraceSampleRate; got != 0.25 {
		t.Errorf("trace_sample_rate = %v, want 0.25", got)
	}

	def := loadJSON(t, `{
		"schema_version": 1,
		"export": {"native": {"endpoint": "http://127.0.0.1:8090"}}
	}`)
	if def.Export.Native.TraceSampleRate != 0 {
		t.Errorf("unset rate = %v, want the zero value the exporter reads as "+
			"keep-everything", def.Export.Native.TraceSampleRate)
	}
}
