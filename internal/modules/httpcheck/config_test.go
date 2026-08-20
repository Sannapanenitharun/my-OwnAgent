package httpcheck

import (
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

func TestParseTargets(t *testing.T) {
	got, err := parseTargets("ui=http://127.0.0.1:8181/,https://example.com/health")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "ui" || got[1].Name != "example.com" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseSettingsRejectsUnknown(t *testing.T) {
	_, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"nope": "1"}})
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestParseSettingsTimeoutVsInterval(t *testing.T) {
	_, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{
		"interval": "1s",
		"timeout":  "2s",
		"targets":  "a=http://127.0.0.1/",
	}})
	if err == nil {
		t.Fatal("expected timeout < interval rejection")
	}
}

func TestDefaultInterval(t *testing.T) {
	s, err := ParseSettings(config.ModuleConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Interval != 30*time.Second || s.ExpectStatus != 200 {
		t.Fatalf("%+v", s)
	}
}
