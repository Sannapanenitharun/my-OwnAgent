package logs

import (
	"os"
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
)

func TestRedactAWSKey(t *testing.T) {
	in := "using AKIAIOSFODNN7EXAMPLE for access"
	got := Redact(in)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("leaked AWS key: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("missing redaction marker: %q", got)
	}
}

func TestRedactPasswordAssignment(t *testing.T) {
	got := Redact(`login password=hunter2 ok`)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("leaked password: %q", got)
	}
}

func TestRedactBearer(t *testing.T) {
	got := Redact("Authorization: Bearer abcdefghijklmnop")
	if strings.Contains(got, "abcdefghijklmnop") {
		t.Fatalf("leaked bearer: %q", got)
	}
}

func TestTruncate(t *testing.T) {
	s, cut := Truncate("abcdef", 3)
	if !cut || s != "abc" {
		t.Fatalf("got %q cut=%v", s, cut)
	}
	s, cut = Truncate("ab", 3)
	if cut {
		t.Fatal("short line was truncated")
	}
}

func TestExtractJournalMessages(t *testing.T) {
	buf := []byte("PRIORITY=6\x00MESSAGE=hello from systemd\x00SYSLOG_IDENTIFIER=sshd\x00")
	got := extractJournalMessages(buf, 10)
	if len(got) != 1 || got[0].Body != "hello from systemd" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseSettingsRejectsUnknown(t *testing.T) {
	_, err := ParseSettings(mustMC(t, map[string]string{"pahts": "/var/log/syslog"}))
	if err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestFileTailerStartsAtEnd(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.log"
	if err := osWrite(path, "old line\n"); err != nil {
		t.Fatal(err)
	}
	tail := newFileTailer()
	s := DefaultSettings()
	s.Paths = []string{path}
	recs, err := tail.Read(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("first read shipped history: %#v", recs)
	}
	if err := osAppend(path, "new line\n"); err != nil {
		t.Fatal(err)
	}
	recs, err = tail.Read(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Body != "new line" {
		t.Fatalf("got %#v", recs)
	}
}

func mustMC(t *testing.T, settings map[string]string) config.ModuleConfig {
	t.Helper()
	return config.ModuleConfig{Enabled: true, Settings: settings}
}

func osWrite(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

func osAppend(path, body string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(body)
	return err
}
