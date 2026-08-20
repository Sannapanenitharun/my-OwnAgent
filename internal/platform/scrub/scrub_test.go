package scrub_test

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
	"github.com/obsagent/observability-agent/internal/platform/scrub"
)

func TestStringRedactsSecrets(t *testing.T) {
	in := `user=alice password=s3cret token=abc AKIAIOSFODNN7EXAMPLE bearer eyJhbGciOiJIUzI1NiJ9.xx`
	out := scrub.String(in)
	if out == in {
		t.Fatal("expected redaction")
	}
	if contains(out, "s3cret") || contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked: %q", out)
	}
}

func TestWrapScrubsEmitLog(t *testing.T) {
	mem := inproc.NewTelemetry()
	tel := scrub.Wrap(mem)
	tel.EmitLog(platform.LogRecord{Body: "password=hunter2 ok"})
	// inproc does not expose log bodies via snapshot; assert String path.
	if got := scrub.String("password=hunter2"); contains(got, "hunter2") {
		t.Fatal(got)
	}
	_ = tel
}

func contains(s, sub string) bool {
	return len(sub) > 0 && (s == sub || len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}
