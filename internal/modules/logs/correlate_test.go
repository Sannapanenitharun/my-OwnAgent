package logs

import (
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
)

const (
	tid = "4bf92f3577b34da6a3ce929d0e0e4736"
	sid = "00f067aa0ba902b7"
)

func TestTraceContextIsReadFromRealLogLines(t *testing.T) {
	cases := []struct {
		name        string
		line        string
		trace, span string
	}{
		{"w3c traceparent",
			"GET /cart traceparent=00-" + tid + "-" + sid + "-01", tid, sid},
		{"otel logfmt",
			`ts=2026-08-31 level=info trace_id=` + tid + ` span_id=` + sid + ` msg="ok"`, tid, sid},
		{"json",
			`{"level":"error","trace_id":"` + tid + `","span_id":"` + sid + `","msg":"boom"}`, tid, sid},
		{"dotted keys",
			`trace.id=` + tid + ` span.id=` + sid, tid, sid},
		{"hyphenated",
			`trace-id=` + tid + ` span-id=` + sid, tid, sid},
		{"spring otel mdc",
			`INFO [svc,` + tid + `,` + sid + `] otelTraceID=` + tid + ` otelSpanID=` + sid, tid, sid},
		{"trace without span",
			`level=warn trace_id=` + tid + ` msg="no span here"`, tid, ""},
		{"uppercase id is kept as written",
			`trace_id=` + strings.ToUpper(tid), strings.ToUpper(tid), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotT, gotS, ok := detectTrace(tc.line)
			if !ok {
				t.Fatalf("no trace found in %q", tc.line)
			}
			if gotT != tc.trace {
				t.Errorf("trace = %q, want %q", gotT, tc.trace)
			}
			if gotS != tc.span {
				t.Errorf("span = %q, want %q", gotS, tc.span)
			}
		})
	}
}

// TestNothingIsCorrelatedByAccident is the important half. A WRONG correlation
// is worse than none: it attaches a log line to somebody else's request, and an
// operator following it is being actively misled.
func TestNothingIsCorrelatedByAccident(t *testing.T) {
	lines := []string{
		"",
		"GET /health 200 4ms",
		// A UUID is hex-ish but has hyphens in the wrong places and no key.
		"user 4bf92f35-77b3-4da6-a3ce-929d0e0e4736 logged in",
		// A bare 32-hex run with nothing declaring it a trace.
		"checksum " + tid,
		// A different field that merely contains the key name.
		"parent_trace_id=" + tid,
		"trace_id_hash=" + tid,
		// Too short, and too long: a longer hex run is a different identifier,
		// and truncating it would invent a correlation.
		"trace_id=4bf92f3577b34da6",
		"trace_id=" + tid + "abcdef",
		// The all-zero id means "no trace"; joining on it would correlate
		// every uninstrumented line with every other one.
		"trace_id=00000000000000000000000000000000",
		"traceparent=00-00000000000000000000000000000000-0000000000000000-00",
		// Not hex.
		"trace_id=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			if id, _, ok := detectTrace(line); ok {
				t.Errorf("correlated %q to trace %q; nothing in it declares one", line, id)
			}
		})
	}
}

// TestOnlyTheHeadOfTheLineIsRead. Trace context is a field near the front in
// every convention; a 32-hex run deep inside a payload is far more likely to be
// a checksum, and scanning for it would also put this on the hot path.
func TestOnlyTheHeadOfTheLineIsScannedForTrace(t *testing.T) {
	long := "request completed " + strings.Repeat("x", 4096) + " trace_id=" + tid
	if _, _, ok := detectTrace(long); ok {
		t.Error("a trace id was read from beyond the scan window")
	}
}

// TestTraceparentWinsOverKeyedFields. traceparent carries both IDs in one
// unambiguous field, so where a line has both it is the authority.
func TestTraceparentWinsOverKeyedFields(t *testing.T) {
	other := "1111111111111111111111111111111f"
	line := "traceparent=00-" + tid + "-" + sid + "-01 trace_id=" + other
	got, _, ok := detectTrace(line)
	if !ok || got != tid {
		t.Errorf("trace = %q ok=%v, want the traceparent value", got, ok)
	}
}

// TestSpanWithoutTraceIsNotReported. A span id alone cannot correlate anything
// -- there is no trace to attach the line to.
func TestSpanWithoutTraceIsNotReported(t *testing.T) {
	if _, _, ok := detectTrace("span_id=" + sid + " msg=orphan"); ok {
		t.Error("a line carrying only a span id was reported as correlated")
	}
}

func TestTraceDetectionIsOnByDefaultAndCanBeDisabled(t *testing.T) {
	if !DefaultSettings().DetectTrace {
		t.Error("trace detection is off by default; logs and spans could never be joined")
	}
	s, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"trace.detect": "false"}})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if s.DetectTrace {
		t.Error("trace.detect=false was ignored")
	}
	if _, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"trace.detekt": "true"}}); err == nil {
		t.Error("a misspelled setting was accepted")
	}
}
