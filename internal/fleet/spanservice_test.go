package fleet

import "testing"

// TestSpanServiceNeverNamesTheAgent guards against a wrong answer, which is
// worse than a missing one.
//
// The batch's resource belongs to the AGENT, not to whatever sent the span. A
// fallback to it labelled every span from an application that declared no
// service.name as "observability-agent", pointing an operator at the collector
// instead of at the thing that actually emitted the span.
func TestSpanServiceNeverNamesTheAgent(t *testing.T) {
	if got := spanService(nil); got != "" {
		t.Errorf("service = %q for a span that declared none, want empty", got)
	}
	if got := spanService(map[string]string{"http.method": "GET"}); got != "" {
		t.Errorf("service = %q, want empty: no attribute names a service", got)
	}
}

func TestSpanServiceReadsTheSendersOwnName(t *testing.T) {
	for _, key := range []string{"service.name", "service_name"} {
		if got := spanService(map[string]string{key: "checkout-api"}); got != "checkout-api" {
			t.Errorf("service from %s = %q", key, got)
		}
	}
}

// TestDottedKeyWinsOverUnderscored: service.name is the OTel convention, and
// an application that somehow sets both means the conventional one.
func TestDottedKeyWinsOverUnderscored(t *testing.T) {
	got := spanService(map[string]string{"service_name": "legacy", "service.name": "checkout"})
	if got != "checkout" {
		t.Errorf("service = %q, want the conventional service.name", got)
	}
}
