package diagnostics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecorderBoundsRetention(t *testing.T) {
	// A failing module can emit diagnostics at high frequency. The recorder
	// must convert that into dropped records, never into unbounded growth.
	r := NewRecorder(4)
	for i := 0; i < 100; i++ {
		r.Record(Record{Code: CodeStartFailed, Source: "host", Message: "boom"})
	}
	if got := len(r.Records()); got != 4 {
		t.Fatalf("retained %d records, want 4", got)
	}
	if got := r.Dropped(); got != 96 {
		t.Fatalf("dropped = %d, want 96", got)
	}
}

func TestRecorderRetainsNewest(t *testing.T) {
	r := NewRecorder(2)
	r.Record(Record{Message: "first"})
	r.Record(Record{Message: "second"})
	r.Record(Record{Message: "third"})

	got := r.Records()
	if len(got) != 2 || got[0].Message != "second" || got[1].Message != "third" {
		t.Fatalf("retained %+v, want the two newest records", got)
	}
}

func TestRecorderStampsTimestamp(t *testing.T) {
	r := NewRecorder(4)
	fixed := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	r.SetClock(func() time.Time { return fixed })
	r.Record(Record{Message: "x"})

	if got := r.Records()[0].Timestamp; !got.Equal(fixed) {
		t.Fatalf("timestamp = %v, want %v", got, fixed)
	}
}

func TestRecorderPreservesExplicitTimestamp(t *testing.T) {
	r := NewRecorder(4)
	want := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	r.Record(Record{Message: "x", Timestamp: want})
	if got := r.Records()[0].Timestamp; !got.Equal(want) {
		t.Fatalf("timestamp = %v, want %v", got, want)
	}
}

func TestScopedSinkStampsSourceAndCannotBeForged(t *testing.T) {
	// A module must not be able to attribute a diagnostic to another module.
	r := NewRecorder(8)
	sink := Scoped("process", r)
	sink.Record(Record{Source: "host", Message: "attempted forgery"})

	recs := r.Records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Source != "process" {
		t.Fatalf("source = %q, want %q", recs[0].Source, "process")
	}
}

func TestBySource(t *testing.T) {
	r := NewRecorder(8)
	Scoped("host", r).Record(Record{Message: "a"})
	Scoped("logs", r).Record(Record{Message: "b"})
	Scoped("host", r).Record(Record{Message: "c"})

	if got := len(r.BySource("host")); got != 2 {
		t.Fatalf("BySource(host) returned %d records, want 2", got)
	}
	if got := len(r.BySource("absent")); got != 0 {
		t.Fatalf("BySource(absent) returned %d records, want 0", got)
	}
}

func TestUnsupportedHelper(t *testing.T) {
	rec := Unsupported("ebpf", "kernel 4.9 lacks BTF")
	if rec.Code != CodeUnsupported {
		t.Fatalf("code = %q, want %q", rec.Code, CodeUnsupported)
	}
	if rec.Severity != Warn {
		t.Fatalf("severity = %v, want Warn: unsupported is a capability boundary, not a failure", rec.Severity)
	}
}

func TestRecordStringIsDeterministic(t *testing.T) {
	rec := Record{
		Code:     CodeUnsupported,
		Severity: Warn,
		Source:   "ebpf",
		Message:  "not supported",
		Attrs:    map[string]string{"kernel": "4.9", "arch": "arm64"},
	}
	first := rec.String()
	for i := 0; i < 50; i++ {
		if got := rec.String(); got != first {
			t.Fatalf("String() is not deterministic:\n%s\n%s", first, got)
		}
	}
	// Attributes must be sorted so operators can diff two renderings.
	if !strings.Contains(first, "arch=arm64 kernel=4.9") {
		t.Fatalf("attributes not sorted in %q", first)
	}
}

func TestRecorderIsConcurrencySafe(t *testing.T) {
	r := NewRecorder(64)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); r.Record(Record{Source: "a", Message: "m"}) }()
		go func() { defer wg.Done(); _ = r.Records() }()
		go func() { defer wg.Done(); _ = r.Dropped() }()
	}
	wg.Wait()
}
