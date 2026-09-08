package logs

import (
	"strings"
	"testing"
	"time"
)

func mlSettings() Settings {
	s := DefaultSettings()
	s.Multiline = MultilineAuto
	return s
}

func fileRec(path, body string) Record {
	return Record{Body: body, Source: SourceFiles, File: path}
}

// feed pushes lines through the aggregator with detection already settled, so
// a test does not have to send 500 warm-up lines to reach the behaviour it is
// about.
func feed(m *multiline, s Settings, path string, lines ...string) []Record {
	var out []Record
	for _, l := range lines {
		out = append(out, m.Process([]Record{fileRec(path, l)}, s)...)
	}
	return out
}

func decide(m *multiline, path string, aggregate bool) {
	m.states[path] = &mlFile{decided: true, aggregate: aggregate, firstSeen: m.now()}
}

// TestAStackTraceBecomesOneRecord is the whole point of the feature.
func TestAStackTraceBecomesOneRecord(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	decide(m, "/var/log/app.log", true)

	got := feed(m, s, "/var/log/app.log",
		"2026-09-07 14:26:25 ERROR Unhandled exception",
		"java.lang.NullPointerException: boom",
		"        at com.foo.Bar.baz(Bar.java:42)",
		"        at com.foo.Qux.run(Qux.java:17)",
		"2026-09-07 14:26:26 INFO recovered",
	)

	if len(got) != 1 {
		t.Fatalf("emitted %d records mid-stream, want 1 (the completed trace)", len(got))
	}
	body := got[0].Body
	for _, want := range []string{"Unhandled exception", "NullPointerException", "Bar.java:42", "Qux.java:17"} {
		if !strings.Contains(body, want) {
			t.Errorf("aggregated record missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "recovered") {
		t.Error("the next record's line was folded into the previous one")
	}
	if n := strings.Count(body, "\n"); n != 3 {
		t.Errorf("record has %d newlines, want 3 -- line structure must survive", n)
	}

	// The second record is still open; it is released when it goes idle.
	m.now = func() time.Time { return time.Now().Add(time.Hour) }
	rest := m.FlushIdle(s)
	if len(rest) != 1 || !strings.Contains(rest[0].Body, "recovered") {
		t.Fatalf("idle flush returned %+v", rest)
	}
}

// TestAFileWithoutTimestampsIsNeverAggregated is the safety property. Without
// it the aggregation rule would collapse such a file into one endless record.
func TestAFileWithoutTimestampsIsNeverAggregated(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	path := "/var/log/plain.log"

	var got []Record
	for i := 0; i < detectSamples+50; i++ {
		got = append(got, m.Process([]Record{fileRec(path, "just some text with no stamp")}, s)...)
	}
	if len(got) != detectSamples+50 {
		t.Fatalf("emitted %d records from %d lines; a file with no timestamps must pass straight through",
			len(got), detectSamples+50)
	}
	st := m.states[path]
	if !st.decided || st.aggregate {
		t.Errorf("detection decided=%v aggregate=%v, want decided with aggregation off", st.decided, st.aggregate)
	}
}

// TestLinesAreNotHeldDuringDetection. Datadog sends single lines while it is
// still deciding, and so must we: buffering instead would delay every line on
// every new file by the length of the detection window.
func TestLinesAreNotHeldDuringDetection(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	got := feed(m, s, "/var/log/new.log",
		"2026-09-07 14:26:25 one",
		"  continuation that would be folded later",
		"2026-09-07 14:26:26 two",
	)
	if len(got) != 3 {
		t.Errorf("emitted %d records during detection, want all 3 passed through", len(got))
	}
}

// TestDetectionThreshold checks the verdict at the boundary, using a file that
// is exactly half timestamped.
func TestDetectionThreshold(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	path := "/var/log/half.log"
	for i := 0; i < detectSamples; i++ {
		body := "        at com.foo.Bar(Bar.java:1)"
		if i%2 == 0 {
			body = "2026-09-07 14:26:25 ERROR boom"
		}
		m.Process([]Record{fileRec(path, body)}, s)
	}
	st := m.states[path]
	if !st.decided {
		t.Fatal("detection did not conclude after the sample limit")
	}
	if !st.aggregate {
		t.Errorf("a file that is 50%% timestamped was refused; matched=%d sampled=%d",
			st.matched, st.sampled)
	}
}

// TestOversizeRecordsSplitRatherThanTruncate. Losing the fact that lines were
// contiguous is recoverable; losing the lines is not.
func TestOversizeRecordsSplitRatherThanTruncate(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	path := "/var/log/huge.log"
	decide(m, path, true)

	lines := []string{"2026-09-07 14:26:25 start"}
	for i := 0; i < maxMultilineLines+20; i++ {
		lines = append(lines, "        at frame")
	}
	got := feed(m, s, path, lines...)
	if len(got) == 0 {
		t.Fatal("nothing was emitted; the line cap did not flush")
	}
	total := 0
	for _, r := range got {
		total += strings.Count(r.Body, "\n") + 1
	}
	m.now = func() time.Time { return time.Now().Add(time.Hour) }
	for _, r := range m.FlushIdle(s) {
		total += strings.Count(r.Body, "\n") + 1
	}
	if total != len(lines) {
		t.Errorf("recovered %d lines from %d fed; the cap dropped data", total, len(lines))
	}
}

// TestOnlyFileRecordsAreAggregated. A journald entry is already a whole
// message and the synthetic sources build their own lines; folding either
// would corrupt them.
func TestOnlyFileRecordsAreAggregated(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	recs := []Record{
		{Body: "a journal message with no stamp", Source: SourceJournald},
		{Body: "failed login for user \"root\" from 1.2.3.4", Source: SourceLogins, File: "/var/log/btmp"},
		{Body: "last login for user \"ubuntu\"", Source: SourceLastlog, File: "/var/log/lastlog"},
	}
	got := m.Process(recs, s)
	if len(got) != 3 {
		t.Errorf("emitted %d of 3 non-file records; they must pass through untouched", len(got))
	}
}

// TestTurningItOffReleasesHeldRecords. A pending record must not be stranded
// in memory by a config change.
func TestTurningItOffReleasesHeldRecords(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	path := "/var/log/app.log"
	decide(m, path, true)
	feed(m, s, path, "2026-09-07 14:26:25 held", "  continuation")

	s.Multiline = MultilineOff
	got := m.Process([]Record{fileRec(path, "next line")}, s)
	if len(got) != 2 {
		t.Fatalf("got %d records, want the released one plus the new one", len(got))
	}
	if !strings.Contains(got[0].Body, "held") {
		t.Errorf("the held record was not released first: %+v", got)
	}
}

// TestExplicitPatternMustMatchAtLineStart. Datadog is explicit that patterns
// "cannot be matched mid-line", and the distinction matters: a line that
// merely mentions a date is not a record boundary.
func TestExplicitPatternMustMatchAtLineStart(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	s.Multiline = MultilinePattern
	s.MultilinePattern = `\d{4}-\d{2}-\d{2}`
	path := "/var/log/app.log"
	decide(m, path, true)

	got := feed(m, s, path,
		"2026-09-07 first record",
		"continued, and mentions 2026-09-08 in the middle",
		"2026-09-09 second record",
	)
	if len(got) != 1 {
		t.Fatalf("emitted %d records, want 1 -- the mid-line date split a record", len(got))
	}
	if !strings.Contains(got[0].Body, "mentions 2026-09-08") {
		t.Errorf("the continuation was not folded in: %q", got[0].Body)
	}
}

func TestRecordStartShapes(t *testing.T) {
	starts := []string{
		"2026-09-07T14:26:25.355250+00:00 host agent[886]: export ok",
		"2026-09-07 14:26:25,123 ERROR boom",
		"2026/09/07 14:26:25 boom",
		"[2026-09-07 14:26:25] boom",
		"Sep  7 14:26:25 host sshd[1]: accepted",
		"Sep 17 14:26:25 host sshd[1]: accepted",
		"Mon Jan  2 15:04:05 2026 boom",
		"Mon, 02 Jan 2026 15:04:05 GMT boom",
		"Sep 07, 2026 2:26:25 PM com.foo.Bar main",
		"I0907 14:26:25.123456       1 server.go:42] serving",
		"E0907 14:26:25.123456       1 server.go:42] failed",
	}
	for _, line := range starts {
		if !startsWithTimestamp(line) {
			t.Errorf("not recognised as a record start: %q", line)
		}
	}

	continuations := []string{
		"        at com.foo.Bar.baz(Bar.java:42)",
		"java.lang.NullPointerException: boom",
		"Caused by: java.lang.IllegalStateException",
		"  File \"/app/main.py\", line 12, in <module>",
		"Traceback (most recent call last):",
		`{"level":"info","msg":"hello"}`,
		"[   12.345678] kernel: usb 1-1: new device",
		"127.0.0.1 - - [07/Sep/2026:14:26:25 +0000] \"GET / HTTP/1.1\" 200",
		"the time is 14:26:25 and nothing else",
		"",
		"   ",
	}
	for _, line := range continuations {
		if startsWithTimestamp(line) {
			t.Errorf("wrongly treated as a record start: %q", line)
		}
	}
}

// TestKernelRingAndAccessLogsAreLeftAlone pins two real formats that must fail
// detection: dmesg opens with a bracketed uptime and an access log opens with
// an address. Both are single-line formats, and aggregating either would be
// pure damage.
func TestKernelRingAndAccessLogsAreLeftAlone(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	for path, line := range map[string]string{
		"/var/log/dmesg":           "[   12.345678] kernel: usb 1-1: new high-speed USB device",
		"/var/log/cups/access_log": `127.0.0.1 - - [07/Sep/2026:14:26:25 +0000] "POST /jobs HTTP/1.1" 200 143`,
	} {
		for i := 0; i < detectSamples; i++ {
			m.Process([]Record{fileRec(path, line)}, s)
		}
		if st := m.states[path]; st.aggregate {
			t.Errorf("%s was marked for aggregation", path)
		}
	}
}

func TestStateMapIsBounded(t *testing.T) {
	m := newMultiline()
	s := mlSettings()
	for i := 0; i < maxMultilineFiles+200; i++ {
		m.Process([]Record{fileRec("/var/log/rotated-"+strings.Repeat("x", i%7)+itoaTest(i)+".log", "line")}, s)
	}
	m.FlushIdle(s)
	if len(m.states) > maxMultilineFiles {
		t.Errorf("state map holds %d entries, above the %d cap", len(m.states), maxMultilineFiles)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
