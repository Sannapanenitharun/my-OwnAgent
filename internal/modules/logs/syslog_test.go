package logs

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRFC5424(t *testing.T) {
	const line = `<34>1 2026-09-07T22:14:15.003Z mymachine.example.com su 1234 ID47 - 'su root' failed for lonvick`
	m := parseSyslog(line)

	if !m.HasPriority {
		t.Fatal("priority not parsed")
	}
	// PRI 34 is facility 4 (auth), severity 2 (critical).
	if m.Priority != 2 || m.Facility != 4 {
		t.Errorf("severity/facility = %d/%d, want 2/4", m.Priority, m.Facility)
	}
	if m.Hostname != "mymachine.example.com" || m.AppName != "su" || m.PID != 1234 {
		t.Errorf("host/app/pid = %q/%q/%d", m.Hostname, m.AppName, m.PID)
	}
	if m.Message != `'su root' failed for lonvick` {
		t.Errorf("message = %q", m.Message)
	}
	if !m.HasTime || m.Timestamp.Year() != 2026 || m.Timestamp.Minute() != 14 {
		t.Errorf("timestamp = %v", m.Timestamp)
	}
}

func TestParseRFC3164(t *testing.T) {
	const line = `<34>Sep  7 22:14:15 mymachine su[4321]: 'su root' failed for lonvick`
	m := parseSyslog(line)

	if m.Priority != 2 || m.Facility != 4 {
		t.Errorf("severity/facility = %d/%d, want 2/4", m.Priority, m.Facility)
	}
	if m.Hostname != "mymachine" || m.AppName != "su" || m.PID != 4321 {
		t.Errorf("host/app/pid = %q/%q/%d", m.Hostname, m.AppName, m.PID)
	}
	if m.Message != `'su root' failed for lonvick` {
		t.Errorf("message = %q", m.Message)
	}

	// The same format without a PID is at least as common.
	m2 := parseSyslog(`<13>Sep  7 22:14:15 host cron: job finished`)
	if m2.AppName != "cron" || m2.PID != 0 || m2.Message != "job finished" {
		t.Errorf("app/pid/message = %q/%d/%q", m2.AppName, m2.PID, m2.Message)
	}
}

// TestStructuredDataIsStepped over. SD-ELEMENTs contain spaces, brackets and
// escaped quotes, so a naive field split lands in the middle of one and every
// field after it is wrong.
func TestStructuredDataIsStepped(t *testing.T) {
	const line = `<165>1 2026-09-07T22:14:15Z host app - ID [ex@1 iut="3" msg="a ] bracket"][ex2@1 k="v"] the real message`
	m := parseSyslog(line)
	if m.Message != "the real message" {
		t.Errorf("message = %q, want the text after the structured data", m.Message)
	}
}

// TestUnparseableInputIsKeptNotDropped. A relay that silently discards what it
// does not understand is worse than one that forwards it unstructured.
func TestUnparseableInputIsKeptNotDropped(t *testing.T) {
	for _, line := range []string{
		"just some text nobody framed",
		"<not a priority> hello",
		"<999>1 2026-09-07T22:14:15Z host app - - - out of range priority",
	} {
		m := parseSyslog(line)
		if m.Message == "" {
			t.Errorf("input %q produced an empty message", line)
		}
	}
	// An out-of-range PRI must not be accepted as a level.
	if m := parseSyslog("<999>whatever"); m.HasPriority {
		t.Error("priority 999 was accepted; the maximum is 191")
	}
}

// TestAStrayAngleBracketIsNotAPriority guards the parser against a message
// that merely contains "<".
func TestAStrayAngleBracketIsNotAPriority(t *testing.T) {
	m := parseSyslog("<this is a very long thing> and then some text")
	if m.HasPriority {
		t.Error("a long bracketed word was read as a priority")
	}
	if !strings.HasPrefix(m.Message, "<this is") {
		t.Errorf("message = %q, want the input unchanged", m.Message)
	}
}

// --- the listener ---

func startTestListener(t *testing.T, proto SyslogProtocol) (*syslogListener, Settings, string) {
	t.Helper()
	// Port 0 lets the OS choose; loopback because a test must never bind a
	// routable address.
	l := newSyslogListener()
	t.Cleanup(l.Close)

	s := DefaultSettings()
	s.SyslogProtocol = proto

	// Find a free port by binding and releasing one.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	s.SyslogListen = addr

	if _, err := l.Read(context.Background(), s); err != nil {
		t.Fatalf("starting listener on %s: %v", addr, err)
	}
	return l, s, addr
}

func drain(t *testing.T, l *syslogListener, s Settings, want int) []Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got []Record
	for time.Now().Before(deadline) {
		recs, err := l.Read(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, recs...)
		if len(got) >= want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

func TestSyslogOverUDP(t *testing.T) {
	l, s, addr := startTestListener(t, SyslogUDP)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`<34>Sep  7 22:14:15 firewall sshd[99]: refused connection`)); err != nil {
		t.Fatal(err)
	}

	got := drain(t, l, s, 1)
	if len(got) != 1 {
		t.Fatalf("received %d records, want 1", len(got))
	}
	r := got[0]
	if r.Body != "refused connection" || r.Process != "sshd" || r.PID != 99 {
		t.Errorf("record = %+v", r)
	}
	if r.Hostname != "firewall" {
		t.Errorf("hostname = %q, want the sender's declared name", r.Hostname)
	}
	if !r.HasPriority || r.Priority != 2 {
		t.Errorf("priority = %d (set=%v), want 2", r.Priority, r.HasPriority)
	}
	if r.Source != SourceSyslog {
		t.Errorf("source = %q", r.Source)
	}
}

// TestSyslogOverTCPBothFramings. RFC 6587 defines two and senders use both:
// octet-counting prefixes the length, non-transparent framing uses newlines.
func TestSyslogOverTCPBothFramings(t *testing.T) {
	l, s, addr := startTestListener(t, SyslogTCP)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	newlineFramed := `<13>Sep  7 22:14:15 host app: newline framed` + "\n"
	body := `<13>Sep  7 22:14:16 host app: octet counted`
	octetFramed := fmt.Sprintf("%d %s", len(body), body)

	if _, err := conn.Write([]byte(newlineFramed + octetFramed + "\n")); err != nil {
		t.Fatal(err)
	}

	got := drain(t, l, s, 2)
	if len(got) < 2 {
		t.Fatalf("received %d records, want 2: %+v", len(got), got)
	}
	if got[0].Body != "newline framed" {
		t.Errorf("first = %q", got[0].Body)
	}
	if got[1].Body != "octet counted" {
		t.Errorf("second = %q -- octet counting was misread", got[1].Body)
	}
}

// TestTheSenderCannotChooseOurMemory. A declared length is the input that must
// not be trusted: honouring it would let one packet request an allocation of
// any size the sender likes.
func TestTheSenderCannotChooseOurMemory(t *testing.T) {
	l, s, addr := startTestListener(t, SyslogTCP)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Claim two gigabytes, then send nothing.
	if _, err := conn.Write([]byte("2147483647 ")); err != nil {
		t.Fatal(err)
	}
	// The connection must be dropped rather than the allocation attempted.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("connection stayed open after an absurd declared length")
	}
	if recs, _ := l.Read(context.Background(), s); len(recs) != 0 {
		t.Errorf("an unsent message produced %d records", len(recs))
	}
}

// TestALineWithoutANewlineCannotGrowForever. A sender that opens a socket and
// streams bytes with no delimiter must not be able to grow the buffer without
// limit.
func TestALineWithoutANewlineCannotGrowForever(t *testing.T) {
	r := strings.NewReader(strings.Repeat("x", maxSyslogLine*3))
	line, _ := readLimitedLine(bufio.NewReader(r), maxSyslogLine)
	if len(line) > maxSyslogLine {
		t.Errorf("read %d bytes, above the %d cap", len(line), maxSyslogLine)
	}
}

// TestTheQueueIsBoundedAndDropsAreCounted. A remote sender must not be able to
// decide how much memory this process uses, and what is dropped must be
// countable rather than silent.
func TestTheQueueIsBoundedAndDropsAreCounted(t *testing.T) {
	l := newSyslogListener()
	for i := 0; i < maxSyslogQueue+500; i++ {
		l.enqueue("<13>Sep  7 22:14:15 host app: message", nil)
	}
	if got := len(l.queue); got > maxSyslogQueue {
		t.Errorf("queue holds %d, above the %d cap", got, maxSyslogQueue)
	}
	if l.Dropped() != 500 {
		t.Errorf("dropped = %d, want 500", l.Dropped())
	}
	// The newest must survive: a relay's backlog is stale by definition.
	last := l.queue[len(l.queue)-1]
	if last.Body != "message" {
		t.Errorf("last queued record = %q", last.Body)
	}
}

// TestTheObservedAddressFillsInAMissingHostname. The hostname field is
// whatever the sender chose to claim; when it claims nothing, what the network
// saw is better than nothing.
func TestTheObservedAddressFillsInAMissingHostname(t *testing.T) {
	l := newSyslogListener()
	l.enqueue("<13>1 2026-09-07T22:14:15Z - app - - - no hostname given",
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40001})
	if len(l.queue) != 1 {
		t.Fatal("nothing queued")
	}
	if got := l.queue[0].Hostname; got != "198.51.100.7" {
		t.Errorf("hostname = %q, want the peer address", got)
	}
}

// TestTheListenerIsOffByDefault is the security posture, pinned.
//
// This port accepts unauthenticated writes into the log pipeline from anyone
// who can reach it. It must never come up because somebody enabled the logs
// module.
func TestTheListenerIsOffByDefault(t *testing.T) {
	if s := DefaultSettings(); s.SyslogListen != "" {
		t.Errorf("syslog.listen defaults to %q; it must default to disabled", s.SyslogListen)
	}
	l := newSyslogListener()
	defer l.Close()
	recs, err := l.Read(context.Background(), DefaultSettings())
	if err != nil || len(recs) != 0 {
		t.Errorf("a disabled listener returned %d records, err=%v", len(recs), err)
	}
	if l.addr != "" {
		t.Errorf("a disabled listener bound %q", l.addr)
	}
}

// TestClearingTheAddressReleasesThePort. Reconfiguring to empty must actually
// stop listening, or the setting is advisory.
func TestClearingTheAddressReleasesThePort(t *testing.T) {
	l, s, addr := startTestListener(t, SyslogTCP)
	if l.addr != addr {
		t.Fatalf("listener bound %q, want %q", l.addr, addr)
	}

	off := s
	off.SyslogListen = ""
	if _, err := l.Read(context.Background(), off); err != nil {
		t.Fatal(err)
	}
	if l.addr != "" {
		t.Error("listener still reports an address after being disabled")
	}
	// The port must be free for anyone else to take.
	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s was not released: %v", addr, err)
	}
	again.Close()
}

func TestSyslogSettingsValidate(t *testing.T) {
	if _, err := ParseSettings(mustMC(t, map[string]string{"syslog.listen": "not-an-address"})); err == nil {
		t.Error("syslog.listen accepted a value that is not host:port")
	}
	if _, err := ParseSettings(mustMC(t, map[string]string{"syslog.protocol": "sctp"})); err == nil {
		t.Error("syslog.protocol accepted an unsupported transport")
	}
	s, err := ParseSettings(mustMC(t, map[string]string{
		"syslog.listen": "127.0.0.1:5514", "syslog.protocol": "udp",
	}))
	if err != nil {
		t.Fatalf("valid syslog settings rejected: %v", err)
	}
	if s.SyslogListen != "127.0.0.1:5514" || s.SyslogProtocol != SyslogUDP {
		t.Errorf("parsed %+v", s)
	}
}
