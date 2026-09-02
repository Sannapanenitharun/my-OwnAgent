package logs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDiscoveryRefusesPathsOutsideItsRoots is the security test, and it is the
// reason discovery has an allow-list at all.
//
// The candidate paths come from whatever processes happen to have open, which
// is attacker-influenced: a hostile process can open any file it can reach and
// would be glad to have a root agent tail it off the host. /etc/shadow is the
// specific thing this must never admit.
func TestDiscoveryRefusesPathsOutsideItsRoots(t *testing.T) {
	roots := []string{"/var/log"}
	refused := []string{
		"/etc/shadow",
		"/etc/observability-agent/agent.json",
		"/root/.ssh/id_rsa",
		"/home/ubuntu/secrets.txt",
		"/etc/ssl/private/server.key",
		"relative/path.log",
		"",
	}
	for _, p := range refused {
		if underAnyRoot(p, roots) {
			t.Errorf("discovery would have read %q, which is outside %v", p, roots)
		}
	}
	for _, p := range []string{"/var/log/syslog", "/var/log/nginx/error.log"} {
		if !underAnyRoot(p, roots) {
			t.Errorf("discovery refused %q, which is inside %v", p, roots)
		}
	}
}

// TestARootIsASegmentNotAPrefix. "/var/logger" starts with "/var/log" as a
// string and is a different directory entirely; a prefix comparison would
// admit it and every other sibling that happened to share those characters.
func TestARootIsASegmentNotAPrefix(t *testing.T) {
	for _, p := range []string{"/var/logger/app.log", "/var/log-archive/old.log", "/var/log"} {
		if underAnyRoot(p, []string{"/var/log"}) {
			t.Errorf("%q was admitted by root /var/log on a prefix match", p)
		}
	}
}

// TestTraversalIsRefused. The kernel resolves /proc/<pid>/fd links, so a "…/../…"
// target should never arrive -- but the check is free and this function is one
// caller away from being reused somewhere the input is not pre-resolved.
func TestTraversalIsRefused(t *testing.T) {
	for _, p := range []string{"/var/log/../../etc/shadow", "/var/log/.."} {
		if underAnyRoot(p, []string{"/var/log"}) {
			t.Errorf("traversal %q was admitted", p)
		}
	}
}

// TestDiscoveredFilesAreTailedAndAttributed drives the portable half of the
// feature with the platform hook stubbed, so it runs everywhere rather than
// only on the machine that has /proc.
func TestDiscoveredFilesAreTailedAndAttributed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nginx-error.log")
	if err := os.WriteFile(path, []byte("first line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	restore := discoverHook
	discoverHook = func(Settings) map[string]logOwner {
		return map[string]logOwner{path: {PID: 4242, Process: "nginx"}}
	}
	t.Cleanup(func() { discoverHook = restore })

	s := DefaultSettings()
	s.Paths = []string{filepath.Join(dir, "nothing-here-*.log")}
	s.DiscoverLogs = true

	tailer := newFileTailer()
	// First read establishes the tail position; discovery must have run by now
	// or the file is never opened at all.
	if _, err := tailer.Read(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, ok := tailer.owners[path]; !ok {
		t.Fatalf("discovery did not register %s; owners=%v", path, tailer.owners)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("upstream timed out\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	recs, err := tailer.Read(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("read %d records, want 1: %+v", len(recs), recs)
	}
	if recs[0].Body != "upstream timed out" {
		t.Errorf("body = %q", recs[0].Body)
	}
	if recs[0].PID != 4242 || recs[0].Process != "nginx" {
		t.Errorf("attribution = pid %d process %q, want 4242/nginx -- this is the whole point of discovering through /proc/<pid>/fd",
			recs[0].PID, recs[0].Process)
	}
}

// TestDiscoveryIsOffUnlessAsked. Reading every process's descriptors and then
// tailing files nobody listed should be a decision, not a surprise on upgrade.
func TestDiscoveryIsOffUnlessAsked(t *testing.T) {
	called := false
	restore := discoverHook
	discoverHook = func(Settings) map[string]logOwner {
		called = true
		return nil
	}
	t.Cleanup(func() { discoverHook = restore })

	s := DefaultSettings()
	s.Paths = []string{filepath.Join(t.TempDir(), "none.log")}
	tailer := newFileTailer()
	if _, err := tailer.Read(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("discovery ran with DiscoverLogs unset")
	}
	if DefaultSettings().DiscoverLogs {
		t.Error("DiscoverLogs defaults on")
	}
}

// TestDiscoveryIsRateLimited. The set of open log files changes when processes
// start, not when lines are written, so the walk must not run at collection
// cadence -- it reads every descriptor of every process.
func TestDiscoveryIsRateLimited(t *testing.T) {
	runs := 0
	restore := discoverHook
	discoverHook = func(Settings) map[string]logOwner {
		runs++
		return nil
	}
	t.Cleanup(func() { discoverHook = restore })

	s := DefaultSettings()
	s.Paths = []string{filepath.Join(t.TempDir(), "none.log")}
	s.DiscoverLogs = true
	s.DiscoverInterval = time.Minute

	now := time.Unix(1_700_000_000, 0)
	tailer := newFileTailer()
	tailer.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		tailer.refreshDiscovery(s)
	}
	if runs != 1 {
		t.Errorf("walked %d times in one interval, want 1", runs)
	}

	now = now.Add(2 * time.Minute)
	tailer.refreshDiscovery(s)
	if runs != 2 {
		t.Errorf("walked %d times after the interval elapsed, want 2", runs)
	}
}

// TestDiscoveredPathsSurviveAProcessRestart. A process that has just died is
// briefly absent from /proc; dropping its log at that moment loses exactly the
// lines that explain why it died.
func TestDiscoveredPathsSurviveAProcessRestart(t *testing.T) {
	restore := discoverHook
	first := true
	discoverHook = func(Settings) map[string]logOwner {
		if first {
			first = false
			return map[string]logOwner{"/var/log/app.log": {PID: 1, Process: "app"}}
		}
		return nil // the process is gone this cycle
	}
	t.Cleanup(func() { discoverHook = restore })

	s := DefaultSettings()
	s.DiscoverLogs = true
	s.DiscoverInterval = time.Nanosecond

	tailer := newFileTailer()
	tailer.refreshDiscovery(s)
	tailer.refreshDiscovery(s)

	if _, ok := tailer.owners["/var/log/app.log"]; !ok {
		t.Error("a discovered path was forgotten the moment its process vanished")
	}
}
