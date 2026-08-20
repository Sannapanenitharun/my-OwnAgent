package process

import (
	"strings"
	"testing"
	"time"
)

// These run on every developer platform, not just Linux, which is the whole
// reason parse.go carries no build tag. Kernel text formats are where collectors
// historically get subtly wrong numbers, and those defects are only cheap to
// find if the tests run everywhere.

const pageSize4K = 4096

// realStatLine is a genuine /proc/PID/stat line, trimmed of nothing.
const realStatLine = `1234 (nginx) S 1 1234 1234 0 -1 4194624 512 0 0 0 150 75 0 0 20 0 4 0 987654 12345678 900 18446744073709551615 1 1 0 0 0 0 0 4096 134489087 0 0 0 17 2 0 0 0 0 0 0 0 0 0 0 0 0 0`

func TestParseStatReadsEveryFieldFromTheRightColumn(t *testing.T) {
	info, _, err := parseStat([]byte(realStatLine), pageSize4K, nil)
	if err != nil {
		t.Fatalf("parseStat: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"pid", info.PID, PID(1234)},
		{"name", info.Name, "nginx"},
		{"state", info.State, StateSleeping},
		{"ppid", info.PPID, PID(1)},
		{"threads", info.Threads, KnownU64(4)},
		{"start", info.StartRaw, uint64(987654)},
		{"virtual", info.VirtualBytes, KnownU64(12345678)},
		{"rss", info.RSSBytes, KnownU64(900 * pageSize4K)},
		// 150 ticks at 100 Hz is 1.5 seconds.
		{"user cpu", info.CPUUserNanos, KnownU64(150 * uint64(10*time.Millisecond))},
		{"system cpu", info.CPUSystemNanos, KnownU64(75 * uint64(10*time.Millisecond))},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestParseStatSurvivesHostileProcessNames is the single most important parser
// test in this module.
//
// Field 2 of /proc/PID/stat is the executable name, wrapped in parentheses and
// NOT escaped. A process may legally name itself ") 0 0 0 0 (" — and a hostile
// one will, because doing so lets it choose the values the agent reports for
// every field after it. Splitting on whitespace, or scanning for the first ')',
// hands an attacker control of the telemetry.
func TestParseStatSurvivesHostileProcessNames(t *testing.T) {
	tests := []struct {
		desc     string
		comm     string
		wantName string
	}{
		{"plain", "nginx", "nginx"},
		{"space", "postgres writer", "postgres writer"},
		{"closing paren", "evil)", "evil)"},
		{"opening paren", "(evil", "(evil"},
		{"forged fields", ") 9 9999 9 9 9 9 9 9 9 9 9 9 9 (", ") 9 9999 9 9 9 9 9 9 9 9 9 9 9 ("},
		{"only parens", ")(", ")("},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Everything after the comm is fixed, so any misparse shows up as a
			// wrong PPID or a wrong start time rather than as an error.
			line := "1234 (" + tc.comm + ") S 77 1234 1234 0 -1 0 0 0 0 0 150 75 0 0 20 0 4 0 987654 12345678 900"
			info, _, err := parseStat([]byte(line), pageSize4K, nil)
			if err != nil {
				t.Fatalf("parseStat: %v", err)
			}
			if info.Name != tc.wantName {
				t.Errorf("name = %q, want %q", info.Name, tc.wantName)
			}
			if info.PPID != 77 {
				t.Errorf("ppid = %d, want 77 — the comm field shifted the columns", info.PPID)
			}
			if info.StartRaw != 987654 {
				t.Errorf("start = %d, want 987654 — the comm field shifted the columns", info.StartRaw)
			}
			if info.Threads != KnownU64(4) {
				t.Errorf("threads = %v, want 4", info.Threads)
			}
		})
	}
}

func TestParseStatRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		desc string
		line string
	}{
		{"empty", ""},
		{"no comm", "1234 nginx S 1"},
		{"no closing paren", "1234 (nginx S 1"},
		{"non-numeric pid", "abc (nginx) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22"},
		{"truncated before start time", "1234 (nginx) S 1 2 3"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if _, _, err := parseStat([]byte(tc.line), pageSize4K, nil); err == nil {
				t.Error("malformed stat line was accepted")
			}
		})
	}
}

func TestParseStatWithoutStartTimeIsRejected(t *testing.T) {
	// Without a start stamp there is no instance key, and without an instance
	// key a recycled PID would silently inherit the previous process's counter
	// baselines. Omitting the process is the lesser harm.
	line := "1234 (nginx) S 1 1234 1234 0 -1 0 0 0 0 0 150 75 0 0 20 0 4 0"
	if _, _, err := parseStat([]byte(line), pageSize4K, nil); err == nil {
		t.Error("a stat line with no start time was accepted")
	}
}

func TestParseStatMapsEveryDocumentedState(t *testing.T) {
	tests := map[byte]State{
		'R': StateRunning, 'S': StateSleeping, 'D': StateDiskSleep,
		'T': StateStopped, 't': StateStopped, 'Z': StateZombie,
		'X': StateZombie, 'I': StateIdle, 'W': StateUnknown, '?': StateUnknown,
	}
	for c, want := range tests {
		line := "1 (init) " + string(c) + " 0 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10"
		info, _, err := parseStat([]byte(line), pageSize4K, nil)
		if err != nil {
			t.Fatalf("state %q: %v", c, err)
		}
		if info.State != want {
			t.Errorf("state %q = %v, want %v", c, info.State, want)
		}
	}
}

func TestParseIOPrefersRealBlockIOOverCachedBytes(t *testing.T) {
	// rchar and wchar count bytes passed to read(2) and write(2), including
	// those served from page cache. Reporting them as disk I/O overstates it by
	// orders of magnitude on a host with a warm cache.
	data := []byte(strings.Join([]string{
		"rchar: 999999999",
		"wchar: 888888888",
		"syscr: 120",
		"syscw: 45",
		"read_bytes: 4096",
		"write_bytes: 8192",
		"cancelled_write_bytes: 0",
	}, "\n"))

	io, err := parseIO(data)
	if err != nil {
		t.Fatalf("parseIO: %v", err)
	}
	if io.ReadBytes != KnownU64(4096) {
		t.Errorf("ReadBytes = %v, want 4096 (read_bytes, not rchar)", io.ReadBytes)
	}
	if io.WriteBytes != KnownU64(8192) {
		t.Errorf("WriteBytes = %v, want 8192 (write_bytes, not wchar)", io.WriteBytes)
	}
	if io.ReadOps != KnownU64(120) || io.WriteOps != KnownU64(45) {
		t.Errorf("ops = %v/%v, want 120/45", io.ReadOps, io.WriteOps)
	}
}

func TestParseIORejectsUnrecognisedContent(t *testing.T) {
	if _, err := parseIO([]byte("nothing: useful\n")); err == nil {
		t.Error("io content with no recognised counters was accepted")
	}
}

func TestParseCmdlineSplitsAndBounds(t *testing.T) {
	data := []byte("nginx\x00-c\x00/etc/nginx.conf\x00")
	got := parseCmdline(data, 32, 4096)
	want := []string{"nginx", "-c", "/etc/nginx.conf"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseCmdlineBoundsUntrustedInput(t *testing.T) {
	// argv is entirely under the observed process's control and can be
	// megabytes long. The caps are applied where the untrusted bytes enter.
	huge := strings.Repeat("a\x00", 100000)
	got := parseCmdline([]byte(huge), 32, 4096)
	if len(got) > 32 {
		t.Errorf("returned %d args, want at most 32", len(got))
	}
	total := 0
	for _, a := range got {
		total += len(a)
	}
	if total > 4096 {
		t.Errorf("returned %d bytes, want at most 4096", total)
	}

	if got := parseCmdline(nil, 32, 4096); got != nil {
		t.Errorf("empty cmdline returned %v", got)
	}
}

func TestParseBootTime(t *testing.T) {
	data := []byte("cpu  1 2 3\nintr 0\nctxt 999\nbtime 1700000000\nprocesses 12345\n")
	got, err := parseBootTime(data)
	if err != nil {
		t.Fatalf("parseBootTime: %v", err)
	}
	if got.Unix() != 1700000000 {
		t.Errorf("boot time = %v, want unix 1700000000", got)
	}

	if _, err := parseBootTime([]byte("cpu 1 2 3\n")); err == nil {
		t.Error("stat content with no btime line was accepted")
	}
}

func TestStartTimeFromConvertsTicks(t *testing.T) {
	boot := time.Unix(1700000000, 0)
	// 250 ticks at 100 Hz is 2.5 seconds after boot.
	got := startTimeFrom(boot, 250)
	if want := boot.Add(2500 * time.Millisecond); !got.Equal(want) {
		t.Errorf("start time = %v, want %v", got, want)
	}
}

func TestParseUintRejectsOverflowAndGarbage(t *testing.T) {
	if _, err := parseUint([]byte("18446744073709551616")); err == nil {
		t.Error("an integer past uint64 was accepted")
	}
	for _, s := range []string{"", "-1", "1.5", "0x10", "12a"} {
		if _, err := parseUint([]byte(s)); err == nil {
			t.Errorf("%q was accepted as an integer", s)
		}
	}
	if v, err := parseUint([]byte("18446744073709551615")); err != nil || v != 1<<64-1 {
		t.Errorf("max uint64 = %v, %v", v, err)
	}
}

func TestSplitFieldsIsAllocationFreeAcrossCalls(t *testing.T) {
	var dst [][]byte
	// The input is hoisted: a string-to-[]byte conversion inside the loop would
	// allocate once per iteration and measure the conversion, not the parser.
	line := []byte("a b  c\td   e")
	allocs := testingAllocs(func() {
		for i := 0; i < 1000; i++ {
			dst = splitFields(line, dst)
		}
	})
	if allocs > 2 {
		t.Errorf("splitFields allocated %v times across 1000 reused calls", allocs)
	}
	if len(dst) != 5 {
		t.Errorf("got %d fields, want 5", len(dst))
	}
}

func testingAllocs(fn func()) float64 { return testing.AllocsPerRun(1, fn) }
