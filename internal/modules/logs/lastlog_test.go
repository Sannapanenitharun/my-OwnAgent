package logs

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// realLastlogRecord is the actual record for UID 1000 from a live Ubuntu
// host, copied byte for byte out of /var/log/lastlog with dd.
//
// It is here rather than synthesised because the whole risk in this file is
// that the offsets are wrong, and a record built from the same constants the
// reader uses would agree with a wrong reader. The host's own `lastlog`
// command rendered this record as:
//
//	ubuntu  pts/1  18.206.107.29  Mon Sep  7 13:09:46 +0000 2026
//
// so the assertions below are against a second implementation, not against me.
const realLastlogRecordHex = "9ab79e6a" + // ll_time  = 0x6a9eb79a
	"7074732f31" + // ll_line  = "pts/1"
	"000000000000000000000000000000000000000000000000000000" + // padding to 36
	"31382e3230362e3130372e3239" // ll_host = "18.206.107.29"

func realLastlogRecord(t *testing.T) []byte {
	t.Helper()
	head, err := hex.DecodeString(realLastlogRecordHex)
	if err != nil {
		t.Fatalf("bad test fixture: %v", err)
	}
	if len(head) > lastlogRecordLen {
		t.Fatalf("fixture is %d bytes, longer than a record", len(head))
	}
	// The rest of the record on the real host is NUL padding, which is what a
	// zero-filled tail reproduces exactly.
	b := make([]byte, lastlogRecordLen)
	copy(b, head)
	return b
}

// TestLastlogDecodesTheRealRecord pins every field against the host's own
// lastlog output.
func TestLastlogDecodesTheRealRecord(t *testing.T) {
	got := decodeLastlog(1000, realLastlogRecord(t))

	if !got.Present {
		t.Fatal("a record with a login time reported absent")
	}
	if got.UID != 1000 {
		t.Errorf("uid = %d, want 1000 -- the UID is the record's index, not a field", got.UID)
	}
	if got.Line != "pts/1" {
		t.Errorf("line = %q, want pts/1", got.Line)
	}
	if got.Host != "18.206.107.29" {
		t.Errorf("host = %q, want 18.206.107.29", got.Host)
	}
	// What `lastlog` on the host printed: Mon Sep 7 13:09:46 +0000 2026.
	want := time.Date(2026, 9, 7, 13, 9, 46, 0, time.UTC)
	if !got.When.Equal(want) {
		t.Errorf("when = %v, want %v", got.When, want)
	}
}

// TestNeverLoggedInIsAbsent. 1000 of the 1001 entries on the host are this
// case, and it is also what a hole in the sparse file reads as.
func TestNeverLoggedInIsAbsent(t *testing.T) {
	if got := decodeLastlog(0, make([]byte, lastlogRecordLen)); got.Present {
		t.Error("an all-zero record was reported as a login")
	}
	if msg := lastlogMessage(decodeLastlog(0, make([]byte, lastlogRecordLen))); msg != "" {
		t.Errorf("an absent record produced %q", msg)
	}
}

// TestATerminalWithNoTimestampIsNotALogin guards the corrupt-record path: a
// zero ll_time with a populated ll_line must not invent a login at the epoch.
func TestATerminalWithNoTimestampIsNotALogin(t *testing.T) {
	b := make([]byte, lastlogRecordLen)
	copy(b[llOffLine:], "pts/9")
	if decodeLastlog(7, b).Present {
		t.Error("a record with no timestamp was reported as a login")
	}
}

// TestUIDComesFromThePosition. There is no UID field; getting this wrong
// attributes every login to the wrong account, which is the worst possible
// failure for a security surface and would still look like working code.
func TestUIDComesFromThePosition(t *testing.T) {
	buf := make([]byte, lastlogRecordLen*4)
	// Populate only the record at index 2.
	copy(buf[2*lastlogRecordLen:], realLastlogRecord(t))

	got := lastlogRecords(buf, 0)
	if len(got) != 1 {
		t.Fatalf("decoded %d records, want 1", len(got))
	}
	if got[0].UID != 2 {
		t.Errorf("uid = %d, want 2 -- derived from the record's offset", got[0].UID)
	}

	// A buffer read from a later offset carries a first-UID base.
	got = lastlogRecords(buf, 500)
	if len(got) != 1 || got[0].UID != 502 {
		t.Errorf("with base 500 got %+v, want uid 502", got)
	}
}

// TestPartialTailIsNotHeldBack. Unlike utmp, this file is written in place at
// fixed offsets and never appended to, so a short tail is permanent: holding
// it back would stall on the same bytes forever.
func TestPartialTailIsNotHeldBack(t *testing.T) {
	buf := append(realLastlogRecord(t), make([]byte, 100)...)
	if got := lastlogRecords(buf, 0); len(got) != 1 {
		t.Errorf("decoded %d records from one and a fragment, want 1", len(got))
	}
}

func TestLastlogMessageReadsAsState(t *testing.T) {
	r := decodeLastlog(1000, realLastlogRecord(t))
	r.User = "ubuntu"
	msg := lastlogMessage(r)
	for _, want := range []string{"last login", `"ubuntu"`, "18.206.107.29", "pts/1", "2026-09-07T13:09:46Z"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	// It must not read as an event that just happened -- the timestamp in it
	// can be years old.
	if strings.HasPrefix(msg, "login") {
		t.Errorf("message %q reads as a fresh login event", msg)
	}
}

// TestAnEntryWithNoAccountIsStillReported. A lastlog row whose UID has no
// passwd line means the account was deleted after being used, which is
// precisely what an audit wants surfaced rather than hidden.
func TestAnEntryWithNoAccountIsStillReported(t *testing.T) {
	r := decodeLastlog(4242, realLastlogRecord(t))
	msg := lastlogMessage(r) // User deliberately left unresolved
	if !strings.Contains(msg, "deleted uid 4242") {
		t.Errorf("message %q does not flag the missing account", msg)
	}
}

func TestParsePasswdUIDs(t *testing.T) {
	content := []byte(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
		"toor:x:0:0:duplicate uid:/root:/bin/bash",
		"",
		"# a comment, which is not a passwd entry",
		"malformed-line-with-no-colons",
	}, "\n"))

	got := parsePasswdUIDs(content)
	if got[0] != "root" {
		t.Errorf("uid 0 = %q, want root -- the first entry must win over toor "+
			"so the mapping does not depend on map iteration order", got[0])
	}
	if got[1000] != "ubuntu" {
		t.Errorf("uid 1000 = %q, want ubuntu", got[1000])
	}
	if len(got) != 3 {
		t.Errorf("parsed %d entries (%v), want 3", len(got), got)
	}
}

// TestTheSparseFileCapIsMeaningful. lastlog is addressed by UID, so a single
// login by a directory-service UID in the billions makes the file nominally
// hundreds of gigabytes of holes. The cap is what stops a linear walk of it.
func TestTheSparseFileCapIsMeaningful(t *testing.T) {
	if maxLastlogBytes%lastlogRecordLen == 0 {
		// Not a requirement, just a note for the reader: the cap is a byte
		// count, and it is fine for it to land mid-record because the decoder
		// only ever consumes whole records.
		t.Log("cap happens to be record-aligned")
	}
	accounts := maxLastlogBytes / lastlogRecordLen
	if accounts < 10000 {
		t.Errorf("cap admits only %d accounts, which is too few for a real host", accounts)
	}
	// A UID of two billion would need this many bytes; the cap must be far
	// below it or the guard does nothing.
	if int64(maxLastlogBytes) >= int64(2_000_000_000)*lastlogRecordLen {
		t.Error("cap does not actually bound a sparse file addressed by a large UID")
	}
}

// TestRotatedArchivesAreNotTailed. The widened globs match whole directories
// now, and a fortnight of nginx retention would otherwise spend the entire
// max.files budget on files whose contents already shipped when they were live.
func TestRotatedArchivesAreNotTailed(t *testing.T) {
	rotated := []string{
		"syslog.1", "access.log.2", "error.log.14",
		"syslog.2.gz", "auth.log.gz", "messages.xz", "daemon.log.bz2",
		"app.log.zst", "old.log.old", "config.bak",
		"access.log.20260907", // logrotate dateext
	}
	for _, name := range rotated {
		if !looksRotated(name) {
			t.Errorf("%q was not recognised as a rotated archive", name)
		}
	}

	live := []string{
		"syslog", "auth.log", "access_log", "error_log", "dmesg",
		"sar26", "0.log", "amazon-ssm-agent.log",
		// The SSM audit trail names the LIVE file by date with no separator.
		// Treating a date in a name as rotation would drop it.
		"amazon-ssm-agent-audit-2026-08-26",
		// A container log named by hash, and a unit named with a dot.
		"a1b2c3-json.log", "systemd-resolved.log",
	}
	for _, name := range live {
		if looksRotated(name) {
			t.Errorf("%q was dropped as rotated, but it is a live log", name)
		}
	}
}
