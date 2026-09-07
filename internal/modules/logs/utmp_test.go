package logs

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// buildUtmp assembles one 384-byte record at the glibc offsets. It is
// deliberately written from the struct definition rather than from the reader,
// so a wrong offset in utmp.go does not get a matching wrong offset here.
func buildUtmp(typ int16, pid int32, line, user, host string, sec int32, addr []byte) []byte {
	b := make([]byte, utmpRecordLen)
	binary.LittleEndian.PutUint16(b[0:], uint16(typ))
	binary.LittleEndian.PutUint32(b[4:], uint32(pid))
	copy(b[8:8+32], line)
	copy(b[44:44+32], user)
	copy(b[76:76+256], host)
	binary.LittleEndian.PutUint32(b[340:], uint32(sec))
	copy(b[348:348+16], addr)
	return b
}

func TestUtmpDecodesAFailedLogin(t *testing.T) {
	rec := buildUtmp(utLoginProcess, 1234, "ssh:notty", "root", "", 1_700_000_000,
		[]byte{203, 0, 113, 195}) // 203.0.113.195, IPv4 in the first word

	got := decodeUtmp(rec)
	if !got.Present {
		t.Fatal("record reported absent")
	}
	if got.User != "root" || got.Line != "ssh:notty" || got.PID != 1234 {
		t.Errorf("decoded %+v", got)
	}
	if got.Addr != "203.0.113.195" {
		t.Errorf("addr = %q, want 203.0.113.195", got.Addr)
	}
	if !got.When.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Errorf("when = %v", got.When)
	}

	msg := utmpMessage(got, true)
	for _, want := range []string{"failed login", `"root"`, "203.0.113.195", "ssh:notty"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

// TestFixedWidthPaddingNeverReachesTheBody. Every field is a fixed-width C
// array padded with NULs. Shipping the padding would put NUL bytes through the
// pipeline and into whatever renders them.
func TestFixedWidthPaddingNeverReachesTheBody(t *testing.T) {
	rec := buildUtmp(utUserProcess, 9, "pts/0", "ubuntu", "10.0.0.5", 1_700_000_000, nil)
	got := decodeUtmp(rec)
	if strings.ContainsRune(got.User+got.Line+got.Host, 0) {
		t.Fatal("a NUL survived into a decoded field")
	}
	if got.User != "ubuntu" {
		t.Errorf("user = %q -- padding was not trimmed", got.User)
	}
	if msg := utmpMessage(got, false); strings.ContainsRune(msg, 0) {
		t.Errorf("a NUL reached the message: %q", msg)
	}
}

// TestHostnameWinsOverAddress. Both fields can be set; the name is what an
// operator recognises, and printing both would say the same thing twice.
func TestHostnameWinsOverAddress(t *testing.T) {
	rec := buildUtmp(utUserProcess, 1, "pts/1", "deploy", "build.internal", 1_700_000_000,
		[]byte{10, 0, 0, 7})
	got := decodeUtmp(rec)
	if got.Addr != "" {
		t.Errorf("addr was decoded even though a hostname was present: %q", got.Addr)
	}
	if !strings.Contains(utmpMessage(got, false), "build.internal") {
		t.Error("hostname missing from the message")
	}
}

func TestIPv6AddressIsRendered(t *testing.T) {
	addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	got := decodeUtmp(buildUtmp(utLoginProcess, 1, "ssh:notty", "admin", "", 1, addr))
	if got.Addr != "2001:db8::1" {
		t.Errorf("addr = %q, want 2001:db8::1", got.Addr)
	}
}

// TestBookkeepingRecordsProduceNoLine. wtmp is mostly getty and init
// housekeeping. Reporting all of it would bury the two record types an
// operator actually reads.
func TestBookkeepingRecordsProduceNoLine(t *testing.T) {
	for _, typ := range []int16{utInitProcess, utLoginProcess} {
		rec := decodeUtmp(buildUtmp(typ, 1, "tty1", "", "", 1, nil))
		if msg := utmpMessage(rec, false); msg != "" {
			t.Errorf("type %d produced %q, want no line", typ, msg)
		}
	}
	// ...but the same type IS a line when it comes from btmp, where it means
	// somebody failed to log in.
	rec := decodeUtmp(buildUtmp(utLoginProcess, 1, "ssh:notty", "root", "", 1, nil))
	if msg := utmpMessage(rec, true); msg == "" {
		t.Error("a btmp record produced no line")
	}
}

func TestBootAndRunlevelReadPlainly(t *testing.T) {
	if got := utmpMessage(decodeUtmp(buildUtmp(utBootTime, 0, "~", "reboot", "", 1, nil)), false); got != "system boot" {
		t.Errorf("boot record = %q", got)
	}
	if got := utmpMessage(decodeUtmp(buildUtmp(utRunLevel, 0, "~", "runlevel", "", 1, nil)), false); got != "runlevel change" {
		t.Errorf("runlevel record = %q", got)
	}
}

// TestAPartialRecordIsLeftForNextTime. The file is appended to while the read
// runs, so a short tail is normal -- and decoding half a struct would invent a
// login that never happened.
func TestAPartialRecordIsLeftForNextTime(t *testing.T) {
	full := buildUtmp(utUserProcess, 1, "pts/0", "a", "", 1, nil)
	buf := append(append([]byte{}, full...), full[:100]...) // one and a bit

	got, consumed := utmpRecords(buf)
	if len(got) != 1 {
		t.Errorf("decoded %d records from one and a fragment", len(got))
	}
	if consumed != utmpRecordLen {
		t.Errorf("consumed %d bytes, want exactly one record (%d) so the fragment is re-read", consumed, utmpRecordLen)
	}
}

func TestEmptySlotsAreSkipped(t *testing.T) {
	buf := make([]byte, utmpRecordLen*3) // all zeros: ut_type EMPTY
	got, consumed := utmpRecords(buf)
	if len(got) != 0 {
		t.Errorf("empty slots produced %d records", len(got))
	}
	if consumed != utmpRecordLen*3 {
		t.Errorf("consumed %d, want all of it -- empty slots must still advance the offset", consumed)
	}
}

// TestBinaryFilesAreNeverTailedAsText is the guard that makes the widened
// default paths safe.
//
// /var/log now matches suffix-less files so that dmesg and access_log are
// collected. wtmp, btmp, lastlog and atop's archives sit in the same
// directories, and tailing one line-by-line would ship struct padding into the
// log pipeline.
func TestBinaryFilesAreNeverTailedAsText(t *testing.T) {
	binaries := map[string][]byte{
		"utmp record":  buildUtmp(utUserProcess, 1, "pts/0", "ubuntu", "", 1, nil),
		"nul at start": {0x00, 0x01, 0x02, 'l', 'o', 'g'},
		"elf header":   {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0},
	}
	for name, b := range binaries {
		if !looksBinary(b) {
			t.Errorf("%s was accepted as text", name)
		}
	}

	texts := map[string]string{
		"syslog line":   "2026-09-07T14:26:25.355250+00:00 host agent[886]: export ok\n",
		"utf-8 accents": "février: démarrage terminé\n",
		"utf-8 cjk":     "サービスを開始しました\n",
		"tabs and crlf": "field\tvalue\r\nnext\tvalue\r\n",
		"empty":         "",
	}
	for name, s := range texts {
		if looksBinary([]byte(s)) {
			t.Errorf("%s was rejected as binary -- UTF-8 continuation bytes are text", name)
		}
	}
}
