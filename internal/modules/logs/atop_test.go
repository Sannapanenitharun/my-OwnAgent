package logs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// realAtopHeaderPrefix is the first 41 bytes of a live /var/log/atop archive,
// copied out of a hexdump on the host that produced it.
//
// Reading it back with the constants in atop.go must reproduce what the host's
// own `atop -V` and `dpkg -l` reported: version 2.10, and a struct-length pair
// that the writing binary chose. Building this fixture from those same
// constants would prove nothing, which is why it is a byte transcript.
//
//	magic   ef be ed fe   -> 0xfeedbeef
//	aver    0a 82         -> 0x820a, masked 0x020a -> 2.10
//	headlen e0 01         -> 480
//	reclen  60 00         -> 96
//	hertz   64 00         -> 100
//	sstat   48 b8 0f 00   -> 1030216
//	tstat   e0 03 00 00   -> 992
//	sysname 4c 69 6e 75 78 -> "Linux"
const realAtopHeaderPrefix = "efbeedfe" + // magic
	"0a82" + // aversion
	"0000" + "0000" + // future1, future2
	"e001" + // rawheadlen = 480
	"6000" + // rawreclen  = 96
	"6400" + // hertz      = 100
	"070000000000000000000000" + // sfuture[6]
	"48b80f00" + // sstatlen = 1030216
	"e0030000" + // tstatlen = 992
	"4c696e7578" // utsname.sysname = "Linux"

const (
	testAtopHeadLen = 480
	testAtopRecLen  = 96
)

func atopHeaderBytes(t *testing.T) []byte {
	t.Helper()
	prefix, err := hex.DecodeString(realAtopHeaderPrefix)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	b := make([]byte, testAtopHeadLen)
	copy(b, prefix)
	// utsname.nodename sits one 65-byte field after sysname. On the real host
	// this is where the hostname was found, at offset 0x65.
	copy(b[atopOffSysname+atopUtsFieldLen:], "ip-172-31-36-199")
	return b
}

// atopRecordBytes encodes one 96-byte sample header.
func atopRecordBytes(when int64, scomp, pcomp, interval uint32) []byte {
	r := make([]byte, testAtopRecLen)
	binary.LittleEndian.PutUint64(r[atopRecOffTime:], uint64(when))
	binary.LittleEndian.PutUint32(r[atopRecOffScomp:], scomp)
	binary.LittleEndian.PutUint32(r[atopRecOffPcomp:], pcomp)
	binary.LittleEndian.PutUint32(r[atopRecOffInterval:], interval)
	return r
}

// buildAtopArchive assembles a whole archive: header, then each sample's
// record header followed by payload bytes of the declared lengths.
func buildAtopArchive(t *testing.T, samples [][4]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(atopHeaderBytes(t))
	for _, s := range samples {
		when, scomp, pcomp, interval := s[0], uint32(s[1]), uint32(s[2]), uint32(s[3])
		buf.Write(atopRecordBytes(when, scomp, pcomp, interval))
		buf.Write(bytes.Repeat([]byte{0xAB}, int(scomp+pcomp)))
	}
	return buf.Bytes()
}

func TestAtopHeaderMatchesTheRealArchive(t *testing.T) {
	h, err := readAtopHeader(bytes.NewReader(atopHeaderBytes(t)))
	if err != nil {
		t.Fatalf("readAtopHeader: %v", err)
	}
	if h.Major != 2 || h.Minor != 10 {
		t.Errorf("version = %d.%d, want 2.10 (the host reported atop 2.10.0)", h.Major, h.Minor)
	}
	if h.HeadLen != 480 || h.RecLen != 96 {
		t.Errorf("headlen/reclen = %d/%d, want 480/96", h.HeadLen, h.RecLen)
	}
	if h.Hertz != 100 {
		t.Errorf("hertz = %d, want 100", h.Hertz)
	}
	if h.SstatLen != 1030216 || h.TstatLen != 992 {
		t.Errorf("sstatlen/tstatlen = %d/%d, want 1030216/992 -- these are "+
			"sizeof() in the writing binary and are why the payloads are not decoded",
			h.SstatLen, h.TstatLen)
	}
	if h.Sysname != "Linux" {
		t.Errorf("sysname = %q, want Linux", h.Sysname)
	}
	if h.Nodename != "ip-172-31-36-199" {
		t.Errorf("nodename = %q -- the utsname field stride is wrong", h.Nodename)
	}
}

// TestTheVersionMarkerBitIsMasked. aversion carries a high marker bit; failing
// to mask it reports every archive as major version 130.
func TestTheVersionMarkerBitIsMasked(t *testing.T) {
	b := atopHeaderBytes(t)
	if got := binary.LittleEndian.Uint16(b[atopOffVersion:]); got&0x8000 == 0 {
		t.Fatalf("fixture aversion 0x%04x has no marker bit; the test is not testing the mask", got)
	}
	h, err := readAtopHeader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if h.Major != 2 {
		t.Errorf("major = %d, want 2 -- the 0x8000 marker bit leaked into the version", h.Major)
	}
}

// TestTheChainWalksExactlyToEOF is the property that validated this layout
// against three real archives: every byte of the file is claimed by the header
// or by a sample, so the walk ends precisely at the end.
func TestTheChainWalksExactlyToEOF(t *testing.T) {
	base := int64(1788770263) // 2026-09-07T08:37:43Z, from the real archive
	samples := [][4]int64{
		{base, 1469, 8603, 7}, // the real first record's lengths and interval
		{base + 600, 2652, 186551, 600},
		{base + 1200, 2600, 180000, 600},
		{base + 1800, 2601, 181000, 600},
	}
	archive := buildAtopArchive(t, samples)

	h, err := readAtopHeader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	span := walkAtopRecords(bytes.NewReader(archive), h, int64(len(archive)))

	if span.Samples != 4 {
		t.Errorf("samples = %d, want 4", span.Samples)
	}
	if span.Slack != 0 {
		t.Errorf("slack = %d, want 0 -- the chain must account for every byte", span.Slack)
	}
	if span.Overran || span.Truncated {
		t.Errorf("overran=%v truncated=%v, want both false", span.Overran, span.Truncated)
	}
	if want := time.Unix(base, 0).UTC(); !span.First.Equal(want) {
		t.Errorf("first = %v, want %v", span.First, want)
	}
	if want := time.Unix(base+1800, 0).UTC(); !span.Last.Equal(want) {
		t.Errorf("last = %v, want %v", span.Last, want)
	}
	// The first sample after atop starts is a short partial one (7s on the
	// real host); the median must reflect the steady 600s rotation, not it.
	if span.Interval != 600 {
		t.Errorf("interval = %d, want 600 -- the median must ignore the short first sample", span.Interval)
	}
}

// TestATruncatedArchiveIsReportedNotGuessed. An archive cut off mid-write --
// the machine lost power -- declares payload bytes that are not there.
func TestATruncatedArchiveIsReportedNotGuessed(t *testing.T) {
	base := int64(1788770263)
	archive := buildAtopArchive(t, [][4]int64{
		{base, 100, 200, 600},
		{base + 600, 100, 200, 600},
	})
	full := len(archive)
	archive = archive[:full-150] // cut the last PAYLOAD short, header intact

	h, _ := readAtopHeader(bytes.NewReader(archive))
	span := walkAtopRecords(bytes.NewReader(archive), h, int64(len(archive)))

	if !span.Overran {
		t.Error("a record claiming bytes past EOF was not reported as an overrun")
	}
	// Both samples count. The second record's HEADER survived the cut, so the
	// time it was taken is known for certain -- it is the payload that is
	// missing, and this reader does not read payloads. Dropping the sample
	// would understate the window the archive actually covers.
	if span.Samples != 2 {
		t.Errorf("samples = %d, want 2 -- an intact record header is a known sample", span.Samples)
	}
	if want := time.Unix(base+600, 0).UTC(); !span.Last.Equal(want) {
		t.Errorf("last = %v, want %v", span.Last, want)
	}

	// Cutting into the record HEADER is different: nothing is known about
	// that sample, so it must not be counted.
	shorter := buildAtopArchive(t, [][4]int64{
		{base, 100, 200, 600},
		{base + 600, 100, 200, 600},
	})
	shorter = shorter[:full-350] // lands inside the second record header
	h2, _ := readAtopHeader(bytes.NewReader(shorter))
	span2 := walkAtopRecords(bytes.NewReader(shorter), h2, int64(len(shorter)))
	if span2.Samples != 1 {
		t.Errorf("samples = %d, want 1 -- a severed record header is not a sample", span2.Samples)
	}
}

// TestTrailingBytesAreNotSilentlyDropped. Slack is the signal that this
// reader's idea of the layout has drifted from the writer's.
func TestTrailingBytesAreNotSilentlyDropped(t *testing.T) {
	base := int64(1788770263)
	archive := buildAtopArchive(t, [][4]int64{{base, 100, 200, 600}})
	archive = append(archive, bytes.Repeat([]byte{0}, 40)...) // shorter than a record

	h, _ := readAtopHeader(bytes.NewReader(archive))
	span := walkAtopRecords(bytes.NewReader(archive), h, int64(len(archive)))
	if span.Slack != 40 {
		t.Errorf("slack = %d, want 40", span.Slack)
	}
}

// TestZeroLengthPayloadsCannotLoopForever. A record declaring no payload is
// legal arithmetic; if the step could be zero the walk would never advance.
func TestZeroLengthPayloadsCannotLoopForever(t *testing.T) {
	base := int64(1788770263)
	archive := buildAtopArchive(t, [][4]int64{
		{base, 0, 0, 600},
		{base + 600, 0, 0, 600},
		{base + 1200, 0, 0, 600},
	})
	done := make(chan atopSpan, 1)
	go func() {
		h, _ := readAtopHeader(bytes.NewReader(archive))
		done <- walkAtopRecords(bytes.NewReader(archive), h, int64(len(archive)))
	}()
	select {
	case span := <-done:
		if span.Samples != 3 {
			t.Errorf("samples = %d, want 3", span.Samples)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the walk did not terminate on zero-length payloads")
	}
}

// TestNonAtopFilesAreRefused. This reader is pointed at a directory glob, and
// the guards must reject anything that is not the format -- including a file
// whose first four bytes match by luck.
func TestNonAtopFilesAreRefused(t *testing.T) {
	cases := map[string][]byte{
		"empty":       {},
		"short":       []byte("not an atop file"),
		"text":        bytes.Repeat([]byte("2026-09-07 hello\n"), 40),
		"wrong magic": append([]byte{0xde, 0xad, 0xbe, 0xef}, make([]byte, 500)...),
		"utmp record": buildUtmp(utUserProcess, 1, "pts/0", "ubuntu", "", 1, nil),
		"right magic, absurd header lengths": func() []byte {
			b := atopHeaderBytes(t)
			binary.LittleEndian.PutUint16(b[atopOffHeadLen:], 3) // smaller than the header itself
			return b
		}(),
		"right magic, zero record length": func() []byte {
			b := atopHeaderBytes(t)
			binary.LittleEndian.PutUint16(b[atopOffRecLen:], 0)
			return b
		}(),
	}
	for name, body := range cases {
		if _, err := readAtopHeader(bytes.NewReader(body)); err == nil {
			t.Errorf("%s was accepted as an atop archive", name)
		}
	}
}
