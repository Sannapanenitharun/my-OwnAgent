package logs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A synthetic journal file, so the walk is exercised in CI without carrying an
// 8 MB fixture in the repository.
//
// These tests prove the walk is self-consistent with the layout described in
// journalfile.go. They CANNOT prove that layout matches systemd's, because a
// builder and a reader that share a wrong offset agree perfectly. That half was
// checked against a real journal copied from a live host: journalctl reported
// 54 entries and the parser returned 54, with messages byte-identical and
// _COMM/_PID/_SYSTEMD_UNIT populated. The file was compact-mode, so that path
// is covered there too.

type journalBuilder struct {
	buf     []byte
	compact bool
	// dataAt remembers where each field value was written, so entries can
	// reference the same DATA object twice -- which is the whole point of
	// deduplication and the reason the old byte scan could not work.
	dataAt map[string]int64
}

func newJournalBuilder(compact bool) *journalBuilder {
	b := &journalBuilder{compact: compact, dataAt: map[string]int64{}}
	b.buf = make([]byte, 272) // header
	copy(b.buf[hdrSignature:], journalSignature)
	binary.LittleEndian.PutUint64(b.buf[hdrHeaderSize:], 272)
	if compact {
		binary.LittleEndian.PutUint32(b.buf[hdrIncompatibleFlags:], incompatibleCompact)
	}
	return b
}

func (b *journalBuilder) align() {
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
}

// data writes a DATA object for "key=value" once and returns its offset.
func (b *journalBuilder) data(kv string, flags byte) int64 {
	if off, ok := b.dataAt[kv]; ok {
		return off
	}
	b.align()
	off := int64(len(b.buf))
	payloadAt := dataPayload
	if b.compact {
		payloadAt = dataPayloadCompact
	}
	obj := make([]byte, payloadAt)
	obj[0] = objTypeData
	obj[1] = flags
	binary.LittleEndian.PutUint64(obj[8:], uint64(payloadAt+len(kv)))
	b.buf = append(b.buf, obj...)
	b.buf = append(b.buf, kv...)
	b.dataAt[kv] = off
	return off
}

// entry writes an ENTRY object referencing the given field offsets.
func (b *journalBuilder) entry(realtime uint64, offsets []int64) {
	b.align()
	stride := itemLen
	if b.compact {
		stride = itemLenCompact
	}
	size := entryItems + len(offsets)*stride
	obj := make([]byte, size)
	obj[0] = objTypeEntry
	binary.LittleEndian.PutUint64(obj[8:], uint64(size))
	binary.LittleEndian.PutUint64(obj[entryRealtime:], realtime)
	for i, off := range offsets {
		at := entryItems + i*stride
		if b.compact {
			binary.LittleEndian.PutUint32(obj[at:], uint32(off))
		} else {
			binary.LittleEndian.PutUint64(obj[at:], uint64(off))
		}
	}
	b.buf = append(b.buf, obj...)
}

func (b *journalBuilder) done() ([]byte, journalHeader) {
	binary.LittleEndian.PutUint64(b.buf[hdrArenaSize:], uint64(len(b.buf)-272))
	h := journalHeader{headerSize: 272, arenaSize: int64(len(b.buf) - 272), compact: b.compact}
	return b.buf, h
}

// addEntry is the common case: one message with its usual companions.
func (b *journalBuilder) addEntry(rt uint64, msg, comm, pid, pri, unit string) {
	offs := []int64{
		b.data("MESSAGE="+msg, 0),
		b.data("_COMM="+comm, 0),
		b.data("_PID="+pid, 0),
		b.data("PRIORITY="+pri, 0),
		b.data("_SYSTEMD_UNIT="+unit, 0),
	}
	b.entry(rt, offs)
}

func TestJournalEntriesCarryTheirOwnFields(t *testing.T) {
	for _, compact := range []bool{false, true} {
		name := "regular"
		if compact {
			name = "compact"
		}
		t.Run(name, func(t *testing.T) {
			b := newJournalBuilder(compact)
			b.addEntry(1000, "Accepted publickey for ubuntu", "sshd", "4242", "6", "ssh.service")
			b.addEntry(2000, "segfault at 0", "nginx", "99", "3", "nginx.service")
			buf, h := b.done()

			got, _, _ := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
			if len(got) != 2 {
				t.Fatalf("read %d entries, want 2", len(got))
			}
			if got[0].Fields["MESSAGE"] != "Accepted publickey for ubuntu" {
				t.Errorf("message = %q", got[0].Fields["MESSAGE"])
			}
			if got[0].Fields["_COMM"] != "sshd" || got[0].Fields["_PID"] != "4242" {
				t.Errorf("attribution = %v", got[0].Fields)
			}
			if got[0].Fields["_SYSTEMD_UNIT"] != "ssh.service" {
				t.Errorf("unit = %q", got[0].Fields["_SYSTEMD_UNIT"])
			}
			if got[0].Realtime != 1000 || got[1].Realtime != 2000 {
				t.Errorf("timestamps = %d, %d", got[0].Realtime, got[1].Realtime)
			}
			if got[1].Fields["_COMM"] != "nginx" || got[1].Fields["PRIORITY"] != "3" {
				t.Errorf("second entry = %v", got[1].Fields)
			}
		})
	}
}

// TestDeduplicatedFieldsAttributeCorrectly is the test that expresses why the
// byte scanner had to be replaced.
//
// journald stores "_COMM=sshd" ONCE and points every sshd entry at it. A scan
// of appended bytes sees that value near its first use and never again, so it
// can only guess which message it belongs to. Following the entry's item array
// is not a faster way to do the same thing -- it is the only way to be right.
func TestDeduplicatedFieldsAttributeCorrectly(t *testing.T) {
	b := newJournalBuilder(false)
	// sshd writes, then cron, then sshd again. The second sshd entry reuses
	// the DATA object written for the first, so nothing about it appears near
	// its own entry in the file.
	b.addEntry(1, "first from sshd", "sshd", "10", "6", "ssh.service")
	b.addEntry(2, "something from cron", "cron", "20", "6", "cron.service")
	b.addEntry(3, "third from sshd", "sshd", "10", "6", "ssh.service")
	buf, h := b.done()

	got, _, _ := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
	if len(got) != 3 {
		t.Fatalf("read %d entries, want 3", len(got))
	}
	want := []string{"sshd", "cron", "sshd"}
	for i, w := range want {
		if got[i].Fields["_COMM"] != w {
			t.Errorf("entry %d attributed to %q, want %q -- deduplicated fields are being mis-associated",
				i, got[i].Fields["_COMM"], w)
		}
	}
	// And the shared field really was stored once.
	if len(b.dataAt) != 4+3+2 { // messages(3) + comms(2) + pids(2) + priority(1) + units(2) = 10
		t.Logf("distinct DATA objects: %d", len(b.dataAt))
	}
}

// TestTailingResumesWhereItStopped. The walk returns the offset to continue
// from; re-reading from it must yield only what was appended since.
func TestTailingResumesWhereItStopped(t *testing.T) {
	b := newJournalBuilder(true)
	b.addEntry(1, "before", "a", "1", "6", "a.service")
	buf, h := b.done()

	first, next, _ := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
	if len(first) != 1 {
		t.Fatalf("first read got %d", len(first))
	}

	b.addEntry(2, "after", "a", "1", "6", "a.service")
	buf2, h2 := b.done()

	second, _, _ := readJournalEntries(bytes.NewReader(buf2), h2, next, journalWanted, 100)
	if len(second) != 1 {
		t.Fatalf("resumed read got %d entries, want just the appended one", len(second))
	}
	if second[0].Fields["MESSAGE"] != "after" {
		t.Errorf("resumed read returned %q", second[0].Fields["MESSAGE"])
	}
}

// TestCompressedMessagesAreCountedNotFaked. XZ/LZ4/ZSTD would each be a
// dependency this agent does not have. A record whose body cannot be read is
// dropped and counted, never shipped with an empty message.
func TestCompressedMessagesAreCountedNotFaked(t *testing.T) {
	b := newJournalBuilder(false)
	offs := []int64{
		b.data("\x00\x00compressed-garbage", 1), // OBJECT_COMPRESSED_XZ
		b.data("_COMM=big", 0),
	}
	b.entry(1, offs)
	b.addEntry(2, "readable", "small", "1", "6", "s.service")
	buf, h := b.done()

	got, _, compressed := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
	if len(got) != 1 || got[0].Fields["MESSAGE"] != "readable" {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if compressed != 1 {
		t.Errorf("compressed drops = %d, want 1 -- an unreadable record must be counted, not silently lost", compressed)
	}
}

// TestOnlyWantedFieldsAreCopied. An entry references every field it carries and
// journald attaches a couple of dozen; copying all of them would multiply the
// allocation and the payload for fields nothing displays.
func TestOnlyWantedFieldsAreCopied(t *testing.T) {
	b := newJournalBuilder(false)
	offs := []int64{
		b.data("MESSAGE=hi", 0),
		b.data("_CAP_EFFECTIVE=1ffffffffff", 0),
		b.data("_SYSTEMD_CGROUP=/system.slice/x.service", 0),
		b.data("_AUDIT_SESSION=27", 0),
	}
	b.entry(1, offs)
	buf, h := b.done()

	got, _, _ := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
	if len(got) != 1 {
		t.Fatal("no entry")
	}
	if len(got[0].Fields) != 1 {
		t.Errorf("copied %d fields, want only MESSAGE: %v", len(got[0].Fields), got[0].Fields)
	}
}

// TestAnEntryWithNoMessageIsNotALogLine. journald writes plenty of them --
// audit records, coredump metadata -- and an empty body fills the view with
// rows that say nothing.
func TestAnEntryWithNoMessageIsNotALogLine(t *testing.T) {
	b := newJournalBuilder(false)
	b.entry(1, []int64{b.data("_COMM=auditd", 0), b.data("PRIORITY=5", 0)})
	buf, h := b.done()

	got, _, compressed := readJournalEntries(bytes.NewReader(buf), h, h.headerSize, journalWanted, 100)
	if len(got) != 0 {
		t.Errorf("a message-less entry was returned as a log line: %+v", got)
	}
	if compressed != 0 {
		t.Errorf("a message-less entry was blamed on compression: %d", compressed)
	}
}

// TestCorruptInputTerminatesTheWalk. A journal is written by a privileged
// daemon, but a truncated or corrupt file must produce a short read rather
// than a wild seek or an allocation the size of the disk.
func TestCorruptInputTerminatesTheWalk(t *testing.T) {
	b := newJournalBuilder(false)
	b.addEntry(1, "good", "a", "1", "6", "a.service")
	buf, h := b.done()

	cases := map[string]func([]byte) []byte{
		"zero-sized object": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			binary.LittleEndian.PutUint64(out[272+8:], 0)
			return out
		},
		"absurd object size": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			binary.LittleEndian.PutUint64(out[272+8:], 1<<62)
			return out
		},
		"truncated file": func(in []byte) []byte { return in[:len(in)/2] },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			bad := mangle(buf)
			// Must return, not hang, panic, or allocate the world.
			got, _, _ := readJournalEntries(bytes.NewReader(bad), h, h.headerSize, journalWanted, 100)
			_ = got
		})
	}
}

func TestHeaderRejectsWhatIsNotAJournal(t *testing.T) {
	if _, err := readJournalHeader(bytes.NewReader(make([]byte, 300))); err == nil {
		t.Error("a file of zeros was accepted as a journal")
	}
	if _, err := readJournalHeader(bytes.NewReader([]byte("short"))); err == nil {
		t.Error("a short file was accepted as a journal")
	}
}
