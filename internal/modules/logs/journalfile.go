package logs

import (
	"encoding/binary"
	"errors"
	"io"
)

// The systemd journal file format, enough of it to read entries correctly.
//
// WHY THIS EXISTS. The previous reader scanned newly appended bytes for the
// literal "MESSAGE=" and shipped whatever followed. On a host where journald
// is the primary sink that collected 30 lines out of 39,485 -- 0.08% -- while
// reporting success on every cycle. The source looked healthy and was
// effectively off.
//
// The scan cannot be repaired, because the format does not work the way it
// assumes. Journal DATA objects are DEDUPLICATED: "_COMM=sshd" is stored once
// and referenced by every entry sshd ever wrote. A byte scan therefore sees a
// field value at most once, near its first use, and has no way to know which
// entry any later message belongs to. Proximity would produce confident wrong
// attribution, which is worse than none.
//
// The format is a flat arena of length-prefixed objects. An ENTRY object holds
// an array of offsets to the DATA objects that make up that entry, so reading
// an entry means following its items. That is what this file does.
//
// WHAT IS NOT DONE. Compressed payloads are skipped, not decoded: XZ, LZ4 and
// ZSTD would each be a third-party dependency, and this agent has none.
// journald only compresses payloads above a threshold (512 bytes by default),
// so the fields that matter here -- PRIORITY, _PID, _COMM, _SYSTEMD_UNIT, and
// all but the longest MESSAGE -- arrive uncompressed. Records whose message is
// compressed are counted and dropped rather than shipped empty.

const journalSignature = "LPKSHHRH"

// Header field offsets. Named because a bare number here is unreviewable, and
// getting one wrong silently reads a different file than the one on disk.
const (
	hdrSignature         = 0  // 8 bytes
	hdrIncompatibleFlags = 12 // le32
	hdrHeaderSize        = 88 // le64
	hdrArenaSize         = 96 // le64
	hdrTailObjectOffset  = 136
	hdrMinLen            = 144
)

// HEADER_INCOMPATIBLE_COMPACT changes the width of entry items and adds two
// fields to every DATA object. Reading a compact file with the regular layout
// yields offsets that point at nothing.
const incompatibleCompact = 1 << 4

// Object header: type(1) flags(1) reserved(6) size(8), then the payload.
const (
	objHeaderLen = 16
	objTypeData  = 1
	objTypeEntry = 3
)

// Object flags. Any non-zero compression flag means the payload is not text.
const objCompressedMask = 0x07

// Payload offsets within each object type, measured from the object start.
const (
	dataPayload        = objHeaderLen + 48 // hash, next_hash, next_field, entry, entry_array, n_entries
	dataPayloadCompact = dataPayload + 8   // ...plus tail_entry_array_offset/_n_entries
	entryItems         = objHeaderLen + 48 // seqnum, realtime, monotonic, boot_id[16], xor_hash
	entryRealtime      = objHeaderLen + 8

	itemLen        = 16 // object_offset, hash
	itemLenCompact = 4  // object_offset
)

// Bounds. A journal file is routinely gigabytes and is not trusted input: it
// is written by a privileged daemon, but a corrupt or truncated file must
// produce a short read rather than an allocation the size of the disk.
const (
	maxEntriesPerRead = 2048
	maxItemsPerEntry  = 128
	maxFieldLen       = 64 << 10
	maxObjectSize     = 8 << 20
)

// journalWanted is the field set read out of each entry.
//
// Restricting it is what keeps the walk cheap: an entry references every field
// it carries, and journald attaches a couple of dozen -- cgroup paths, boot
// IDs, capability sets, audit session data. Copying all of them would multiply
// both the allocation and the payload for fields nothing displays.
var journalWanted = map[string]bool{
	"MESSAGE":           true,
	"PRIORITY":          true,
	"_PID":              true,
	"_COMM":             true,
	"_SYSTEMD_UNIT":     true,
	"SYSLOG_IDENTIFIER": true,
	"CONTAINER_ID":      true,
	"CONTAINER_NAME":    true,
	"_TRANSPORT":        true,
}

var errNotAJournal = errors.New("logs: not a journal file")

// journalHeader is the part of the file header this reader uses.
type journalHeader struct {
	headerSize       int64
	arenaSize        int64
	tailObjectOffset int64
	compact          bool
}

// end is the first offset past the arena: where scanning must stop.
func (h journalHeader) end() int64 { return h.headerSize + h.arenaSize }

func readJournalHeader(r io.ReaderAt) (journalHeader, error) {
	buf := make([]byte, hdrMinLen)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return journalHeader{}, err
	}
	if string(buf[hdrSignature:hdrSignature+8]) != journalSignature {
		return journalHeader{}, errNotAJournal
	}
	h := journalHeader{
		headerSize:       int64(binary.LittleEndian.Uint64(buf[hdrHeaderSize:])),
		arenaSize:        int64(binary.LittleEndian.Uint64(buf[hdrArenaSize:])),
		tailObjectOffset: int64(binary.LittleEndian.Uint64(buf[hdrTailObjectOffset:])),
		compact:          binary.LittleEndian.Uint32(buf[hdrIncompatibleFlags:])&incompatibleCompact != 0,
	}
	if h.headerSize < hdrMinLen || h.arenaSize < 0 {
		return journalHeader{}, errNotAJournal
	}
	return h, nil
}

// journalEntry is one record, already reduced to the fields asked for.
type journalEntry struct {
	Realtime uint64
	Fields   map[string]string
}

// readJournalEntries walks objects from `from` and returns the entries found,
// the offset to resume at, and how many records were dropped because their
// message was compressed.
//
// Walking sequentially rather than following the entry-array index is
// deliberate: tailing only ever needs "what was appended since last time", and
// a sequential walk expresses that directly. The index exists to seek
// backwards through history, which nothing here does.
func readJournalEntries(r io.ReaderAt, h journalHeader, from int64, want map[string]bool, max int) (out []journalEntry, next int64, compressed int) {
	if max <= 0 || max > maxEntriesPerRead {
		max = maxEntriesPerRead
	}
	end := h.end()
	off := from
	if off < h.headerSize {
		off = h.headerSize
	}

	scratch := &journalScratch{}
	hdr := make([]byte, objHeaderLen)
	for off+objHeaderLen <= end && len(out) < max {
		if _, err := r.ReadAt(hdr, off); err != nil {
			break
		}
		typ := hdr[0]
		size := int64(binary.LittleEndian.Uint64(hdr[8:]))
		// A size that is not sane ends the walk. Continuing would either loop
		// forever (size 0) or read from a wild offset.
		if size < objHeaderLen || size > maxObjectSize || off+size > end {
			break
		}

		if typ == objTypeEntry {
			if e, ok := readEntry(r, h, off, size, want, &compressed, scratch); ok {
				out = append(out, e)
			}
		}

		// Objects are 8-byte aligned in the arena.
		off += (size + 7) &^ 7
	}
	return out, off, compressed
}

// journalScratch holds the buffers one walk reuses. An entry references
// roughly ten DATA objects and a busy file holds tens of thousands of entries,
// so allocating per item made the walk's cost the allocator rather than the
// reads.
type journalScratch struct {
	hdr   [objHeaderLen]byte
	items []byte
	buf   []byte
}

func (s *journalScratch) field(n int) []byte {
	if cap(s.buf) < n {
		s.buf = make([]byte, n)
	}
	return s.buf[:n]
}

func (s *journalScratch) itemBuf(n int) []byte {
	if cap(s.items) < n {
		s.items = make([]byte, n)
	}
	return s.items[:n]
}

func readEntry(r io.ReaderAt, h journalHeader, off, size int64, want map[string]bool, compressed *int, scratch *journalScratch) (journalEntry, bool) {
	if size < entryItems {
		return journalEntry{}, false
	}
	stride := int64(itemLen)
	if h.compact {
		stride = itemLenCompact
	}
	n := (size - entryItems) / stride
	if n <= 0 {
		return journalEntry{}, false
	}
	if n > maxItemsPerEntry {
		n = maxItemsPerEntry
	}

	var tsBuf [8]byte
	if _, err := r.ReadAt(tsBuf[:], off+entryRealtime); err != nil {
		return journalEntry{}, false
	}
	e := journalEntry{Realtime: binary.LittleEndian.Uint64(tsBuf[:])}

	items := scratch.itemBuf(int(n * stride))
	if _, err := r.ReadAt(items, off+entryItems); err != nil {
		return journalEntry{}, false
	}

	sawCompressed := false
	for i := int64(0); i < n; i++ {
		var dataOff int64
		if h.compact {
			dataOff = int64(binary.LittleEndian.Uint32(items[i*stride:]))
		} else {
			dataOff = int64(binary.LittleEndian.Uint64(items[i*stride:]))
		}
		if dataOff < h.headerSize || dataOff >= h.end() {
			continue
		}
		key, val, ok, wasCompressed := readDataField(r, h, dataOff, want, scratch)
		if wasCompressed {
			// Which field this was cannot be known without decompressing it:
			// compression covers the whole "KEY=value" payload, so a
			// compressed object does not begin with its own key. So the most
			// that can be said is that this entry had a field we could not
			// read -- and if the entry then turns out to have no message,
			// that field is the likely reason.
			sawCompressed = true
			continue
		}
		if !ok {
			continue
		}
		if e.Fields == nil {
			e.Fields = make(map[string]string, 4)
		}
		e.Fields[key] = val
	}

	if _, hasMsg := e.Fields["MESSAGE"]; !hasMsg {
		if sawCompressed {
			*compressed++
		}
		// An entry with no message is not a log line. journald writes plenty
		// of them -- audit records, coredump metadata -- and shipping an empty
		// body would fill the view with rows that say nothing.
		return journalEntry{}, false
	}
	return e, true
}

// readDataField reads one DATA object and splits its "KEY=value" payload.
//
// The `want` set is applied to the KEY before the value is copied, so a 200 KB
// audit blob costs one key comparison rather than an allocation.
func readDataField(r io.ReaderAt, h journalHeader, off int64, want map[string]bool, scratch *journalScratch) (key, val string, ok, compressed bool) {
	hdr := scratch.hdr[:]
	if _, err := r.ReadAt(hdr, off); err != nil {
		return "", "", false, false
	}
	if hdr[0] != objTypeData {
		return "", "", false, false
	}
	if hdr[1]&objCompressedMask != 0 {
		// XZ, LZ4 or ZSTD. Decoding any of them means a dependency this agent
		// does not have; see the file comment.
		return "", "", false, true
	}
	size := int64(binary.LittleEndian.Uint64(hdr[8:]))
	payloadAt := int64(dataPayload)
	if h.compact {
		payloadAt = dataPayloadCompact
	}
	if size <= payloadAt || size > maxObjectSize {
		return "", "", false, false
	}
	length := size - payloadAt
	if length > maxFieldLen {
		length = maxFieldLen
	}
	buf := scratch.field(int(length))
	if _, err := r.ReadAt(buf, off+payloadAt); err != nil {
		return "", "", false, false
	}
	eq := indexByte(buf, '=')
	if eq <= 0 {
		return "", "", false, false
	}
	key = string(buf[:eq])
	if !want[key] {
		return "", "", false, false
	}
	return key, string(buf[eq+1:]), true, false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
