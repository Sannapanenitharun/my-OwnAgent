package logs

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"time"
)

// atop archives: /var/log/atop/atop_YYYYMMDD.
//
// WHAT THIS READS, AND WHAT IT DELIBERATELY DOES NOT.
//
// An atop archive is a header followed by a chain of samples. Each sample is a
// fixed-size record header giving a timestamp and two compressed payload
// lengths, then those two payloads: a system-wide `sstat` and an array of
// per-task `tstat`. This file walks the CHAIN and decodes the record headers.
// It does not decompress or interpret the payloads.
//
// That boundary is not laziness, it is the format's own. The archive header
// states sstatlen=1030216 and tstatlen=992 for the host this was written
// against, and those numbers are sizeof() of two C structs as compiled into
// the atop binary that wrote the file. atop itself refuses to read an archive
// whose lengths do not match its own build, because the payload is a raw
// struct dump with no field tags: interpreting it requires the exact struct
// layout of that atop version, and a mismatch does not fail, it silently
// yields plausible wrong numbers. Reimplementing a 1 MB struct from a version
// we cannot see is how you ship a parser that is confidently wrong on the next
// release.
//
// The payloads are also the part we least need. Per-process CPU, memory and
// I/O are what the process module measures directly, live, at a resolution
// atop's 10-minute samples cannot match.
//
// What the chain gives that we have nowhere else is COVERAGE: which historical
// windows exist on this host, at what sample interval. That is the question
// worth answering when an incident predates the agent's installation, and it
// is answerable from fields that are stable across versions.
//
// VALIDATION. The layout below was checked against three real archives by
// walking the chain and comparing the final offset to the file size. All three
// landed exactly on EOF with zero out-of-order timestamps and a median
// interval of 600s, which is atop's packaged rotation interval. A wrong offset
// anywhere in the record header would have desynchronised the walk within one
// or two records and missed EOF by megabytes.

const atopMagic = 0xfeedbeef

// Archive header offsets. Only the fields this reader uses are named; the
// rest of the 480-byte header is atop's own bookkeeping.
const (
	atopOffMagic    = 0  // uint32
	atopOffVersion  = 4  // uint16
	atopOffHeadLen  = 10 // uint16  size of this header, = offset of record 0
	atopOffRecLen   = 12 // uint16  size of each record header
	atopOffHertz    = 14 // uint16
	atopOffSstatLen = 28 // uint32  sizeof(struct sstat) in the writing binary
	atopOffTstatLen = 32 // uint32  sizeof(struct tstat)
	atopOffSysname  = 36 // char[65] utsname.sysname, then nodename at +65

	atopUtsFieldLen  = 65 // glibc's utsname members are _UTSNAME_LENGTH = 65
	atopMinHeaderLen = atopOffSysname + 2*atopUtsFieldLen
)

// Record header offsets, within the first atopOffRecInterval+4 bytes of each
// rawrecord. The record is 96 bytes on the observed version; everything past
// the interval is counts this reader does not report (see below).
const (
	atopRecOffTime     = 0  // int64  time_t curtime
	atopRecOffScomp    = 16 // uint32 compressed system-stat length
	atopRecOffPcomp    = 20 // uint32 compressed process-stat length
	atopRecOffInterval = 24 // uint32 seconds covered by this sample

	atopMinRecLen = atopRecOffInterval + 4
)

// Sanity bounds. A corrupt or hostile archive must not be able to steer this
// into a large allocation or an endless walk.
const (
	maxAtopHeaderLen = 64 << 10
	maxAtopRecords   = 4096
)

var errNotAtop = errors.New("not an atop archive")

// atopHeader is the part of the archive header this reader understands.
type atopHeader struct {
	Major, Minor int
	HeadLen      int
	RecLen       int
	Hertz        int
	SstatLen     uint32
	TstatLen     uint32
	Sysname      string
	Nodename     string
}

// atopSpan is what a walked archive covers.
type atopSpan struct {
	Samples  int
	First    time.Time
	Last     time.Time
	Interval int // median seconds between samples
	// Slack is the bytes between where the chain ended and the end of the
	// file. Zero means every byte was accounted for. A non-zero value means
	// the archive is truncated or the walk desynchronised, and the difference
	// between those two is not knowable from here -- so it is reported rather
	// than judged.
	Slack int64
	// Truncated records that the walk hit its record cap with bytes left.
	Truncated bool
	// Overran records that a record's declared payload lengths pointed past
	// the end of the file. That is a different failure from Slack: slack is
	// bytes nobody claimed, overrun is a claim on bytes that are not there.
	Overran bool
}

func readAtopHeader(r io.ReaderAt) (atopHeader, error) {
	buf := make([]byte, atopMinHeaderLen)
	n, err := r.ReadAt(buf, 0)
	if n < atopMinHeaderLen {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return atopHeader{}, err
	}
	if binary.LittleEndian.Uint32(buf[atopOffMagic:]) != atopMagic {
		return atopHeader{}, errNotAtop
	}

	// aversion packs major and minor into one uint16, with the top bit set as
	// a marker by every version that writes this header. Mask it off before
	// splitting, or every archive reports a major version of 130.
	ver := binary.LittleEndian.Uint16(buf[atopOffVersion:]) & 0x7fff
	h := atopHeader{
		Major:    int(ver >> 8),
		Minor:    int(ver & 0xff),
		HeadLen:  int(binary.LittleEndian.Uint16(buf[atopOffHeadLen:])),
		RecLen:   int(binary.LittleEndian.Uint16(buf[atopOffRecLen:])),
		Hertz:    int(binary.LittleEndian.Uint16(buf[atopOffHertz:])),
		SstatLen: binary.LittleEndian.Uint32(buf[atopOffSstatLen:]),
		TstatLen: binary.LittleEndian.Uint32(buf[atopOffTstatLen:]),
		Sysname:  cString(buf[atopOffSysname : atopOffSysname+atopUtsFieldLen]),
		Nodename: cString(buf[atopOffSysname+atopUtsFieldLen : atopOffSysname+2*atopUtsFieldLen]),
	}
	// The magic can match by luck in 1 in 4 billion; these cannot. A record
	// header shorter than the fields read from it, or a header that does not
	// contain itself, is not a format this reader knows.
	if h.HeadLen < atopMinHeaderLen || h.HeadLen > maxAtopHeaderLen {
		return atopHeader{}, errNotAtop
	}
	if h.RecLen < atopMinRecLen || h.RecLen > maxAtopHeaderLen {
		return atopHeader{}, errNotAtop
	}
	return h, nil
}

// walkAtopRecords follows the sample chain from the end of the header to the
// end of the file, reading only record headers and skipping the payloads.
func walkAtopRecords(r io.ReaderAt, h atopHeader, size int64) atopSpan {
	var span atopSpan
	intervals := make([]int, 0, 64)
	rec := make([]byte, h.RecLen)

	off := int64(h.HeadLen)
	for off+int64(h.RecLen) <= size {
		if span.Samples >= maxAtopRecords {
			span.Truncated = true
			break
		}
		n, err := r.ReadAt(rec, off)
		if n < h.RecLen {
			_ = err
			break
		}
		sec := int64(binary.LittleEndian.Uint64(rec[atopRecOffTime:]))
		scomp := int64(binary.LittleEndian.Uint32(rec[atopRecOffScomp:]))
		pcomp := int64(binary.LittleEndian.Uint32(rec[atopRecOffPcomp:]))
		interval := int(binary.LittleEndian.Uint32(rec[atopRecOffInterval:]))

		if sec <= 0 {
			break
		}
		when := time.Unix(sec, 0).UTC()
		if span.Samples == 0 {
			span.First = when
		}
		span.Last = when
		span.Samples++
		if interval > 0 {
			intervals = append(intervals, interval)
		}

		// Forward progress is structural rather than hoped for: RecLen is
		// validated at or above atopMinRecLen, and the two payload lengths are
		// uint32 widened to int64, so the step is always positive and cannot
		// overflow. What is NOT guaranteed is that it stays inside the file.
		next := off + int64(h.RecLen) + scomp + pcomp
		if next > size {
			// The record claims payload bytes past EOF: the archive was
			// truncated mid-write, or this is not the layout we think it is.
			// Both stop the walk, and the offset is left where it was so the
			// unparsed remainder is reported honestly.
			span.Overran = true
			break
		}
		off = next
	}

	span.Slack = size - off
	if len(intervals) > 0 {
		sort.Ints(intervals)
		span.Interval = intervals[len(intervals)/2]
	}
	return span
}
