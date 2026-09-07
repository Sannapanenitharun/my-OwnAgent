package logs

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

// Login accounting: /var/log/btmp and /var/log/wtmp.
//
// These are the only log files on a stock Ubuntu host that carry a signal
// nothing else does and that no text reader can reach. btmp holds FAILED login
// attempts -- 289 of them on the host this was written against, whose SSH port
// answers the public internet -- and there is no text log anywhere on the
// system that records them. auth.log records some, journald records some, but
// btmp is the one that is meant to.
//
// The format is a flat array of fixed-size C structs, appended to. No index, no
// compression, no cross-references: after the journal file format this is a
// short walk. What makes it worth its own reader rather than a glob entry is
// that tailing it as text would ship 384 bytes of NULs and struct padding per
// record.
//
// LAYOUT is glibc's `struct utmp` on 64-bit Linux, which is 384 bytes. The
// offsets below are that struct's, and they are why this file is not built
// from a generic binary reader: get one wrong and every field after it is
// garbage that still looks like data.

const (
	utmpRecordLen = 384

	utOffType    = 0   // int16
	utOffPID     = 4   // int32
	utOffLine    = 8   // char[32]  terminal
	utOffUser    = 44  // char[32]
	utOffHost    = 76  // char[256] remote host
	utOffSeconds = 340 // int32     tv_sec
	utOffAddrV6  = 348 // int32[4]

	utLineLen = 32
	utUserLen = 32
	utHostLen = 256
)

// ut_type values, from <utmpx.h>.
const (
	utEmpty        = 0
	utRunLevel     = 1
	utBootTime     = 2
	utNewTime      = 3
	utOldTime      = 4
	utInitProcess  = 5
	utLoginProcess = 6
	utUserProcess  = 7
	utDeadProcess  = 8
)

// utmpRecord is one decoded accounting entry.
type utmpRecord struct {
	Type    int
	PID     int
	Line    string // terminal: pts/0, tty1, ssh:notty
	User    string
	Host    string // remote host name, when the source recorded one
	Addr    string // remote address, when the name was not resolvable
	When    time.Time
	Present bool
}

// decodeUtmp reads one 384-byte record. It returns Present=false for entries
// that carry nothing worth reporting, which is most of what a wtmp file holds:
// EMPTY slots and the clock-change records the kernel writes at boot.
func decodeUtmp(b []byte) utmpRecord {
	if len(b) < utmpRecordLen {
		return utmpRecord{}
	}
	r := utmpRecord{
		Type: int(int16(binary.LittleEndian.Uint16(b[utOffType:]))),
		PID:  int(int32(binary.LittleEndian.Uint32(b[utOffPID:]))),
		Line: cString(b[utOffLine : utOffLine+utLineLen]),
		User: cString(b[utOffUser : utOffUser+utUserLen]),
		Host: cString(b[utOffHost : utOffHost+utHostLen]),
	}
	if sec := int32(binary.LittleEndian.Uint32(b[utOffSeconds:])); sec > 0 {
		// tv_sec is a 32-bit signed integer even on 64-bit systems, so these
		// timestamps overflow in January 2038. Nothing can be done about it
		// here -- the file says what it says -- but a reader that silently
		// produced 1901 dates afterwards would be worse than one that says so.
		r.When = time.Unix(int64(sec), 0).UTC()
	}
	if r.Host == "" {
		r.Addr = decodeUtmpAddr(b[utOffAddrV6 : utOffAddrV6+16])
	}
	r.Present = r.Type != utEmpty
	return r
}

// decodeUtmpAddr renders ut_addr_v6, which holds an IPv4 address in its first
// word and zeroes in the rest, or a full IPv6 address across all four.
func decodeUtmpAddr(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	// A v4 address leaves words 1..3 clear.
	if binary.LittleEndian.Uint32(b[4:]) == 0 &&
		binary.LittleEndian.Uint32(b[8:]) == 0 &&
		binary.LittleEndian.Uint32(b[12:]) == 0 {
		return net.IP(b[:4]).String()
	}
	return net.IP(b[:16]).String()
}

// cString trims a fixed-width C string at its first NUL. The remainder is
// padding, not content, and shipping it would put NULs through the pipeline.
func cString(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// utmpMessage renders a record as a log line.
//
// The wording is chosen so the line reads the same way the events read in
// auth.log, because an operator scanning both should not have to learn two
// vocabularies for the same event.
func utmpMessage(r utmpRecord, failed bool) string {
	where := r.Host
	if where == "" {
		where = r.Addr
	}

	var b strings.Builder
	switch {
	case failed:
		b.WriteString("failed login")
		if r.User != "" {
			b.WriteString(" for user " + strconv.Quote(r.User))
		}
	case r.Type == utBootTime:
		return "system boot"
	case r.Type == utRunLevel:
		return "runlevel change"
	case r.Type == utNewTime || r.Type == utOldTime:
		return "system clock changed"
	case r.Type == utDeadProcess:
		if r.Line == "" {
			return ""
		}
		return "logout on " + r.Line
	case r.Type == utUserProcess:
		b.WriteString("login")
		if r.User != "" {
			b.WriteString(" by user " + strconv.Quote(r.User))
		}
	default:
		// INIT_PROCESS and LOGIN_PROCESS are getty bookkeeping, not events an
		// operator reads. Reporting them would bury the two that matter.
		return ""
	}

	if where != "" {
		b.WriteString(" from " + where)
	}
	if r.Line != "" {
		b.WriteString(" on " + r.Line)
	}
	return b.String()
}

// utmpRecords decodes a buffer of whole records. A trailing partial record is
// left for the next read rather than decoded from half its bytes: the file is
// appended to while this runs, so a short tail is the normal case.
func utmpRecords(buf []byte) (out []utmpRecord, consumed int) {
	for len(buf)-consumed >= utmpRecordLen {
		r := decodeUtmp(buf[consumed : consumed+utmpRecordLen])
		consumed += utmpRecordLen
		if r.Present {
			out = append(out, r)
		}
	}
	return out, consumed
}
