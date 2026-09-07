package logs

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// Last-login accounting: /var/log/lastlog.
//
// This file is not a log. It is a TABLE, indexed by user ID, holding one
// fixed-size record per account, overwritten in place at each login. Record N
// lives at offset N*292 and nowhere else, there is no append, and there is no
// history: the file answers "when did account N last log in", once, for every
// account that ever has.
//
// WHY IT IS WORTH READING when wtmp already reports logins as events. wtmp is
// rotated -- monthly on Ubuntu -- and lastlog is not. After a rotation, "when
// did root last log in" is answerable only here. The security question this
// surface answers uniquely is the negative one: which accounts have NEVER
// been used, and which were used once, long ago. Neither is derivable from an
// event stream that starts at the current month.
//
// LAYOUT is glibc's `struct lastlog`, which is 292 bytes on 64-bit Linux:
//
//	int32_t ll_time;         // 4   NOT time_t -- see below
//	char    ll_line[32];     // 32  terminal
//	char    ll_host[256];    // 256 remote host
//
// The size was confirmed against a live host, whose lastlog is exactly 292292
// bytes: 1001 records of 292, the highest UID on it being 1000.
//
// ll_time is int32 even on 64-bit systems, so these timestamps overflow in
// January 2038 -- the same defect as utmp's ut_tv.tv_sec, for the same reason,
// and worth stating twice because the two files are read by different code.
const (
	lastlogRecordLen = 292

	llOffTime = 0  // int32
	llOffLine = 4  // char[32]
	llOffHost = 36 // char[256]

	llLineLen = 32
	llHostLen = 256
)

// maxLastlogBytes bounds the read, and it is a safety property rather than a
// tuning knob.
//
// lastlog is a SPARSE file addressed by UID. On a host joined to a directory
// service that hands out UIDs in the billions, one login by UID 2000000000
// makes the file nominally 584 GB -- almost entirely holes. The kernel will
// happily serve those holes as zeroes, at memory-bus speed, forever. An agent
// that walked it linearly would read until something killed it.
//
// 4 MiB is roughly 14,000 accounts, far more than any host with real human
// users, and it is a cap on BYTES READ rather than on records found: entries
// past it are not reported, and the fact that they were skipped is.
const maxLastlogBytes = 4 << 20

// maxLastlogAccounts bounds what a single cycle will emit, so the baseline
// pass on a host with thousands of populated entries cannot swamp a batch.
const maxLastlogAccounts = 256

// lastlogRecord is one decoded table entry. UID is the record's INDEX, not a
// field: it is implied by the file position, which is why decoding needs it
// passed in.
type lastlogRecord struct {
	UID     int
	User    string // resolved from /etc/passwd, empty if the UID has no account
	Line    string // terminal: pts/0, tty1
	Host    string // remote host or address, as the login recorded it
	When    time.Time
	Present bool
}

// decodeLastlog reads one 292-byte record.
//
// Present is false for an account that has never logged in. That is the
// common case by a wide margin -- 1000 of the 1001 entries on the host this
// was written against -- and it is represented in the file as an all-zero
// record, which is also what a hole in the sparse file reads as. The two are
// indistinguishable and mean the same thing.
func decodeLastlog(uid int, b []byte) lastlogRecord {
	if len(b) < lastlogRecordLen {
		return lastlogRecord{}
	}
	sec := int32(binary.LittleEndian.Uint32(b[llOffTime:]))
	if sec <= 0 {
		// Never logged in. Line and host are not consulted: a zero timestamp
		// with a non-zero terminal would be a corrupt record, and inventing a
		// login for it would be worse than dropping it.
		return lastlogRecord{UID: uid}
	}
	return lastlogRecord{
		UID:     uid,
		Line:    cString(b[llOffLine : llOffLine+llLineLen]),
		Host:    cString(b[llOffHost : llOffHost+llHostLen]),
		When:    time.Unix(int64(sec), 0).UTC(),
		Present: true,
	}
}

// lastlogMessage renders a record as a log line.
//
// The wording deliberately says "last login", not "login": this is a
// statement about the state of the table, not the report of an event that
// just happened. An operator reading it next to a wtmp line must not mistake
// the two, because the timestamp in it may be years old.
func lastlogMessage(r lastlogRecord) string {
	if !r.Present {
		return ""
	}
	var b strings.Builder
	b.WriteString("last login for ")
	if r.User != "" {
		b.WriteString("user " + strconv.Quote(r.User))
	} else {
		// An entry with no matching passwd line is worth reporting rather
		// than hiding: it means the account was deleted after logging in,
		// which is exactly the kind of thing an audit wants to see.
		b.WriteString("deleted uid " + strconv.Itoa(r.UID))
	}
	b.WriteString(" at " + r.When.Format(time.RFC3339))
	if r.Host != "" {
		b.WriteString(" from " + r.Host)
	}
	if r.Line != "" {
		b.WriteString(" on " + r.Line)
	}
	return b.String()
}

// lastlogRecords decodes a buffer of whole records starting at UID firstUID.
//
// Unlike the utmp reader, a trailing partial record here is NOT held back for
// the next read: this file is written in place at fixed offsets, never
// appended to, so a short tail means the file ends mid-record and re-reading
// it would return the same short tail forever.
func lastlogRecords(buf []byte, firstUID int) []lastlogRecord {
	out := make([]lastlogRecord, 0, 8)
	for off := 0; off+lastlogRecordLen <= len(buf); off += lastlogRecordLen {
		r := decodeLastlog(firstUID+off/lastlogRecordLen, buf[off:off+lastlogRecordLen])
		if r.Present {
			out = append(out, r)
		}
	}
	return out
}

// parsePasswdUIDs maps UID to username from /etc/passwd content.
//
// /etc/passwd is world-readable and holds no secrets; the hashes live in
// /etc/shadow, which this agent has no reason to open and does not. Parsing
// the file directly rather than calling os/user keeps the lookup free of cgo
// and of NSS, which on a directory-joined host would turn a local table read
// into a network round trip per UID.
func parsePasswdUIDs(content []byte) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(string(content), "\n") {
		// name:passwd:uid:gid:gecos:dir:shell -- only the first three matter,
		// and a line with fewer fields is not a passwd entry.
		parts := strings.Split(line, ":")
		if len(parts) < 3 || parts[0] == "" {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil || uid < 0 {
			continue
		}
		// First writer wins. Duplicate UIDs are legal and occasionally
		// deliberate (root and toor), and picking the first keeps the mapping
		// stable across reads instead of depending on map iteration.
		if _, seen := out[uid]; !seen {
			out[uid] = parts[0]
		}
	}
	return out
}
