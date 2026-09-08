package logs

import (
	"strconv"
	"strings"
	"time"
)

// Syslog wire parsing, RFC 3164 and RFC 5424.
//
// This is the one log source that arrives instead of being found. Everything
// else in this module reads something the host already wrote; a syslog
// listener accepts what another machine decided to send, which makes it the
// only place here where the input is chosen by a third party. Every bound in
// this file exists for that reason.
//
// TWO FORMATS, one socket. RFC 5424 is the current standard and is
// self-identifying: the priority is followed by a version number, which is
// always "1". RFC 3164 is the older format that most appliances still emit and
// has no version field. Reading the character after the priority tells them
// apart, and everything that is neither is kept verbatim as the message rather
// than discarded -- a line we cannot parse is still a line somebody wanted.
//
//	RFC 5424: <34>1 2026-09-07T22:14:15.003Z host su - ID47 - failed for lonvick
//	RFC 3164: <34>Sep  7 22:14:15 host su: failed for lonvick
//
// PRI encodes facility and severity in one integer: facility*8 + severity.
// Severity is the half that matters here, because it is the level an operator
// alerts on and it maps directly onto the same scale journald uses.

// maxSyslogPriority is the largest legal PRI value: facility 23, severity 7.
const maxSyslogPriority = 191

type syslogMessage struct {
	Priority    int // severity, 0-7
	Facility    int
	HasPriority bool
	Timestamp   time.Time
	HasTime     bool
	Hostname    string
	AppName     string
	PID         int
	Message     string
}

// parseSyslog decodes one wire message. It never fails: anything it cannot
// interpret is returned with the whole input as the message, because a relay
// that silently drops what it does not understand is worse than one that
// forwards it unstructured.
func parseSyslog(line string) syslogMessage {
	m := syslogMessage{Message: line}
	rest, pri, ok := parsePRI(line)
	if !ok {
		return m
	}
	m.HasPriority = true
	m.Priority = pri % 8
	m.Facility = pri / 8
	m.Message = rest

	// RFC 5424 announces itself with a version. "1 " is the only version ever
	// issued, and treating a different digit as 5424 would misparse every
	// field after it.
	if strings.HasPrefix(rest, "1 ") {
		parse5424(rest[2:], &m)
		return m
	}
	parse3164(rest, &m)
	return m
}

// parsePRI reads "<N>" from the head of the line.
func parsePRI(s string) (rest string, pri int, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return s, 0, false
	}
	end := strings.IndexByte(s, '>')
	// A priority is at most three digits. Scanning further would let a stray
	// '<' anywhere in a message turn the whole line into a "priority".
	if end < 2 || end > 4 {
		return s, 0, false
	}
	n, err := strconv.Atoi(s[1:end])
	if err != nil || n < 0 || n > maxSyslogPriority {
		return s, 0, false
	}
	return s[end+1:], n, true
}

// parse5424 reads TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG.
func parse5424(s string, m *syslogMessage) {
	ts, s := nextField(s)
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		m.Timestamp, m.HasTime = t.UTC(), true
	}
	var host, app, procid string
	host, s = nextField(s)
	app, s = nextField(s)
	procid, s = nextField(s)
	_, s = nextField(s) // MSGID, which nothing in practice sets usefully

	m.Hostname = nilDash(host)
	m.AppName = nilDash(app)
	if n, err := strconv.Atoi(nilDash(procid)); err == nil && n > 0 {
		m.PID = n
	}

	s = skipStructuredData(s)
	// A BOM here is legal and means "the message is UTF-8". It is a statement
	// about encoding, not content, and shipping it would put a stray glyph at
	// the head of every message from a conforming sender.
	s = strings.TrimPrefix(s, "\uFEFF")
	m.Message = s
}

// skipStructuredData steps over the SD-ELEMENTs.
//
// There can be SEVERAL of them, written back to back as "[a ...][b ...]", and
// a value inside one may contain quoted brackets and escaped quotes. Stopping
// at the first "]" therefore leaves the next element sitting at the head of
// the message, which is what the first version of this did.
func skipStructuredData(s string) string {
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "-") {
		return strings.TrimLeft(s[1:], " ")
	}
	for strings.HasPrefix(s, "[") {
		end, ok := endOfSDElement(s)
		if !ok {
			// Unterminated: the rest of the input is structured data as far
			// as anyone can tell, so there is no message to salvage.
			return ""
		}
		s = s[end:]
	}
	return strings.TrimLeft(s, " ")
}

// endOfSDElement finds the "]" that closes one element, ignoring any that sit
// inside a quoted PARAM-VALUE.
func endOfSDElement(s string) (int, bool) {
	inQuote, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case inQuote:
			if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
		case c == ']':
			return i + 1, true
		}
	}
	return 0, false
}

// parse3164 reads "MMM DD HH:MM:SS HOST TAG[PID]: MSG".
//
// The timestamp is fixed-width by specification, which is the only reliable
// thing about this format: it carries no year, no timezone and no fractional
// seconds, so the year is taken as the current one.
func parse3164(s string, m *syslogMessage) {
	m.Message = s
	if len(s) < 16 || !syslogMonthDay(s) {
		// No timestamp. Plenty of senders omit it; the rest of the line is
		// still the message.
		return
	}
	stamp := s[:15]
	rest := strings.TrimLeft(s[15:], " ")
	if t, err := time.Parse(time.Stamp, stamp); err == nil {
		now := time.Now().UTC()
		m.Timestamp = time.Date(now.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		m.HasTime = true
	}

	host, after := nextField(rest)
	m.Hostname = host
	m.Message = after

	// TAG is terminated by any non-alphanumeric, conventionally ':' with an
	// optional "[pid]" before it.
	tagEnd := strings.IndexAny(after, ":[")
	if tagEnd <= 0 || tagEnd > 48 {
		return
	}
	m.AppName = after[:tagEnd]
	i := tagEnd
	if after[i] == '[' {
		if end := strings.IndexByte(after[i:], ']'); end > 1 {
			if n, err := strconv.Atoi(after[i+1 : i+end]); err == nil && n > 0 {
				m.PID = n
			}
			i += end + 1
		}
	}
	if i < len(after) && after[i] == ':' {
		i++
	}
	m.Message = strings.TrimLeft(after[i:], " ")
}

// nextField splits off the next space-delimited field.
func nextField(s string) (field, rest string) {
	s = strings.TrimLeft(s, " ")
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// nilDash converts syslog's "-" placeholder to an empty string.
func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
