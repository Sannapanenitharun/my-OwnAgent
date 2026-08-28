package logs

import (
	"strings"

	"github.com/obsagent/observability-agent/internal/platform"
)

// Severity detection.
//
// Every log line the agent emitted was stamped Info, which made severity
// filtering and any alert built on it inert: a container writing
// "W0828 16:37:10 prometheus is not configured" arrived at the same level as
// routine chatter.
//
// The level is in the line, but only in SOME lines, and only in a handful of
// shapes. This reads the shapes it can prove and leaves everything else at
// Info, because the alternative -- searching anywhere in the line for the word
// "error" -- promotes a line that merely MENTIONS an error, and the first thing
// an operator does with a severity column that lies is stop trusting it.
//
// Three rules keep it honest:
//
//  1. Only the head of the line is examined. A level marker is a prefix or an
//     early structured field; a match three kilobytes into a stack trace is a
//     coincidence, not a level.
//  2. Only delimited matches count. "error" as a key's value or a bracketed
//     tag is evidence; "error" inside "errors.go:41" or "no errors found" is
//     not.
//  3. The first match wins, and nothing escalates. A line is read once, left
//     to right, and the earliest marker is the one the writer meant.

// severityScanLimit bounds the window. Every format below puts its level well
// inside the first hundred bytes; the limit is what stops a long line from
// costing a full scan, and what stops a message body from being searched at
// all.
const severityScanLimit = 96

// severityWords maps a level token to a severity. Only tokens that name a
// level are here -- "critical" and "fatal" both mean Error because the platform
// has no level above it, and saying so is better than inventing one.
var severityWords = map[string]platform.EventSeverity{
	"trace":     platform.SeverityDebug,
	"debug":     platform.SeverityDebug,
	"dbg":       platform.SeverityDebug,
	"info":      platform.SeverityInfo,
	"inf":       platform.SeverityInfo,
	"notice":    platform.SeverityInfo,
	"warn":      platform.SeverityWarn,
	"warning":   platform.SeverityWarn,
	"wrn":       platform.SeverityWarn,
	"error":     platform.SeverityError,
	"err":       platform.SeverityError,
	"eror":      platform.SeverityError,
	"fatal":     platform.SeverityError,
	"critical":  platform.SeverityError,
	"crit":      platform.SeverityError,
	"panic":     platform.SeverityError,
	"emergency": platform.SeverityError,
	"alert":     platform.SeverityError,
}

// detectSeverity reads the level out of a log line. The second result reports
// whether a level was actually found, so a caller can tell "this line says it
// is informational" from "this line does not say".
func detectSeverity(line string) (platform.EventSeverity, bool) {
	head := line
	if len(head) > severityScanLimit {
		head = head[:severityScanLimit]
	}
	if head == "" {
		return platform.SeverityInfo, false
	}

	// klog / glog, which is what Kubernetes components and much of the Go
	// ecosystem write: a single letter, then the timestamp.
	// "W0828 16:37:10.331120       1 updater.go:46] ..."
	if sev, ok := klogSeverity(head); ok {
		return sev, true
	}
	// Structured logfmt and JSON: level=warn, "level":"error", severity=ERROR.
	if sev, ok := keyedSeverity(head); ok {
		return sev, true
	}
	// Bracketed or bare leading token: "[ERROR] ...", "ERROR ...", "<3>...".
	if sev, ok := leadingSeverity(head); ok {
		return sev, true
	}
	return platform.SeverityInfo, false
}

// klogSeverity matches the glog header: a level letter immediately followed by
// four digits of date. The digits are what make it unambiguous -- a bare
// leading "E" is a letter, "E0828" is a klog line.
func klogSeverity(head string) (platform.EventSeverity, bool) {
	if len(head) < 5 {
		return 0, false
	}
	var sev platform.EventSeverity
	switch head[0] {
	case 'D':
		sev = platform.SeverityDebug
	case 'I':
		sev = platform.SeverityInfo
	case 'W':
		sev = platform.SeverityWarn
	case 'E', 'F':
		sev = platform.SeverityError
	default:
		return 0, false
	}
	for i := 1; i < 5; i++ {
		if head[i] < '0' || head[i] > '9' {
			return 0, false
		}
	}
	return sev, true
}

// keyedSeverity finds level="value" or level=value, in logfmt or JSON. Both
// spell the key the same way and differ only in quoting, so one scan covers
// them.
func keyedSeverity(head string) (platform.EventSeverity, bool) {
	lower := strings.ToLower(head)
	for _, key := range []string{"level", "severity", "lvl", "loglevel"} {
		idx := 0
		for {
			at := strings.Index(lower[idx:], key)
			if at < 0 {
				break
			}
			at += idx
			idx = at + len(key)
			// The key must stand alone: "level" inside "sublevel" is not a
			// level field.
			if at > 0 && isWordByte(lower[at-1]) {
				continue
			}
			rest := strings.TrimLeft(lower[idx:], `"' `)
			if !strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, ":") {
				continue
			}
			rest = strings.TrimLeft(rest[1:], `"' `)
			if sev, ok := severityWords[leadingWord(rest)]; ok {
				return sev, true
			}
		}
	}
	return 0, false
}

// leadingSeverity matches a level at the very start of the line, bare or
// wrapped in one pair of brackets. Anchoring at the start is the whole of its
// safety: a bracketed tag later in the line is a component name far more often
// than a level.
func leadingSeverity(head string) (platform.EventSeverity, bool) {
	s := strings.TrimLeft(head, " \t")
	// Syslog priority, "<3>" -- the value is a facility and severity packed
	// together, and the low three bits are the severity.
	if strings.HasPrefix(s, "<") {
		if end := strings.IndexByte(s, '>'); end > 1 && end <= 4 {
			pri, ok := atoiSmall(s[1:end])
			if ok {
				return syslogSeverity(pri % 8), true
			}
		}
	}
	open := ""
	switch {
	case strings.HasPrefix(s, "["):
		open, s = "]", s[1:]
	case strings.HasPrefix(s, "("):
		open, s = ")", s[1:]
	}
	word := leadingWord(strings.ToLower(s))
	if word == "" {
		return 0, false
	}
	sev, ok := severityWords[word]
	if !ok {
		return 0, false
	}
	if open != "" {
		// The bracket must close soon after the word, or this was not a tag.
		rest := s[len(word):]
		if !strings.HasPrefix(strings.TrimLeft(rest, " "), open) {
			return 0, false
		}
		return sev, true
	}
	// Bare leading word: require a delimiter after it, so "Error:" and
	// "ERROR " count while "Errors were found" does not.
	rest := s[len(word):]
	if rest == "" {
		return sev, true
	}
	switch rest[0] {
	case ' ', ':', '\t', '-', ']', '|':
		return sev, true
	}
	return 0, false
}

// syslogSeverity maps the numeric severity in a syslog priority.
func syslogSeverity(n int) platform.EventSeverity {
	switch {
	case n <= 3: // emerg, alert, crit, err
		return platform.SeverityError
	case n == 4:
		return platform.SeverityWarn
	case n <= 6: // notice, info
		return platform.SeverityInfo
	default:
		return platform.SeverityDebug
	}
}

// leadingWord returns the run of letters at the start of s.
func leadingWord(s string) string {
	for i := 0; i < len(s); i++ {
		if !isLetter(s[i]) {
			return s[:i]
		}
	}
	return s
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isWordByte(c byte) bool {
	return isLetter(c) || c >= '0' && c <= '9' || c == '_'
}

// atoiSmall parses a short non-negative integer without allocating.
func atoiSmall(s string) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
