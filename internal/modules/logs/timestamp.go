package logs

// Recognising the start of a log record.
//
// This is the whole basis of automatic multi-line aggregation: a line that
// opens with a timestamp is a new record, and a line that does not is the
// continuation of the one before it. Getting it wrong in the permissive
// direction splits records; getting it wrong in the strict direction glues
// them together. The detection gate in multiline.go makes the second failure
// survivable, so these matchers err towards strict.
//
// The shapes below are the ones Datadog's legacy detector lists -- ANSIC,
// RFC822/850/1123, RFC3339, Ruby, Unix date, and the Java SimpleFormatter
// default -- plus klog, which every Kubernetes component writes.
//
// Every matcher requires a DATE AND A TIME, or a month-day-time, and never a
// bare time. "14:26:25 starting up" is a plausible log line and an implausible
// record boundary, and admitting it would split any stack trace whose frames
// happen to mention a clock.

// startsWithTimestamp reports whether the line opens with a recognised stamp.
func startsWithTimestamp(line string) bool {
	s := line
	// One leading wrapper is allowed: "[2026-09-07 14:26:25] ..." is the same
	// record start as the unbracketed form.
	if len(s) > 0 && (s[0] == '[' || s[0] == '<') {
		s = s[1:]
	}
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	s = s[i:]
	return isoDateTime(s) ||
		syslogMonthDay(s) ||
		weekdayDate(s) ||
		javaMonthDayYear(s) ||
		klogStamp(s)
}

// isoDateTime matches 2026-09-07T14:26 and 2026/09/07 14:26, which covers
// RFC3339, RFC3339Nano and the ISO-ish forms most libraries emit.
func isoDateTime(s string) bool {
	if len(s) < 16 {
		return false
	}
	sep := s[4]
	if sep != '-' && sep != '/' {
		return false
	}
	if !digitsOnly(s[0:4]) || !digitsOnly(s[5:7]) || !digitsOnly(s[8:10]) {
		return false
	}
	if s[7] != sep {
		return false
	}
	// The date and time may be joined by T (RFC3339), a space (almost
	// everything else), or an underscore (some file-per-hour loggers).
	if c := s[10]; c != 'T' && c != ' ' && c != '_' {
		return false
	}
	return digitsOnly(s[11:13]) && s[13] == ':' && digitsOnly(s[14:16])
}

// syslogMonthDay matches "Sep  7 14:26:25", RFC3164's stamp. The day is space
// padded to two columns, so the gap between month and day is one space or two.
func syslogMonthDay(s string) bool {
	if len(s) < 15 || !isMonthName(s[0:3]) {
		return false
	}
	i := 3
	for i < len(s) && s[i] == ' ' {
		i++
	}
	day := 0
	for i < len(s) && isASCIIDigit(s[i]) && day < 2 {
		i++
		day++
	}
	if day == 0 || i >= len(s) || s[i] != ' ' {
		return false
	}
	return isClockTime(s[i+1:])
}

// weekdayDate matches the formats that lead with a day name: ANSIC
// ("Mon Jan  2 15:04:05"), RFC1123 ("Mon, 02 Jan 2006 ..."), Ruby and Unix
// date.
func weekdayDate(s string) bool {
	if len(s) < 12 || !isWeekdayName(s[0:3]) {
		return false
	}
	i := 3
	if i < len(s) && s[i] == ',' {
		i++
	}
	for i < len(s) && s[i] == ' ' {
		i++
	}
	rest := s[i:]
	// RFC822/850/1123: the day number comes before the month name.
	if len(rest) >= 6 && isASCIIDigit(rest[0]) && isASCIIDigit(rest[1]) &&
		rest[2] == ' ' && isMonthName(rest[3:6]) {
		return true
	}
	// ANSIC, Unix date, Ruby: the month name comes first.
	return len(rest) >= 3 && isMonthName(rest[0:3])
}

// javaMonthDayYear matches "Sep 07, 2026 2:26:25 PM", which is what
// java.util.logging.SimpleFormatter prints unless told otherwise.
func javaMonthDayYear(s string) bool {
	if len(s) < 12 || !isMonthName(s[0:3]) {
		return false
	}
	i := 3
	for i < len(s) && s[i] == ' ' {
		i++
	}
	day := 0
	for i < len(s) && isASCIIDigit(s[i]) && day < 2 {
		i++
		day++
	}
	if day == 0 || i >= len(s) || s[i] != ',' {
		return false
	}
	i++
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return i+4 <= len(s) && digitsOnly(s[i:i+4])
}

// klogStamp matches "I0907 14:26:25.123456", the format every Kubernetes
// component writes. The leading letter is the severity, which is why this is
// also the one shape here that carries a level.
func klogStamp(s string) bool {
	if len(s) < 14 {
		return false
	}
	switch s[0] {
	case 'I', 'W', 'E', 'F', 'D':
	default:
		return false
	}
	if !digitsOnly(s[1:5]) || s[5] != ' ' {
		return false
	}
	return isClockTime(s[6:])
}

// isClockTime matches HH:MM:SS at the head of s.
func isClockTime(s string) bool {
	return len(s) >= 8 &&
		digitsOnly(s[0:2]) && s[2] == ':' &&
		digitsOnly(s[3:5]) && s[5] == ':' &&
		digitsOnly(s[6:8])
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isASCIIDigit(s[i]) {
			return false
		}
	}
	return true
}

// monthNames and weekdayNames are compared case-sensitively on the first
// letter and case-insensitively after it, because "Sep", "SEP" and "sep" all
// occur and "sEp" does not need to.
var monthNames = map[string]bool{
	"jan": true, "feb": true, "mar": true, "apr": true, "may": true, "jun": true,
	"jul": true, "aug": true, "sep": true, "oct": true, "nov": true, "dec": true,
}

var weekdayNames = map[string]bool{
	"mon": true, "tue": true, "wed": true, "thu": true, "fri": true,
	"sat": true, "sun": true,
}

func isMonthName(s string) bool { return len(s) == 3 && monthNames[lower3(s)] }

func isWeekdayName(s string) bool { return len(s) == 3 && weekdayNames[lower3(s)] }

// lower3 lowercases a three-byte ASCII string without allocating through
// strings.ToLower, which shows up when it runs once per line per file.
func lower3(s string) string {
	var b [3]byte
	for i := 0; i < 3; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b[:])
}
