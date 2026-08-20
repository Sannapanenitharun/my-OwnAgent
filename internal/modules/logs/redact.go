package logs

import (
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

var (
	reAWSKey = regexp.MustCompile(`(?i)(?P<k>AKIA[0-9A-Z]{16})`)
	reBearer = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-+=/]{8,}`)
	reAssign = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+`)
)

// Redact replaces credential-shaped substrings. It is intentionally coarse:
// a false positive that masks a word is recoverable; a leaked AWS key is not.
// The Stage 6 secret-scrubber will replace this; until then every log body
// that leaves the module must pass through here.
func Redact(s string) string {
	s = reAWSKey.ReplaceAllString(s, redacted)
	s = reBearer.ReplaceAllString(s, "${1}"+redacted)
	s = reAssign.ReplaceAllStringFunc(s, func(m string) string {
		sep := "="
		if i := strings.IndexByte(m, ':'); i >= 0 && (strings.IndexByte(m, '=') < 0 || i < strings.IndexByte(m, '=')) {
			sep = ":"
		}
		i := strings.Index(m, sep)
		if i < 0 {
			return redacted
		}
		return m[:i+1] + redacted
	})
	return s
}

// Truncate bounds a line. Oversize lines are cut and counted by the caller.
func Truncate(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	return s[:max], true
}
