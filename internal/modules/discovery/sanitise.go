package discovery

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitisation: the single boundary at which untrusted bytes become attribute
// values and natural-key components.
//
// NEARLY EVERY STRING THIS MODULE HANDLES IS CHOSEN BY SOMETHING OTHER THAN THE
// AGENT. A process names itself. A container runtime writes the cgroup path. An
// operator names a mount point. A service author writes the display name. A
// Kubernetes user names the pod. Each of those strings ends up in a log line, a
// dashboard, an event attribute, and — for key components — potentially in the
// platform's permanent entity store.
//
// Three things are therefore done to every one of them, in order:
//
//  1. Control characters are REPLACED, not stripped. Replaced, because two names
//     differing only in control characters must not collide into one entity;
//     and control characters specifically because they include the newline that
//     forges a second log line and the ESC that reprograms a terminal reading
//     it.
//  2. The result is truncated on a rune boundary.
//  3. An empty or wholly-invalid value becomes a bounded sentinel the operator
//     can see and act on, rather than an empty string that reads as "absent".
//
// This is deliberately ONE function used everywhere rather than per-source
// bounding. Sanitisation that lives in ten places is sanitisation that is
// correct in nine.

// sentinelUnknown is what an unusable value becomes. It is bounded, obvious in a
// dashboard, and cannot be produced by sanitising a real value — a real value
// containing the word never reduces to exactly this.
const sentinelUnknown = "unknown"

// sanitiseValue makes an untrusted string safe to use as an attribute value or a
// natural-key component.
//
// The second return value reports whether anything was changed, so callers can
// count how often it happens: a sudden rise is itself a signal worth having, and
// on this module it usually means a new container runtime is writing a path
// shape nobody has seen.
func sanitiseValue(s string, maxLen int) (string, bool) {
	if s == "" {
		return sentinelUnknown, true
	}

	// Fast path. The overwhelming majority of these strings are already clean
	// ASCII, and this function runs several times per entity per cycle.
	// Scanning for a reason to rewrite, and returning the original when there is
	// none, removes an allocation per value.
	if len(s) <= maxLen {
		plain := true
		for i := 0; i < len(s); i++ {
			// Non-ASCII falls through to the slow path rather than being
			// rejected: a mount point or a pod name may legitimately be UTF-8,
			// and the slow path preserves it. Only the common case is optimised.
			if c := s[i]; c < 0x20 || c == 0x7f || c >= utf8.RuneSelf {
				plain = false
				break
			}
		}
		if plain && strings.TrimSpace(s) != "" {
			return s, false
		}
	}

	clean := s
	modified := false

	if !utf8.ValidString(clean) {
		// Invalid UTF-8 would be rejected or mangled unpredictably by whatever
		// consumes it downstream. Coercing it here makes the outcome the
		// agent's decision rather than a surprise three systems away.
		clean = strings.ToValidUTF8(clean, "_")
		modified = true
	}

	var b strings.Builder
	b.Grow(len(clean))
	for _, r := range clean {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r):
			b.WriteByte('_')
			modified = true
		default:
			b.WriteRune(r)
		}
	}
	clean = b.String()

	// Truncated on a rune boundary: cutting a multi-byte rune in half would
	// produce exactly the invalid UTF-8 the step above just removed.
	if len(clean) > maxLen {
		cut := maxLen
		for cut > 0 && !utf8.RuneStart(clean[cut]) {
			cut--
		}
		clean = clean[:cut]
		modified = true
	}

	if strings.TrimSpace(clean) == "" {
		return sentinelUnknown, true
	}
	return clean, modified
}

// sanitiseName bounds an identifying string: a service name, an executable name,
// an interface name, a container ID.
func sanitiseName(s string) (string, bool) { return sanitiseValue(s, maxNameLen) }

// sanitisePath bounds a filesystem path: a mount point, a device node.
func sanitisePath(s string) (string, bool) { return sanitiseValue(s, maxPathLen) }

// boundAddresses sanitises, deduplicates, sorts and caps an interface's address
// list.
//
// Sorting is not cosmetic. The address list is part of the interface entity's
// fingerprint, and a source that enumerated addresses in a different order each
// cycle would report every interface as CHANGED, every cycle, forever — turning
// an incremental discovery system into a full one that also lies about what
// changed. Deduplication exists for the same reason, since some stacks report an
// address once per address family.
//
// The cap is applied AFTER sorting so that a machine with more addresses than
// the cap reports the same subset every cycle rather than a different one.
func boundAddresses(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, a := range in {
		clean, _ := sanitiseValue(a, maxNameLen)
		if clean == sentinelUnknown {
			continue
		}
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	if len(out) > maxAddressesPerInterface {
		out = out[:maxAddressesPerInterface]
	}
	return out
}

// joinAddresses renders a bounded address list as one attribute value.
//
// One attribute rather than N, because N would make the ATTRIBUTE COUNT depend
// on the host's configuration — and an event whose shape varies with the data is
// an event nobody can write a schema for. The list is already capped and sorted,
// so the result is bounded in length and stable in content.
func joinAddresses(addrs []string) string {
	if len(addrs) == 0 {
		return ""
	}
	return strings.Join(addrs, ",")
}

// boolValue renders a boolean as a bounded attribute value. Written out rather
// than using strconv so that the two possible values are visible in one place
// and can never become "1"/"0" in one call site and "true"/"false" in another.
func boolValue(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
