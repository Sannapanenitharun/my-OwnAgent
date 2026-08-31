package logs

import "strings"

// Trace correlation.
//
// Correlate is the pipeline stage that makes the other signals worth having
// together: a log line that cannot name the request it belongs to is a log
// file, not a trace view. Nothing in the agent carried a trace ID, so there
// was no join at all between logs and spans.
//
// The agent does not invent the link. An instrumented application already
// writes its trace context into the line -- that is what every OTel, Datadog
// and Spring logging integration does -- so the ID is there to be read, in a
// small number of shapes:
//
//	W3C traceparent   00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//	OTel logging      trace_id=4bf92f... span_id=00f067aa0ba902b7
//	JSON              {"trace_id":"4bf92f...","span_id":"00f067aa0ba902b7"}
//
// Reading it is strictly better than not having it, and strictly worse than
// the application telling us directly -- which is why this only ever accepts
// an ID that is well formed and delimited. A wrong correlation is worse than
// none: it attaches a log line to somebody else's request.

// traceScanLimit bounds the search. Trace context is written as a field near
// the front of a line by every convention above; a 32-hex string deep inside a
// payload is far more likely to be a checksum or a UUID than a trace.
const traceScanLimit = 256

// traceIDLen and spanIDLen are fixed by the W3C spec. Requiring the exact
// length is most of what keeps this from matching arbitrary hex: a 32-character
// lowercase hex run preceded by a trace key is not something that occurs by
// accident.
const (
	traceIDLen = 32
	spanIDLen  = 16
)

// traceKeys and spanKeys are the field names the common logging integrations
// write. Dotted and underscored forms both appear in the wild.
var traceKeys = []string{"trace_id", "traceid", "trace-id", "trace.id", "otelTraceID"}
var spanKeys = []string{"span_id", "spanid", "span-id", "span.id", "otelSpanID"}

// detectTrace reads the trace context out of a log line. The boolean reports
// whether a trace ID was found; a span ID may be empty even when it was.
func detectTrace(line string) (traceID, spanID string, ok bool) {
	head := line
	if len(head) > traceScanLimit {
		head = head[:traceScanLimit]
	}
	if head == "" {
		return "", "", false
	}

	// traceparent carries both IDs in one field and is unambiguous, so it is
	// tried first and wins outright.
	if t, s, found := traceparent(head); found {
		return t, s, true
	}

	lower := strings.ToLower(head)
	traceID = keyedHex(head, lower, traceKeys, traceIDLen)
	if traceID == "" {
		return "", "", false
	}
	spanID = keyedHex(head, lower, spanKeys, spanIDLen)
	return traceID, spanID, true
}

// traceparent matches the W3C header form: version, trace id, span id, flags,
// hyphen-separated. Version "ff" is invalid per the spec.
func traceparent(head string) (string, string, bool) {
	lower := strings.ToLower(head)
	at := strings.Index(lower, "00-")
	for at >= 0 {
		// The version must start the field, not sit inside a longer token.
		if at == 0 || !isTraceWordByte(lower[at-1]) {
			rest := lower[at+3:]
			if len(rest) >= traceIDLen+1+spanIDLen &&
				rest[traceIDLen] == '-' &&
				isHexRun(rest[:traceIDLen]) &&
				isHexRun(rest[traceIDLen+1:traceIDLen+1+spanIDLen]) {
				t := rest[:traceIDLen]
				s := rest[traceIDLen+1 : traceIDLen+1+spanIDLen]
				if !allZero(t) {
					return t, s, true
				}
			}
		}
		next := strings.Index(lower[at+1:], "00-")
		if next < 0 {
			return "", "", false
		}
		at += 1 + next
	}
	return "", "", false
}

// keyedHex finds key=<hex> or "key":"<hex>" and returns the value when it is
// exactly n hex characters. The original string is returned rather than the
// lowered copy so the ID keeps the case the application wrote.
func keyedHex(head, lower string, keys []string, n int) string {
	for _, key := range keys {
		k := strings.ToLower(key)
		idx := 0
		for {
			at := strings.Index(lower[idx:], k)
			if at < 0 {
				break
			}
			at += idx
			idx = at + len(k)
			// The key must stand alone: "trace_id" inside "parent_trace_id" is
			// a different field, and inside "trace_id_hash" it is not an ID.
			if at > 0 && isTraceWordByte(lower[at-1]) {
				continue
			}
			rest := lower[idx:]
			trimmed := strings.TrimLeft(rest, `"' `)
			if !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, ":") {
				continue
			}
			cut := len(rest) - len(trimmed) + 1
			value := strings.TrimLeft(rest[cut:], `"' `)
			off := idx + (len(rest) - len(value))
			if len(value) < n || !isHexRun(value[:n]) {
				continue
			}
			// A longer hex run is not a trace ID that happens to start here --
			// it is a different identifier, and truncating it would invent a
			// correlation.
			if len(value) > n && isHexByte(value[n]) {
				continue
			}
			if allZero(value[:n]) {
				continue
			}
			return head[off : off+n]
		}
	}
	return ""
}

func isHexRun(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// allZero rejects the all-zero ID, which the specs use to mean "no trace".
// Correlating on it would join every uninstrumented line to every other one.
func allZero(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

func isTraceWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_'
}
