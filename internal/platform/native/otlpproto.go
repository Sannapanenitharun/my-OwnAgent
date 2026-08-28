package native

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"
)

// OTLP/protobuf span decoding.
//
// The receiver accepted protobuf from the start -- it takes any body and
// forwards it -- but only JSON was ever decoded into spans. Protobuf bodies
// were base64'd into the envelope's `raw` array, which nothing downstream
// reads, so they were accepted with a 200 and then discarded in silence.
//
// That is the wrong half to support. OTLP/HTTP's default wire format IS
// protobuf: an application has to be told to use JSON
// (OTEL_EXPORTER_OTLP_PROTOCOL=http/json), so every stock SDK -- Go, Java,
// Python, Node -- sent the one format the agent threw away.
//
// This decodes protobuf directly rather than pulling in a generated OTLP
// package, because the agent has no third-party dependencies and the subset
// needed here is small: walk length-delimited submessages down to Span, and
// read the handful of fields a span row shows. Unknown fields are skipped by
// wire type, which is what makes this forward-compatible with OTLP versions
// that add fields.

// Field numbers, from opentelemetry/proto/trace/v1/trace.proto and
// collector/trace/v1/trace_service.proto. Named because a bare number in a
// switch is unreviewable.
const (
	fieldExportResourceSpans = 1 // ExportTraceServiceRequest.resource_spans

	fieldResourceSpansResource = 1 // ResourceSpans.resource
	fieldResourceSpansScope    = 2 // ResourceSpans.scope_spans

	fieldResourceAttributes = 1 // Resource.attributes

	fieldScopeSpansSpans = 2 // ScopeSpans.spans

	fieldSpanTraceID    = 1
	fieldSpanSpanID     = 2
	fieldSpanParentID   = 4
	fieldSpanName       = 5
	fieldSpanKind       = 6
	fieldSpanStartNano  = 7
	fieldSpanEndNano    = 8
	fieldSpanAttributes = 9
	fieldSpanStatus     = 15

	// Status.code is field 3, not 1: field 1 is reserved in the proto. Getting
	// this wrong reads every span as UNSET, which renders as no status at all.
	fieldStatusMessage = 2
	fieldStatusCode    = 3

	fieldKeyValueKey   = 1
	fieldKeyValueValue = 2

	fieldAnyValueString = 1
	fieldAnyValueBool   = 2
	fieldAnyValueInt    = 3
	fieldAnyValueDouble = 4
)

// Protobuf wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

// maxProtoSpans bounds one request. A single OTLP batch is normally a few
// hundred spans; a body claiming a hundred thousand is either a misconfigured
// exporter or hostile, and either way the ring downstream keeps far fewer.
const maxProtoSpans = 4096

// spansFromOTLPProto decodes an ExportTraceServiceRequest. The second result
// reports whether the body parsed as protobuf at all, so a caller can fall
// back to shipping it raw rather than dropping it.
func spansFromOTLPProto(body []byte) ([]spanJSON, bool) {
	var out []spanJSON
	ok := walkProto(body, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldExportResourceSpans || wire != wireBytes {
			return true
		}
		return decodeResourceSpans(val, &out)
	})
	if !ok {
		return nil, false
	}
	return out, len(out) > 0
}

func decodeResourceSpans(b []byte, out *[]spanJSON) bool {
	// Resource attributes carry service.name, which is the only thing that
	// says WHICH application a span came from. A trace list without it is a
	// list of anonymous URLs.
	res := map[string]string{}
	ok := walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field == fieldResourceSpansResource && wire == wireBytes {
			return decodeResource(val, res)
		}
		return true
	})
	if !ok {
		return false
	}
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldResourceSpansScope || wire != wireBytes {
			return true
		}
		return walkProto(val, func(f, w int, v []byte, _ uint64) bool {
			if f != fieldScopeSpansSpans || w != wireBytes {
				return true
			}
			if len(*out) >= maxProtoSpans {
				return true
			}
			sp, ok := decodeSpan(v, res)
			if !ok {
				return false
			}
			if sp.TraceID == "" && sp.SpanID == "" {
				// Not addressable and not correlatable with anything: noise in
				// the list rather than a trace.
				return true
			}
			*out = append(*out, sp)
			return true
		})
	})
}

func decodeResource(b []byte, into map[string]string) bool {
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldResourceAttributes || wire != wireBytes {
			return true
		}
		// An attribute that will not parse is skipped, not fatal. Strictness
		// belongs at the top of the walk, where it distinguishes protobuf from
		// JSON; down here it would let one malformed attribute discard every
		// span in an otherwise good batch.
		if k, v, ok := decodeKeyValue(val); ok && k != "" && v != "" {
			into[k] = v
		}
		return true
	})
}

func decodeSpan(b []byte, resource map[string]string) (spanJSON, bool) {
	sp := spanJSON{}
	var attrs map[string]string
	var statusCode uint64
	var statusMsg string

	ok := walkProto(b, func(field, wire int, val []byte, num uint64) bool {
		switch {
		case field == fieldSpanTraceID && wire == wireBytes:
			sp.TraceID = hex.EncodeToString(val)
		case field == fieldSpanSpanID && wire == wireBytes:
			sp.SpanID = hex.EncodeToString(val)
		case field == fieldSpanParentID && wire == wireBytes:
			sp.ParentID = hex.EncodeToString(val)
		case field == fieldSpanName && wire == wireBytes:
			sp.Name = string(val)
		case field == fieldSpanKind && wire == wireVarint:
			sp.Kind = int(num)
		case field == fieldSpanStartNano && wire == wireI64:
			sp.StartNano = strconv.FormatUint(num, 10)
		case field == fieldSpanEndNano && wire == wireI64:
			sp.EndNano = strconv.FormatUint(num, 10)
		case field == fieldSpanAttributes && wire == wireBytes:
			// Skipped rather than fatal, for the reason in decodeResource.
			if k, v, ok := decodeKeyValue(val); ok && k != "" && v != "" {
				if attrs == nil {
					attrs = map[string]string{}
				}
				attrs[k] = v
			}
		case field == fieldSpanStatus && wire == wireBytes:
			return walkProto(val, func(f, w int, v []byte, n uint64) bool {
				switch {
				case f == fieldStatusCode && w == wireVarint:
					statusCode = n
				case f == fieldStatusMessage && w == wireBytes:
					statusMsg = string(v)
				}
				return true
			})
		}
		return true
	})
	if !ok {
		return spanJSON{}, false
	}

	for k, v := range resource {
		if attrs == nil {
			attrs = map[string]string{}
		}
		// A span attribute wins: it is the more specific statement.
		if _, taken := attrs[k]; !taken {
			attrs[k] = v
		}
	}
	sp.Attributes = attrs
	sp.Status = formatStatus(statusCode, statusMsg)
	return sp, true
}

// formatStatus renders a status the same way the JSON path does, so a span
// reads identically whichever wire format carried it.
func formatStatus(code uint64, msg string) string {
	status := ""
	switch code {
	case 1:
		status = "ok"
	case 2:
		status = "error"
	}
	if msg == "" {
		return status
	}
	if status == "" {
		return msg
	}
	return status + ": " + msg
}

// decodeKeyValue reads one KeyValue. Values that are not strings are rendered
// as strings: an int attribute like http.status_code is exactly the kind an
// operator filters on, and dropping it because of its type loses the attribute
// that mattered.
func decodeKeyValue(b []byte) (string, string, bool) {
	key, value := "", ""
	ok := walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		switch {
		case field == fieldKeyValueKey && wire == wireBytes:
			key = string(val)
		case field == fieldKeyValueValue && wire == wireBytes:
			return walkProto(val, func(f, w int, v []byte, n uint64) bool {
				switch {
				case f == fieldAnyValueString && w == wireBytes:
					value = string(v)
				case f == fieldAnyValueBool && w == wireVarint:
					value = strconv.FormatBool(n != 0)
				case f == fieldAnyValueInt && w == wireVarint:
					value = strconv.FormatInt(int64(n), 10)
				case f == fieldAnyValueDouble && w == wireI64:
					value = strconv.FormatFloat(math.Float64frombits(n), 'g', -1, 64)
				}
				return true
			})
		}
		return true
	})
	return key, value, ok
}

// walkProto iterates the fields of one protobuf message, calling fn for each.
// It returns false if the bytes are not well-formed protobuf, which is how a
// body that is actually something else is told apart from an empty one.
//
// num carries the numeric payload for varint and fixed-width fields; val
// carries the bytes for length-delimited ones. Unknown fields are skipped by
// wire type rather than rejected, so a newer OTLP adding a field does not
// break decoding of the fields already understood.
func walkProto(b []byte, fn func(field, wire int, val []byte, num uint64) bool) bool {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return false
		}
		b = b[n:]
		field, wire := int(key>>3), int(key&7)
		if field == 0 {
			return false
		}
		switch wire {
		case wireVarint:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
			if !fn(field, wire, nil, v) {
				return false
			}
		case wireI64:
			if len(b) < 8 {
				return false
			}
			v := binary.LittleEndian.Uint64(b)
			b = b[8:]
			if !fn(field, wire, nil, v) {
				return false
			}
		case wireBytes:
			size, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
			// The declared length must fit: a truncated or hostile body would
			// otherwise slice past the end.
			if size > uint64(len(b)) {
				return false
			}
			val := b[:size]
			b = b[size:]
			if !fn(field, wire, val, 0) {
				return false
			}
		case wireI32:
			if len(b) < 4 {
				return false
			}
			v := uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
			if !fn(field, wire, nil, v) {
				return false
			}
		default:
			// Groups (3 and 4) are deprecated and never appear in OTLP; an
			// unknown wire type means this is not the message it claims.
			return false
		}
	}
	return true
}
