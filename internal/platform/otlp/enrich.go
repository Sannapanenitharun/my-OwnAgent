package otlp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/obsagent/observability-agent/internal/platform"
)

// injectResourceSpans parses an ExportTraceServiceRequest protobuf and adds
// resource attributes to every ResourceSpans. If the body is not protobuf, it
// is returned unchanged (the exporter POSTs it as-is).
func injectResourceSpans(body []byte, res []platform.Attr) []byte {
	if len(body) == 0 || len(res) == 0 {
		return body
	}
	fields, err := parseMessage(body)
	if err != nil {
		return body
	}
	spans, ok := fields[fTracesResourceSpans]
	if !ok {
		return body
	}
	var out []byte
	for _, rs := range spans {
		if rs.wire != wireBytes {
			continue
		}
		out = appendTagMessage(out, fTracesResourceSpans, injectOneResource(rs.data, res))
	}
	if len(out) == 0 {
		return body
	}
	return out
}

func injectOneResource(rs []byte, res []platform.Attr) []byte {
	fields, err := parseMessage(rs)
	if err != nil {
		return rs
	}
	var resource []byte
	if existing, ok := fields[fRSResource]; ok && len(existing) > 0 && existing[0].wire == wireBytes {
		resource = existing[0].data
	}
	resource = mergeResourceAttrs(resource, res)

	var out []byte
	out = appendTagMessage(out, fRSResource, resource)
	for field, vals := range fields {
		if field == fRSResource {
			continue
		}
		for _, v := range vals {
			out = appendRaw(out, field, v)
		}
	}
	return out
}

func mergeResourceAttrs(resource []byte, extra []platform.Attr) []byte {
	fields, err := parseMessage(resource)
	if err != nil {
		fields = nil
	}
	have := map[string]struct{}{}
	if attrs := fields[fResourceAttrs]; len(attrs) > 0 {
		for _, a := range attrs {
			if a.wire != wireBytes {
				continue
			}
			if k := keyValueKey(a.data); k != "" {
				have[k] = struct{}{}
			}
		}
	}
	out := append([]byte(nil), resource...)
	for _, a := range extra {
		if a.Key == "" || a.Value == "" {
			continue
		}
		if _, ok := have[a.Key]; ok {
			continue
		}
		out = appendTagMessage(out, fResourceAttrs, encodeKeyValue(a.Key, a.Value))
	}
	return out
}

func keyValueKey(msg []byte) string {
	fields, err := parseMessage(msg)
	if err != nil {
		return ""
	}
	vals := fields[fKVKey]
	if len(vals) == 0 || vals[0].wire != wireBytes {
		return ""
	}
	return string(vals[0].data)
}

type rawVal struct {
	wire int
	data []byte
	num  uint64
}

func parseMessage(b []byte) (map[int][]rawVal, error) {
	out := map[int][]rawVal{}
	i := 0
	for i < len(b) {
		key, n := consumeUvarint(b[i:])
		if n == 0 {
			return nil, fmt.Errorf("bad key")
		}
		i += n
		field := int(key >> 3)
		wire := int(key & 7)
		switch wire {
		case wireVarint:
			v, n := consumeUvarint(b[i:])
			if n == 0 {
				return nil, fmt.Errorf("bad varint")
			}
			i += n
			out[field] = append(out[field], rawVal{wire: wire, num: v})
		case wireFixed64:
			if i+8 > len(b) {
				return nil, fmt.Errorf("truncated fixed64")
			}
			out[field] = append(out[field], rawVal{wire: wire, data: append([]byte(nil), b[i:i+8]...)})
			i += 8
		case wireBytes:
			ln, n := consumeUvarint(b[i:])
			if n == 0 {
				return nil, fmt.Errorf("bad len")
			}
			i += n
			if i+int(ln) > len(b) {
				return nil, fmt.Errorf("truncated bytes")
			}
			out[field] = append(out[field], rawVal{wire: wire, data: append([]byte(nil), b[i:i+int(ln)]...)})
			i += int(ln)
		case 5: // fixed32
			if i+4 > len(b) {
				return nil, fmt.Errorf("truncated fixed32")
			}
			out[field] = append(out[field], rawVal{wire: wire, data: append([]byte(nil), b[i:i+4]...)})
			i += 4
		default:
			return nil, fmt.Errorf("unsupported wire %d", wire)
		}
	}
	return out, nil
}

func appendRaw(b []byte, field int, v rawVal) []byte {
	switch v.wire {
	case wireVarint:
		return appendTagUvarint(b, field, v.num)
	case wireFixed64:
		b = appendKey(b, field, wireFixed64)
		return append(b, v.data...)
	case wireBytes:
		return appendTagBytes(b, field, v.data)
	case 5:
		b = appendKey(b, field, 5)
		return append(b, v.data...)
	default:
		return b
	}
}

func consumeUvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i := 0; i < len(b) && i < 10; i++ {
		v := b[i]
		if v < 0x80 {
			return x | uint64(v)<<s, i + 1
		}
		x |= uint64(v&0x7f) << s
		s += 7
	}
	return 0, 0
}

// tracesJSONToProto converts a protojson ExportTraceServiceRequest into
// protobuf. Only the fields we forward are mapped: resourceSpans, resource
// attributes, and span identity/timing/status. Unknown nested detail is
// dropped rather than guessed.
func tracesJSONToProto(body []byte) ([]byte, error) {
	var top struct {
		ResourceSpans []jsonResourceSpans `json:"resourceSpans"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	var req []byte
	for _, rs := range top.ResourceSpans {
		req = appendTagMessage(req, fTracesResourceSpans, encodeJSONResourceSpans(rs))
	}
	if len(req) == 0 {
		return nil, fmt.Errorf("no resourceSpans")
	}
	return req, nil
}

type jsonResourceSpans struct {
	Resource   jsonResource    `json:"resource"`
	ScopeSpans []jsonScopeSpan `json:"scopeSpans"`
}

type jsonResource struct {
	Attributes []jsonKV `json:"attributes"`
}

type jsonKV struct {
	Key   string       `json:"key"`
	Value jsonAnyValue `json:"value"`
}

type jsonAnyValue struct {
	StringValue string `json:"stringValue"`
}

type jsonScopeSpan struct {
	Spans []jsonSpan `json:"spans"`
}

type jsonSpan struct {
	TraceID           string   `json:"traceId"`
	SpanID            string   `json:"spanId"`
	ParentSpanID      string   `json:"parentSpanId"`
	Name              string   `json:"name"`
	Kind              int      `json:"kind"`
	StartTimeUnixNano string   `json:"startTimeUnixNano"`
	EndTimeUnixNano   string   `json:"endTimeUnixNano"`
	Attributes        []jsonKV `json:"attributes"`
	Status            struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

func encodeJSONResourceSpans(rs jsonResourceSpans) []byte {
	var resource []byte
	for _, a := range rs.Resource.Attributes {
		val := a.Value.StringValue
		if val == "" {
			continue
		}
		resource = appendTagMessage(resource, fResourceAttrs, encodeKeyValue(a.Key, val))
	}
	var out []byte
	out = appendTagMessage(out, fRSResource, resource)
	for _, ss := range rs.ScopeSpans {
		var scopeSpans []byte
		scopeSpans = appendTagMessage(scopeSpans, fSSScope, encodeScope("observability-agent", "1.0.0"))
		for _, sp := range ss.Spans {
			scopeSpans = appendTagMessage(scopeSpans, fSSSpans, encodeJSONSpan(sp))
		}
		out = appendTagMessage(out, fRSScopeSpans, scopeSpans)
	}
	return out
}

func encodeJSONSpan(sp jsonSpan) []byte {
	const (
		fSpanTraceID   = 1
		fSpanSpanID    = 2
		fSpanParent    = 4
		fSpanName      = 5
		fSpanKind      = 6
		fSpanStart     = 7
		fSpanEnd       = 8
		fSpanAttrs     = 9
		fSpanStatus    = 15
		fStatusMessage = 2
		fStatusCode    = 3
	)
	var b []byte
	b = appendTagBytes(b, fSpanTraceID, decodeHexID(sp.TraceID, 16))
	b = appendTagBytes(b, fSpanSpanID, decodeHexID(sp.SpanID, 8))
	b = appendTagBytes(b, fSpanParent, decodeHexID(sp.ParentSpanID, 8))
	b = appendTagString(b, fSpanName, sp.Name)
	if sp.Kind != 0 {
		b = appendTagUvarint(b, fSpanKind, uint64(sp.Kind))
	}
	b = appendTagFixed64(b, fSpanStart, parseDecU64(sp.StartTimeUnixNano))
	b = appendTagFixed64(b, fSpanEnd, parseDecU64(sp.EndTimeUnixNano))
	b = append(b, encodeAttrList(fSpanAttrs, jsonAttrs(sp.Attributes))...)
	var st []byte
	st = appendTagString(st, fStatusMessage, sp.Status.Message)
	st = appendTagUvarint(st, fStatusCode, uint64(sp.Status.Code))
	b = appendTagMessage(b, fSpanStatus, st)
	return b
}

func jsonAttrs(in []jsonKV) []platform.Attr {
	out := make([]platform.Attr, 0, len(in))
	for _, a := range in {
		if a.Key == "" || a.Value.StringValue == "" {
			continue
		}
		out = append(out, platform.A(a.Key, a.Value.StringValue))
	}
	return out
}

func decodeHexID(s string, n int) []byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := make([]byte, 0, n)
	for i := 0; i+1 < len(s) && len(out) < n; i += 2 {
		hi := unhex(s[i])
		lo := unhex(s[i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out = append(out, byte(hi<<4|lo))
	}
	if len(out) != n {
		return nil
	}
	return out
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

func parseDecU64(s string) uint64 {
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}
