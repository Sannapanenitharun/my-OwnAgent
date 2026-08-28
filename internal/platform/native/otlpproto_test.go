package native

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// Minimal protobuf writers. The agent has no protobuf dependency, so the test
// builds its fixtures the same way a real exporter's generated code would --
// which is the point: a fixture written with the decoder's own helpers would
// only prove the decoder agrees with itself.

func pbVarint(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func pbTag(field, wire int) []byte { return pbVarint(uint64(field)<<3 | uint64(wire)) }

func pbBytes(field int, val []byte) []byte {
	return append(append(pbTag(field, 2), pbVarint(uint64(len(val)))...), val...)
}

func pbString(field int, s string) []byte { return pbBytes(field, []byte(s)) }

func pbUint(field int, n uint64) []byte { return append(pbTag(field, 0), pbVarint(n)...) }

func pbFixed64(field int, n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return append(pbTag(field, 1), b...)
}

func pbDouble(field int, f float64) []byte { return pbFixed64(field, math.Float64bits(f)) }

// pbAttr builds a KeyValue whose AnyValue holds val, which may be a string,
// int64, bool or float64 -- the four scalar shapes real instrumentation emits.
func pbAttr(key string, val any) []byte {
	var any_ []byte
	switch v := val.(type) {
	case string:
		any_ = pbString(1, v)
	case bool:
		n := uint64(0)
		if v {
			n = 1
		}
		any_ = pbUint(2, n)
	case int:
		any_ = pbUint(3, uint64(v))
	case float64:
		any_ = pbDouble(4, v)
	default:
		panic("unsupported attribute type")
	}
	return pbBytes(9, append(pbString(1, key), pbBytes(2, any_)...))
}

type fixtureSpan struct {
	traceID, spanID, parentID []byte
	name                      string
	kind                      int
	start, end                uint64
	statusCode                int
	statusMsg                 string
	attrs                     [][]byte
}

func (f fixtureSpan) encode() []byte {
	var b []byte
	if f.traceID != nil {
		b = append(b, pbBytes(1, f.traceID)...)
	}
	if f.spanID != nil {
		b = append(b, pbBytes(2, f.spanID)...)
	}
	if f.parentID != nil {
		b = append(b, pbBytes(4, f.parentID)...)
	}
	b = append(b, pbString(5, f.name)...)
	b = append(b, pbUint(6, uint64(f.kind))...)
	b = append(b, pbFixed64(7, f.start)...)
	b = append(b, pbFixed64(8, f.end)...)
	for _, a := range f.attrs {
		b = append(b, a...)
	}
	if f.statusCode != 0 || f.statusMsg != "" {
		// Status.message is field 2 and Status.code is field 3; field 1 is
		// reserved. This ordering is deliberate -- see the decoder.
		var st []byte
		if f.statusMsg != "" {
			st = append(st, pbString(2, f.statusMsg)...)
		}
		st = append(st, pbUint(3, uint64(f.statusCode))...)
		b = append(b, pbBytes(15, st)...)
	}
	return b
}

// exportRequest wraps spans as ExportTraceServiceRequest{ResourceSpans{
// Resource, ScopeSpans{Span...}}}, which is exactly what an OTLP/HTTP POST
// body contains.
func exportRequest(resourceAttrs [][]byte, spans ...fixtureSpan) []byte {
	var scope []byte
	for _, sp := range spans {
		scope = append(scope, pbBytes(2, sp.encode())...)
	}
	var rs []byte
	if len(resourceAttrs) > 0 {
		var res []byte
		for _, a := range resourceAttrs {
			// Resource.attributes is field 1; pbAttr emits field 9 for
			// Span.attributes, so retag it.
			res = append(res, retag(a, 1)...)
		}
		rs = append(rs, pbBytes(1, res)...)
	}
	rs = append(rs, pbBytes(2, scope)...)
	return pbBytes(1, rs)
}

// retag rewrites the field number of a single length-delimited field.
func retag(field []byte, to int) []byte {
	_, n := binary.Uvarint(field)
	return append(pbTag(to, 2), field[n:]...)
}

// TestProtobufSpansAreDecoded is the defect this file exists for. The receiver
// answered 200 to protobuf and then dropped it, and protobuf is OTLP/HTTP's
// DEFAULT: every stock SDK sent the one format the agent could not read, so an
// operator who instrumented an application correctly saw an empty Traces tab
// and no error anywhere explaining why.
func TestProtobufSpansAreDecoded(t *testing.T) {
	body := exportRequest(
		[][]byte{pbAttr("service.name", "checkout")},
		fixtureSpan{
			traceID:    []byte("0123456789abcdef"),
			spanID:     []byte("01234567"),
			name:       "GET /rest/products",
			kind:       2,
			start:      1000,
			end:        1500,
			statusCode: 2,
			statusMsg:  "upstream timeout",
			attrs: [][]byte{
				pbAttr("http.method", "GET"),
				pbAttr("http.status_code", 503),
				pbAttr("http.resend", true),
				pbAttr("duration.ratio", 0.5),
			},
		},
	)

	spans, ok := spansFromOTLPProto(body)
	if !ok || len(spans) != 1 {
		t.Fatalf("decoded %d spans ok=%v, want 1", len(spans), ok)
	}
	sp := spans[0]
	if sp.Name != "GET /rest/products" {
		t.Errorf("name = %q", sp.Name)
	}
	if sp.TraceID != "30313233343536373839616263646566" {
		t.Errorf("trace id = %q, want lowercase hex of the raw bytes", sp.TraceID)
	}
	if sp.Kind != 2 {
		t.Errorf("kind = %d, want 2 (server)", sp.Kind)
	}
	if sp.StartNano != "1000" || sp.EndNano != "1500" {
		t.Errorf("times = %q..%q", sp.StartNano, sp.EndNano)
	}
	if sp.Status != "error: upstream timeout" {
		t.Errorf("status = %q, want the JSON path's rendering", sp.Status)
	}
	if sp.Attributes["service.name"] != "checkout" {
		t.Error("service.name from the resource did not reach the span; " +
			"without it a span list cannot say which application sent it")
	}
	// Non-string attributes are the ones an operator filters on. Keeping only
	// strings would silently discard every status code and duration.
	for k, want := range map[string]string{
		"http.method":      "GET",
		"http.status_code": "503",
		"http.resend":      "true",
		"duration.ratio":   "0.5",
	} {
		if got := sp.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}
}

// TestStatusCodeIsFieldThree guards the trap in the proto: Status field 1 is
// reserved, so reading code from field 1 yields UNSET for every span and every
// failed request renders as blank rather than as an error.
func TestStatusCodeIsFieldThree(t *testing.T) {
	body := exportRequest(nil, fixtureSpan{
		traceID: []byte("aaaaaaaaaaaaaaaa"), spanID: []byte("bbbbbbbb"),
		name: "op", statusCode: 2,
	})
	spans, _ := spansFromOTLPProto(body)
	if len(spans) != 1 || spans[0].Status != "error" {
		t.Fatalf("status = %q, want \"error\"", spans[0].Status)
	}
}

// TestUnsetStatusStaysEmpty documents the common case. Most SDKs leave a
// successful span UNSET rather than setting OK, so "no status" must not be
// invented into one.
func TestUnsetStatusStaysEmpty(t *testing.T) {
	body := exportRequest(nil, fixtureSpan{
		traceID: []byte("cccccccccccccccc"), spanID: []byte("dddddddd"), name: "op",
	})
	spans, _ := spansFromOTLPProto(body)
	if len(spans) != 1 || spans[0].Status != "" {
		t.Fatalf("status = %q, want empty for an unset status", spans[0].Status)
	}
}

func TestSpanAttributeBeatsResourceAttribute(t *testing.T) {
	// A span that names its own service is making the more specific claim.
	body := exportRequest(
		[][]byte{pbAttr("service.name", "gateway")},
		fixtureSpan{
			traceID: []byte("eeeeeeeeeeeeeeee"), spanID: []byte("ffffffff"), name: "op",
			attrs: [][]byte{pbAttr("service.name", "inner")},
		},
	)
	spans, _ := spansFromOTLPProto(body)
	if spans[0].Attributes["service.name"] != "inner" {
		t.Errorf("service.name = %q, want the span's own", spans[0].Attributes["service.name"])
	}
}

// TestUnknownFieldsAreSkipped is what keeps this working against future OTLP
// versions. A decoder that rejected fields it did not recognise would start
// dropping spans the moment an SDK was upgraded.
func TestUnknownFieldsAreSkipped(t *testing.T) {
	sp := fixtureSpan{traceID: []byte("1111111111111111"), spanID: []byte("22222222"), name: "op"}
	enc := sp.encode()
	enc = append(enc, pbString(99, "a field from a newer OTLP")...)
	enc = append(enc, pbUint(98, 12345)...)
	enc = append(enc, pbFixed64(97, 7)...)
	enc = append(enc, pbTag(96, 5)...)
	enc = append(enc, 1, 2, 3, 4) // fixed32
	body := pbBytes(1, pbBytes(2, pbBytes(2, enc)))

	spans, ok := spansFromOTLPProto(body)
	if !ok || len(spans) != 1 || spans[0].Name != "op" {
		t.Fatalf("decoded %d spans ok=%v; unknown fields must be skipped", len(spans), ok)
	}
}

// TestMalformedBodyIsRejectedNotMisread matters because the caller falls back
// to another decoder on failure. Silently "succeeding" with zero spans would
// make a corrupt body indistinguishable from an empty batch.
func TestMalformedBodyIsRejectedNotMisread(t *testing.T) {
	cases := map[string][]byte{
		"truncated length":  append(pbTag(1, 2), 0x7f), // claims 127 bytes, has none
		"truncated fixed64": append(pbTag(1, 1), 1, 2, 3),
		"field zero":        {0x00, 0x01},
		"group wire type":   append(pbTag(1, 3), 1),
		"random bytes":      []byte("this is not protobuf at all\xff\xfe"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := spansFromOTLPProto(body); ok {
				t.Error("malformed body reported as decodable protobuf")
			}
		})
	}
}

func TestSpanWithNoIDsIsDropped(t *testing.T) {
	// Nothing can be correlated with it, so it is a row of noise.
	body := exportRequest(nil, fixtureSpan{name: "anonymous"})
	if spans, ok := spansFromOTLPProto(body); ok || len(spans) != 0 {
		t.Errorf("decoded %d spans, want none", len(spans))
	}
}

func TestProtoSpanCountIsBounded(t *testing.T) {
	many := make([]fixtureSpan, maxProtoSpans+50)
	for i := range many {
		many[i] = fixtureSpan{traceID: []byte("3333333333333333"), spanID: []byte("44444444"), name: "op"}
	}
	spans, _ := spansFromOTLPProto(exportRequest(nil, many...))
	if len(spans) > maxProtoSpans {
		t.Errorf("decoded %d spans, want at most %d", len(spans), maxProtoSpans)
	}
}

// TestEncodeTracesShipsProtobufAsSpans is the end of the path inside the
// agent: a protobuf payload must leave as spans in the envelope, not as an
// opaque raw blob that nothing downstream reads.
func TestEncodeTracesShipsProtobufAsSpans(t *testing.T) {
	body := exportRequest(
		[][]byte{pbAttr("service.name", "checkout")},
		fixtureSpan{traceID: []byte("5555555555555555"), spanID: []byte("66666666"), name: "GET /cart"},
	)
	out := encodeTraces(
		[]platform.Attr{{Key: "host.id", Value: "h1"}},
		[]platform.TracePayload{{ContentType: "application/x-protobuf", Body: body}},
		time.Unix(0, 0),
	)
	var env struct {
		Spans []spanJSON `json:"spans"`
		Raw   []rawJSON  `json:"raw"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if len(env.Spans) != 1 || env.Spans[0].Name != "GET /cart" {
		t.Fatalf("spans = %+v, want the decoded span", env.Spans)
	}
	if len(env.Raw) != 0 {
		t.Error("protobuf was also shipped raw; it is decoded now")
	}
}

// TestMislabelledContentTypeStillDecodes covers exporters and proxies that get
// the header wrong. The body is the evidence; the header is a hint.
func TestMislabelledContentTypeStillDecodes(t *testing.T) {
	proto := exportRequest(nil, fixtureSpan{
		traceID: []byte("7777777777777777"), spanID: []byte("88888888"), name: "mislabelled",
	})
	out := encodeTraces(nil, []platform.TracePayload{
		{ContentType: "application/json", Body: proto},
	}, time.Unix(0, 0))
	var env struct {
		Spans []spanJSON `json:"spans"`
	}
	_ = json.Unmarshal(out, &env)
	if len(env.Spans) != 1 || env.Spans[0].Name != "mislabelled" {
		t.Errorf("spans = %+v, want the protobuf body decoded despite the header", env.Spans)
	}

	jsonBody := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aa","spanId":"bb","name":"json-body"}]}]}]}`)
	out = encodeTraces(nil, []platform.TracePayload{
		{ContentType: "application/x-protobuf", Body: jsonBody},
	}, time.Unix(0, 0))
	env.Spans = nil
	_ = json.Unmarshal(out, &env)
	if len(env.Spans) != 1 || env.Spans[0].Name != "json-body" {
		t.Errorf("spans = %+v, want the JSON body decoded despite the header", env.Spans)
	}
}

// TestUndecodableBodyIsStillShipped keeps the fallback honest: a format this
// agent cannot parse must reach the archive rather than vanish.
func TestUndecodableBodyIsStillShipped(t *testing.T) {
	junk := []byte("\xff\xfe not a known encoding")
	out := encodeTraces(nil, []platform.TracePayload{
		{ContentType: "application/octet-stream", Body: junk},
	}, time.Unix(0, 0))
	var env struct {
		Raw []rawJSON `json:"raw"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if len(env.Raw) != 1 {
		t.Fatalf("raw = %d, want the undecodable body preserved", len(env.Raw))
	}
	got, _ := base64.StdEncoding.DecodeString(env.Raw[0].BodyBase64)
	if string(got) != string(junk) {
		t.Error("the preserved body does not match what was received")
	}
}

// TestOneBadAttributeDoesNotDiscardTheBatch. Attribute decoding used to be
// fatal, so a single KeyValue this decoder could not read rejected the whole
// ExportTraceServiceRequest -- every span in it, silently. Strictness belongs
// at the top of the walk, where it tells protobuf apart from JSON; an
// unreadable attribute is a missing label, not a corrupt batch.
func TestOneBadAttributeDoesNotDiscardTheBatch(t *testing.T) {
	// A KeyValue whose value submessage is not parseable protobuf.
	bad := pbBytes(9, append(pbString(1, "broken"), pbBytes(2, []byte{0x00, 0x01})...))
	body := exportRequest(nil, fixtureSpan{
		traceID: []byte("9999999999999999"), spanID: []byte("aaaaaaaa"), name: "survives",
		attrs: [][]byte{bad, pbAttr("http.method", "GET")},
	})
	spans, ok := spansFromOTLPProto(body)
	if !ok || len(spans) != 1 {
		t.Fatalf("decoded %d spans ok=%v; one bad attribute must not drop the span", len(spans), ok)
	}
	if spans[0].Attributes["http.method"] != "GET" {
		t.Error("the readable attributes were lost along with the unreadable one")
	}
	if _, present := spans[0].Attributes["broken"]; present {
		t.Error("an attribute whose value could not be read was invented anyway")
	}
}

// TestJSONBodyIsStillRejectedByTheProtoDecoder guards the fallback. If a JSON
// body ever parsed as protobuf, encodeTraces would take the proto decoder's
// empty answer and never try the JSON one.
func TestJSONBodyIsStillRejectedByTheProtoDecoder(t *testing.T) {
	body := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"x"}]}]}]}`)
	if _, ok := spansFromOTLPProto(body); ok {
		t.Error("a JSON body was accepted as protobuf")
	}
}

// TestBothWireFormatsProduceTheSameSpan is the invariant that matters once
// there are two decoders. An application must not report a different span
// because it chose a different encoding of the same request -- that turns the
// wire format into a silent feature flag.
func TestBothWireFormatsProduceTheSameSpan(t *testing.T) {
	proto := exportRequest(
		[][]byte{pbAttr("service.name", "checkout")},
		fixtureSpan{
			traceID: []byte("0123456789abcdef"), spanID: []byte("01234567"),
			name: "GET /cart", kind: 2, statusCode: 2, statusMsg: "boom",
			attrs: [][]byte{pbAttr("http.method", "GET"), pbAttr("http.status_code", 503)},
		},
	)
	jsonBody := []byte(`{"resourceSpans":[{
		"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"checkout"}}]},
		"scopeSpans":[{"spans":[{
			"traceId":"30313233343536373839616263646566",
			"spanId":"3031323334353637",
			"name":"GET /cart","kind":2,
			"attributes":[
				{"key":"http.method","value":{"stringValue":"GET"}},
				{"key":"http.status_code","value":{"intValue":"503"}}],
			"status":{"code":2,"message":"boom"}}]}]}]}`)

	fromProto, ok := spansFromOTLPProto(proto)
	if !ok || len(fromProto) != 1 {
		t.Fatalf("protobuf decode failed: %d spans ok=%v", len(fromProto), ok)
	}
	fromJSON, ok := spansFromOTLPJSON(jsonBody)
	if !ok || len(fromJSON) != 1 {
		t.Fatalf("json decode failed: %d spans ok=%v", len(fromJSON), ok)
	}
	a, b := fromProto[0], fromJSON[0]
	if a.TraceID != b.TraceID || a.SpanID != b.SpanID {
		t.Errorf("ids differ: proto %s/%s, json %s/%s", a.TraceID, a.SpanID, b.TraceID, b.SpanID)
	}
	if a.Name != b.Name || a.Kind != b.Kind || a.Status != b.Status {
		t.Errorf("proto %q/%d/%q vs json %q/%d/%q", a.Name, a.Kind, a.Status, b.Name, b.Kind, b.Status)
	}
	for _, k := range []string{"service.name", "http.method", "http.status_code"} {
		if a.Attributes[k] != b.Attributes[k] {
			t.Errorf("attribute %s: proto %q, json %q", k, a.Attributes[k], b.Attributes[k])
		}
	}
	if b.Attributes["service.name"] != "checkout" {
		t.Error("the JSON path did not read service.name from the resource")
	}
	if b.Attributes["http.status_code"] != "503" {
		t.Error("the JSON path dropped a non-string attribute")
	}
}
