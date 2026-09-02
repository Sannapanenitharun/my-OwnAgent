package native

import (
	"strings"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The tests this package never had.
//
// Every existing OTLP test asked "does a trace decode correctly". None asked
// what happens to a payload that is NOT a trace, and that is the exact shape of
// the hole: OTLP metrics and logs were accepted by the receiver, counted as
// accepted, and then dropped by the exporter without a counter.

func metricsBody(name string, value float64, resAttrs ...string) []byte {
	point := pbDouble(fieldNumberAsDouble, value)
	gauge := pbBytes(fieldMetricGauge, pbBytes(fieldPointsGauge, point))
	metric := append(pbString(fieldMetricName, name), gauge...)
	scope := pbBytes(fieldResourceMetricsScope, pbBytes(fieldScopeMetricsMetrics, metric))
	var rm []byte
	if len(resAttrs) >= 2 {
		var attrs []byte
		for i := 0; i+1 < len(resAttrs); i += 2 {
			kv := append(pbString(fieldKeyValueKey, resAttrs[i]),
				pbBytes(fieldKeyValueValue, pbString(fieldAnyValueString, resAttrs[i+1]))...)
			attrs = append(attrs, pbBytes(fieldResourceAttributes, kv)...)
		}
		rm = pbBytes(fieldResourceMetricsResource, attrs)
	}
	rm = append(rm, scope...)
	return pbBytes(fieldExportResourceMetrics, rm)
}

func logsBody(msg string, sev uint64, nano uint64) []byte {
	rec := pbFixed64(fieldLogTimeNano, nano)
	rec = append(rec, pbUint(fieldLogSeverityNumber, sev)...)
	rec = append(rec, pbBytes(fieldLogBody, pbString(fieldAnyValueString, msg))...)
	scope := pbBytes(fieldResourceLogsScope, pbBytes(fieldScopeLogsRecords, rec))
	return pbBytes(fieldExportResourceLogs, scope)
}

// TestAMetricNeverBecomesASpan is the regression that matters.
//
// The three OTLP request types share field numbers all the way down, and
// Metric.name is field 1 bytes -- the slot Span.trace_id occupies. A metrics
// body therefore walks cleanly through the span decoder, and the old
// "reject only if BOTH ids are empty" gate let the result through on the
// strength of a trace ID that was really a metric name in hex.
func TestAMetricNeverBecomesASpan(t *testing.T) {
	body := metricsBody("system.cpu.time", 42)

	spans, ok := spansFromOTLPProto(body)
	if ok || len(spans) != 0 {
		t.Fatalf("a metrics payload decoded into %d span(s) (ok=%v); first=%+v", len(spans), ok, spans)
	}

	// And the encoder refuses it even if a caller routes it wrongly.
	out, _ := encodeTraces(nil, []platform.TracePayload{{
		ContentType: "application/x-protobuf", Body: body, Signal: "metrics",
	}}, time.Unix(0, 0), sampleAll)
	if len(out) != 0 {
		t.Errorf("encodeTraces produced a trace envelope from a metrics payload: %s", out)
	}
}

// TestReceivedMetricsReachTheEnvelope. The point of the fix: what an
// application sends actually leaves the host.
func TestReceivedMetricsReachTheEnvelope(t *testing.T) {
	body := metricsBody("http.server.duration", 12.5, "service.name", "checkout")

	out, stats := encodeOTLPMetrics(
		[]platform.Attr{{Key: "host.id", Value: "h-1"}},
		[]platform.TracePayload{{ContentType: "application/x-protobuf", Body: body, Signal: "metrics"}},
		time.Unix(0, 0),
	)
	if len(out) == 0 {
		t.Fatal("no envelope produced from a valid metrics payload")
	}
	if stats.Decoded != 1 || stats.Undecoded != 0 {
		t.Errorf("stats = %+v, want 1 decoded 0 undecoded", stats)
	}
	s := string(out)
	for _, want := range []string{
		`"signal":"metrics"`,
		`"http.server.duration"`,
		`"value":12.5`,
		`"service.name":"checkout"`, // the app's identity rides on the point
		`"host":"h-1"`,              // the host's identity stays on the envelope
	} {
		if !strings.Contains(s, want) {
			t.Errorf("envelope missing %s\ngot: %s", want, s)
		}
	}
}

// TestReceivedLogsReachTheEnvelope.
func TestReceivedLogsReachTheEnvelope(t *testing.T) {
	body := logsBody("order 41 rejected", 17, 1700000000000000000) // 17 = ERROR

	out, stats := encodeOTLPLogs(nil,
		[]platform.TracePayload{{ContentType: "application/x-protobuf", Body: body, Signal: "logs"}},
		time.Unix(0, 0),
	)
	if len(out) == 0 {
		t.Fatal("no envelope produced from a valid logs payload")
	}
	if stats.Decoded != 1 {
		t.Errorf("stats = %+v, want 1 decoded", stats)
	}
	s := string(out)
	for _, want := range []string{
		`"signal":"logs"`,
		`"order 41 rejected"`,
		`"status":"error"`,
		`"2023-11-14T`, // the record's own timestamp, not the flush time
	} {
		if !strings.Contains(s, want) {
			t.Errorf("envelope missing %s\ngot: %s", want, s)
		}
	}
}

// TestEachSignalIsRoutedToItsOwnEnvelope drives the real exporter the way the
// receiver does, and asserts the whole batch survives. Before the fix this
// posted exactly one body -- traces -- and dropped the other two in silence.
func TestEachSignalIsRoutedToItsOwnEnvelope(t *testing.T) {
	e := New(nil, Config{Endpoint: "http://127.0.0.1:1", MaxBatch: 100})

	e.IngestTraces(platform.TracePayload{ContentType: "application/x-protobuf", Body: metricsBody("q.depth", 3), Signal: "metrics"})
	e.IngestTraces(platform.TracePayload{ContentType: "application/x-protobuf", Body: logsBody("hello", 9, 0), Signal: "logs"})

	e.mu.Lock()
	batch := e.traces
	e.mu.Unlock()
	if len(batch) != 2 {
		t.Fatalf("exporter retained %d of 2 ingested payloads; non-trace signals are being dropped at the door", len(batch))
	}

	sigs := map[string]int{}
	for _, p := range batch {
		sigs[p.Signal]++
	}
	if sigs["metrics"] != 1 || sigs["logs"] != 1 {
		t.Errorf("retained signals = %v, want one of each", sigs)
	}
}

// TestAnUndecodablePayloadIsCounted. The failure that has to stay visible: an
// operator chasing missing telemetry must be able to tell "the agent could not
// read it" from "the application never sent it".
func TestAnUndecodablePayloadIsCounted(t *testing.T) {
	out, stats := encodeOTLPMetrics(nil, []platform.TracePayload{{
		ContentType: "application/x-protobuf",
		Body:        []byte{0xff, 0xff, 0xff, 0xff},
		Signal:      "metrics",
	}}, time.Unix(0, 0))
	if len(out) != 0 {
		t.Error("garbage produced an envelope")
	}
	if stats.Undecoded != 1 {
		t.Errorf("stats = %+v, want 1 undecoded", stats)
	}
}

// TestMonotonicSumsAreCountersAndTheRestAreGauges. A non-monotonic sum is a
// value that goes down -- a queue depth, a pool size -- and charting it as a
// counter would show it decreasing, which no counter does.
func TestMonotonicSumsAreCountersAndTheRestAreGauges(t *testing.T) {
	build := func(monotonic bool) []byte {
		point := pbDouble(fieldNumberAsDouble, 7)
		sum := pbBytes(fieldPointsSum, point)
		if monotonic {
			sum = append(sum, pbUint(fieldSumIsMonotonic, 1)...)
		}
		metric := append(pbString(fieldMetricName, "n"), pbBytes(fieldMetricSum, sum)...)
		scope := pbBytes(fieldResourceMetricsScope, pbBytes(fieldScopeMetricsMetrics, metric))
		return pbBytes(fieldExportResourceMetrics, scope)
	}

	mono, ok := metricsFromOTLPProto(build(true))
	if !ok || len(mono.Counters) != 1 || len(mono.Gauges) != 0 {
		t.Errorf("monotonic sum: counters=%d gauges=%d, want 1 and 0", len(mono.Counters), len(mono.Gauges))
	}
	non, ok := metricsFromOTLPProto(build(false))
	if !ok || len(non.Gauges) != 1 || len(non.Counters) != 0 {
		t.Errorf("non-monotonic sum: gauges=%d counters=%d, want 1 and 0", len(non.Gauges), len(non.Counters))
	}
}

// TestJSONAndProtobufAgree. An exporter set to http/json must not find a
// second silent hole where the protobuf one was.
func TestJSONAndProtobufAgree(t *testing.T) {
	jsonBody := []byte(`{"resourceMetrics":[{"resource":{"attributes":[
	  {"key":"service.name","value":{"stringValue":"checkout"}}]},
	  "scopeMetrics":[{"metrics":[
	    {"name":"http.server.duration","gauge":{"dataPoints":[{"asDouble":12.5}]}},
	    {"name":"http.requests","sum":{"isMonotonic":true,"dataPoints":[{"asInt":"9"}]}}]}]}]}`)

	m, ok := metricsFromOTLPJSON(jsonBody)
	if !ok {
		t.Fatal("OTLP/JSON metrics did not decode")
	}
	if len(m.Gauges) != 1 || m.Gauges[0].Value != 12.5 {
		t.Errorf("gauges = %+v", m.Gauges)
	}
	if len(m.Counters) != 1 || m.Counters[0].Value != 9 {
		t.Errorf("counters = %+v (asInt arrives as a JSON string and must still parse)", m.Counters)
	}
	if m.Gauges[0].Attributes["service.name"] != "checkout" {
		t.Errorf("resource attributes did not reach the point: %v", m.Gauges[0].Attributes)
	}

	logBody := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[
	  {"severityNumber":13,"body":{"stringValue":"disk almost full"}}]}]}]}`)
	recs, ok := logsFromOTLPJSON(logBody, time.Unix(0, 0))
	if !ok || len(recs) != 1 {
		t.Fatalf("OTLP/JSON logs decoded %d records", len(recs))
	}
	if recs[0].Status != "warn" || recs[0].Message != "disk almost full" {
		t.Errorf("record = %+v", recs[0])
	}
}

// TestAnAllZeroTraceIDIsNotCorrelation. OTLP writes all-zero IDs to mean
// "absent"; carrying one as real would file every uncorrelated log line under
// a single fictional trace.
func TestAnAllZeroTraceIDIsNotCorrelation(t *testing.T) {
	rec := pbBytes(fieldLogBody, pbString(fieldAnyValueString, "x"))
	rec = append(rec, pbBytes(fieldLogTraceID, make([]byte, 16))...)
	body := pbBytes(fieldExportResourceLogs,
		pbBytes(fieldResourceLogsScope, pbBytes(fieldScopeLogsRecords, rec)))

	recs, ok := logsFromOTLPProto(body, time.Unix(0, 0))
	if !ok || len(recs) != 1 {
		t.Fatalf("decoded %d records", len(recs))
	}
	if _, present := recs[0].Attributes["trace_id"]; present {
		t.Errorf("an all-zero trace ID was carried as correlation: %v", recs[0].Attributes)
	}
}

// TestDecodedOTLPContentIsRedacted.
//
// Everything a module emits passes through scrub.Telemetry. Received OTLP does
// NOT: it arrives as opaque bytes and scrub forwards them untouched, because
// rewriting protobuf in flight would corrupt it. That was harmless while the
// bytes stayed opaque. Decoding them into log bodies and attribute values
// inherited an obligation the wrapper cannot discharge, and this is the test
// that says so.
func TestDecodedOTLPContentIsRedacted(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"

	// A log body carrying a credential.
	rec := pbBytes(fieldLogBody, pbString(fieldAnyValueString, "connecting with password=hunter2"))
	rec = append(rec, pbBytes(fieldLogAttributes,
		append(pbString(fieldKeyValueKey, "aws.key"),
			pbBytes(fieldKeyValueValue, pbString(fieldAnyValueString, secret))...))...)
	body := pbBytes(fieldExportResourceLogs,
		pbBytes(fieldResourceLogsScope, pbBytes(fieldScopeLogsRecords, rec)))

	out, _ := encodeOTLPLogs(nil, []platform.TracePayload{{
		ContentType: "application/x-protobuf", Body: body, Signal: "logs",
	}}, time.Unix(0, 0))
	s := string(out)
	if strings.Contains(s, "hunter2") {
		t.Errorf("a password reached the envelope unredacted: %s", s)
	}
	if strings.Contains(s, secret) {
		t.Errorf("an AWS key in a log ATTRIBUTE reached the envelope unredacted: %s", s)
	}

	// A metric attribute carrying one.
	kv := append(pbString(fieldKeyValueKey, "token"),
		pbBytes(fieldKeyValueValue, pbString(fieldAnyValueString, secret))...)
	point := append(pbDouble(fieldNumberAsDouble, 1), pbBytes(fieldNumberAttributes, kv)...)
	metric := append(pbString(fieldMetricName, "calls"),
		pbBytes(fieldMetricGauge, pbBytes(fieldPointsGauge, point))...)
	mbody := pbBytes(fieldExportResourceMetrics,
		pbBytes(fieldResourceMetricsScope, pbBytes(fieldScopeMetricsMetrics, metric)))

	mout, _ := encodeOTLPMetrics(nil, []platform.TracePayload{{
		ContentType: "application/x-protobuf", Body: mbody, Signal: "metrics",
	}}, time.Unix(0, 0))
	if strings.Contains(string(mout), secret) {
		t.Errorf("an AWS key in a metric attribute reached the envelope unredacted: %s", mout)
	}
}

// TestADroppedPayloadIsLabelledWithItsOwnSignal. The batch is shared across
// signals, so a metrics flood can crowd out traces; counting that as a dropped
// TRACE sends an operator hunting a tracing problem that does not exist.
func TestADroppedPayloadIsLabelledWithItsOwnSignal(t *testing.T) {
	inner := newCountingTelemetry()
	e := New(inner, Config{Endpoint: "http://127.0.0.1:1", MaxBatch: 1})

	e.IngestTraces(platform.TracePayload{Body: []byte{1}, Signal: "traces"})
	e.IngestTraces(platform.TracePayload{Body: []byte{1}, Signal: "metrics"}) // over the cap

	got := inner.counts["agent.export.received_dropped|metrics"]
	if got != 1 {
		t.Errorf("dropped counter for metrics = %d, want 1 (counts=%v)", got, inner.counts)
	}
	if inner.counts["agent.export.received_dropped|traces"] != 0 {
		t.Error("the dropped metrics payload was counted against traces")
	}
}

// countingTelemetry records counter adds by name and signal attribute.
type countingTelemetry struct {
	platform.Telemetry
	counts map[string]int64
}

func newCountingTelemetry() *countingTelemetry {
	return &countingTelemetry{counts: map[string]int64{}}
}

func (c *countingTelemetry) Counter(name string) platform.Counter {
	return counterFunc{name: name, c: c}
}
func (c *countingTelemetry) Gauge(string) platform.Gauge         { return nopGauge{} }
func (c *countingTelemetry) Histogram(string) platform.Histogram { return nopHist{} }
func (c *countingTelemetry) Emit(platform.Event)                 {}
func (c *countingTelemetry) EmitLog(platform.LogRecord)          {}
func (c *countingTelemetry) IngestTraces(platform.TracePayload)  {}

type counterFunc struct {
	name string
	c    *countingTelemetry
}

func (f counterFunc) Add(n int64, attrs ...platform.Attr) {
	key := f.name
	for _, a := range attrs {
		if a.Key == "signal" {
			key += "|" + a.Value
		}
	}
	f.c.counts[key] += n
}

type nopGauge struct{}

func (nopGauge) Set(float64, ...platform.Attr) {}

type nopHist struct{}

func (nopHist) Observe(float64, ...platform.Attr) {}
