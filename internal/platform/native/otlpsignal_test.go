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
