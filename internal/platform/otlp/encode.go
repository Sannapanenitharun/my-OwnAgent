package otlp

import (
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// OTLP protobuf field numbers. These match opentelemetry-proto and must not
// drift; a wrong number produces a payload a collector silently drops.

const (
	// common.v1.KeyValue
	fKVKey   = 1
	fKVValue = 2
	// common.v1.AnyValue
	fAnyString = 1
	// common.v1.InstrumentationScope
	fScopeName    = 1
	fScopeVersion = 2
	// resource.v1.Resource
	fResourceAttrs = 1
	// metrics ExportMetricsServiceRequest / ResourceMetrics / ScopeMetrics / Metric
	fMetricsResourceMetrics = 1
	fRMResource             = 1
	fRMScopeMetrics         = 2
	fSMScope                = 1
	fSMMetrics              = 2
	fMetricName             = 1
	fMetricGauge            = 5
	fMetricSum              = 7
	fMetricHistogram        = 9
	fGaugeDataPoints        = 1
	fSumDataPoints          = 1
	fSumTemporality         = 2
	fSumIsMonotonic         = 3
	fHistDataPoints         = 1
	fHistTemporality        = 2
	// NumberDataPoint
	fNDPStart  = 2
	fNDPTime   = 3
	fNDPDouble = 4
	fNDPInt    = 6
	fNDPAttrs  = 7
	// HistogramDataPoint
	fHDPStart = 2
	fHDPTime  = 3
	fHDPCount = 4
	fHDPSum   = 5
	fHDPAttrs = 9
	fHDPMin   = 11
	fHDPMax   = 12

	aggregationCumulative = 2

	// logs
	fLogsResourceLogs = 1
	fRLResource       = 1
	fRLScopeLogs      = 2
	fSLScope          = 1
	fSLRecords        = 2
	fLRTime           = 1
	fLRSeverityNumber = 2
	fLRSeverityText   = 3
	fLRBody           = 5
	fLRAttrs          = 6

	severityDebug = 5
	severityInfo  = 9
	severityWarn  = 13
	severityError = 17

	// traces
	fTracesResourceSpans = 1
	fRSResource          = 1
	fRSScopeSpans        = 2
	fSSScope             = 1
	fSSSpans             = 2
)

func encodeKeyValue(key, value string) []byte {
	var b []byte
	b = appendTagString(b, fKVKey, key)
	var any []byte
	any = appendTagString(any, fAnyString, value)
	return appendTagMessage(b, fKVValue, any)
}

func encodeResource(attrs []platform.Attr) []byte {
	var b []byte
	for _, a := range attrs {
		if a.Key == "" || a.Value == "" {
			continue
		}
		b = appendTagMessage(b, fResourceAttrs, encodeKeyValue(a.Key, a.Value))
	}
	return b
}

func encodeScope(name, version string) []byte {
	var b []byte
	b = appendTagString(b, fScopeName, name)
	b = appendTagString(b, fScopeVersion, version)
	return b
}

func encodeAttrList(field int, attrs []platform.Attr) []byte {
	var b []byte
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		b = appendTagMessage(b, field, encodeKeyValue(a.Key, a.Value))
	}
	return b
}

func unixNano(t time.Time) uint64 {
	if t.IsZero() {
		t = time.Now()
	}
	n := t.UnixNano()
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func encodeMetricsRequest(res []platform.Attr, gauges []platform.GaugePoint, counters []platform.CounterPoint, hist []platform.HistogramPoint, now time.Time) []byte {
	ts := unixNano(now)
	var metrics []byte
	for _, g := range gauges {
		var dp []byte
		dp = appendTagFixed64(dp, fNDPTime, ts)
		dp = appendTagDouble(dp, fNDPDouble, g.Value)
		dp = append(dp, encodeAttrList(fNDPAttrs, g.Attrs)...)
		var gauge []byte
		gauge = appendTagMessage(gauge, fGaugeDataPoints, dp)
		var m []byte
		m = appendTagString(m, fMetricName, g.Name)
		m = appendTagMessage(m, fMetricGauge, gauge)
		metrics = appendTagMessage(metrics, fSMMetrics, m)
	}
	for _, c := range counters {
		var dp []byte
		dp = appendTagFixed64(dp, fNDPTime, ts)
		dp = appendTagSFixed64(dp, fNDPInt, c.Value)
		dp = append(dp, encodeAttrList(fNDPAttrs, c.Attrs)...)
		var sum []byte
		sum = appendTagMessage(sum, fSumDataPoints, dp)
		sum = appendTagUvarint(sum, fSumTemporality, aggregationCumulative)
		sum = appendTagBool(sum, fSumIsMonotonic, true)
		var m []byte
		m = appendTagString(m, fMetricName, c.Name)
		m = appendTagMessage(m, fMetricSum, sum)
		metrics = appendTagMessage(metrics, fSMMetrics, m)
	}
	for _, h := range hist {
		var dp []byte
		dp = appendTagFixed64(dp, fHDPTime, ts)
		dp = appendTagUvarint(dp, fHDPCount, uint64(h.Count))
		dp = appendTagDouble(dp, fHDPSum, h.Sum)
		dp = append(dp, encodeAttrList(fHDPAttrs, h.Attrs)...)
		dp = appendTagDouble(dp, fHDPMin, h.Min)
		dp = appendTagDouble(dp, fHDPMax, h.Max)
		var histMsg []byte
		histMsg = appendTagMessage(histMsg, fHistDataPoints, dp)
		histMsg = appendTagUvarint(histMsg, fHistTemporality, aggregationCumulative)
		var m []byte
		m = appendTagString(m, fMetricName, h.Name)
		m = appendTagMessage(m, fMetricHistogram, histMsg)
		metrics = appendTagMessage(metrics, fSMMetrics, m)
	}
	if len(metrics) == 0 {
		return nil
	}
	var sm []byte
	sm = appendTagMessage(sm, fSMScope, encodeScope("observability-agent", "1.0.0"))
	sm = append(sm, metrics...)
	var rm []byte
	rm = appendTagMessage(rm, fRMResource, encodeResource(res))
	rm = appendTagMessage(rm, fRMScopeMetrics, sm)
	var req []byte
	return appendTagMessage(req, fMetricsResourceMetrics, rm)
}

func encodeLogsRequest(res []platform.Attr, recs []platform.LogRecord) []byte {
	if len(recs) == 0 {
		return nil
	}
	var records []byte
	for _, r := range recs {
		var lr []byte
		lr = appendTagFixed64(lr, fLRTime, unixNano(r.Timestamp))
		sev, text := severityOTLP(r.Severity)
		lr = appendTagUvarint(lr, fLRSeverityNumber, uint64(sev))
		lr = appendTagString(lr, fLRSeverityText, text)
		var body []byte
		body = appendTagString(body, fAnyString, r.Body)
		lr = appendTagMessage(lr, fLRBody, body)
		lr = append(lr, encodeAttrList(fLRAttrs, r.Attrs)...)
		records = appendTagMessage(records, fSLRecords, lr)
	}
	var sl []byte
	sl = appendTagMessage(sl, fSLScope, encodeScope("observability-agent", "1.0.0"))
	sl = append(sl, records...)
	var rl []byte
	rl = appendTagMessage(rl, fRLResource, encodeResource(res))
	rl = appendTagMessage(rl, fRLScopeLogs, sl)
	var req []byte
	return appendTagMessage(req, fLogsResourceLogs, rl)
}

func severityOTLP(s platform.EventSeverity) (int, string) {
	switch s {
	case platform.SeverityDebug:
		return severityDebug, "DEBUG"
	case platform.SeverityWarn:
		return severityWarn, "WARN"
	case platform.SeverityError:
		return severityError, "ERROR"
	default:
		return severityInfo, "INFO"
	}
}

func encodePassthroughTraces(res []platform.Attr, payloads []platform.TracePayload) []byte {
	// Each payload is already an ExportTraceServiceRequest (protobuf) or JSON
	// converted to protobuf. We wrap protobuf payloads by injecting resource
	// attributes; JSON is converted first.
	var combined []byte
	for _, p := range payloads {
		body := p.Body
		if isJSON(p.ContentType, body) {
			if converted, err := tracesJSONToProto(body); err == nil {
				body = converted
			}
		}
		combined = append(combined, injectResourceSpans(body, res)...)
	}
	return combined
}

func isJSON(contentType string, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	ct := contentType
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	switch ct {
	case "application/json", "application/json; charset=utf-8":
		return true
	}
	return body[0] == '{' || body[0] == '['
}
