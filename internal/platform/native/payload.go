package native

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

const payloadSchema = "obsagent.v1"

type envelope struct {
	Schema    string            `json:"schema"`
	Signal    string            `json:"signal"`
	Timestamp string            `json:"timestamp"`
	Host      string            `json:"host,omitempty"`
	Resource  map[string]string `json:"resource,omitempty"`
	Logs      []logJSON         `json:"logs,omitempty"`
	Metrics   *metricsJSON      `json:"metrics,omitempty"`
	Traces    []spanJSON        `json:"spans,omitempty"`
	Raw       []rawJSON         `json:"raw,omitempty"`
	Events    []eventJSON       `json:"events,omitempty"`
}

type logJSON struct {
	Timestamp  string            `json:"timestamp"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
	Source     string            `json:"source,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type metricsJSON struct {
	Gauges     []metricJSON `json:"gauges,omitempty"`
	Counters   []metricJSON `json:"counters,omitempty"`
	Histograms []histJSON   `json:"histograms,omitempty"`
}

type metricJSON struct {
	Name       string            `json:"name"`
	Value      float64           `json:"value"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type histJSON struct {
	Name       string            `json:"name"`
	Count      int64             `json:"count"`
	Sum        float64           `json:"sum"`
	Min        float64           `json:"min"`
	Max        float64           `json:"max"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type spanJSON struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_id,omitempty"`
	Name       string            `json:"name"`
	Kind       int               `json:"kind,omitempty"`
	StartNano  string            `json:"start_time_unix_nano,omitempty"`
	EndNano    string            `json:"end_time_unix_nano,omitempty"`
	Status     string            `json:"status,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// eventJSON carries a structured Event. Only discovery entity events are
// exported: they are what lets a central view reconstruct what runs on a host,
// which metrics alone cannot express.
type eventJSON struct {
	Name       string            `json:"name"`
	Severity   string            `json:"severity,omitempty"`
	Timestamp  string            `json:"timestamp"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type rawJSON struct {
	ContentType string `json:"content_type"`
	BodyBase64  string `json:"body_base64"`
}

func encodeLogs(resource []platform.Attr, recs []platform.LogRecord, now time.Time) []byte {
	logs := make([]logJSON, 0, len(recs))
	for _, rec := range recs {
		attrs := attrMap(rec.Attrs)
		src := attrs["source"]
		delete(attrs, "source")
		ts := rec.Timestamp
		if ts.IsZero() {
			ts = now
		}
		logs = append(logs, logJSON{
			Timestamp:  ts.UTC().Format(time.RFC3339Nano),
			Status:     rec.Severity.String(),
			Message:    rec.Body,
			Source:     src,
			Attributes: attrs,
		})
	}
	return mustJSON(envelope{
		Schema:    payloadSchema,
		Signal:    "logs",
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Host:      hostID(resource),
		Resource:  attrMap(resource),
		Logs:      logs,
	})
}

func encodeMetrics(resource []platform.Attr, gauges []platform.GaugePoint, counters []platform.CounterPoint, hist []platform.HistogramPoint, now time.Time) []byte {
	if len(gauges) == 0 && len(counters) == 0 && len(hist) == 0 {
		return nil
	}
	m := &metricsJSON{}
	for _, g := range gauges {
		m.Gauges = append(m.Gauges, metricJSON{Name: g.Name, Value: g.Value, Attributes: attrMap(g.Attrs)})
	}
	for _, c := range counters {
		m.Counters = append(m.Counters, metricJSON{Name: c.Name, Value: float64(c.Value), Attributes: attrMap(c.Attrs)})
	}
	for _, h := range hist {
		m.Histograms = append(m.Histograms, histJSON{
			Name: h.Name, Count: h.Count, Sum: h.Sum, Min: h.Min, Max: h.Max, Attributes: attrMap(h.Attrs),
		})
	}
	return mustJSON(envelope{
		Schema:    payloadSchema,
		Signal:    "metrics",
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Host:      hostID(resource),
		Resource:  attrMap(resource),
		Metrics:   m,
	})
}

func encodeTraces(resource []platform.Attr, payloads []platform.TracePayload, now time.Time) []byte {
	var spans []spanJSON
	var raw []rawJSON
	for _, p := range payloads {
		// Content-Type decides which decoder is tried first, but neither is
		// trusted to be right: an exporter that mislabels its body would
		// otherwise have every span silently shipped as opaque bytes. Trying
		// the other decoder on failure costs one parse of a body that was
		// going to be discarded anyway.
		if isJSON(p.ContentType, p.Body) {
			if parsed, ok := spansFromOTLPJSON(p.Body); ok && len(parsed) > 0 {
				spans = append(spans, parsed...)
				continue
			}
			if parsed, ok := spansFromOTLPProto(p.Body); ok && len(parsed) > 0 {
				spans = append(spans, parsed...)
				continue
			}
		} else {
			if parsed, ok := spansFromOTLPProto(p.Body); ok && len(parsed) > 0 {
				spans = append(spans, parsed...)
				continue
			}
			if parsed, ok := spansFromOTLPJSON(p.Body); ok && len(parsed) > 0 {
				spans = append(spans, parsed...)
				continue
			}
		}
		// Still undecoded: ship the bytes rather than drop them. Nothing
		// downstream reads them today, but the archive keeps the body so a
		// format this agent cannot parse is recoverable rather than lost.
		raw = append(raw, rawJSON{
			ContentType: p.ContentType,
			BodyBase64:  base64.StdEncoding.EncodeToString(p.Body),
		})
	}
	if len(spans) == 0 && len(raw) == 0 {
		return nil
	}
	return mustJSON(envelope{
		Schema:    payloadSchema,
		Signal:    "traces",
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Host:      hostID(resource),
		Resource:  attrMap(resource),
		Traces:    spans,
		Raw:       raw,
	})
}

func spansFromOTLPJSON(body []byte) ([]spanJSON, bool) {
	var top struct {
		ResourceSpans []struct {
			// The resource carries service.name. The protobuf decoder reads it,
			// so this must too: otherwise the same application reports its
			// service or not depending purely on which wire format it chose.
			Resource struct {
				Attributes []otlpKeyValue `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Spans []struct {
					TraceID           string         `json:"traceId"`
					SpanID            string         `json:"spanId"`
					ParentSpanID      string         `json:"parentSpanId"`
					Name              string         `json:"name"`
					Kind              int            `json:"kind"`
					StartTimeUnixNano string         `json:"startTimeUnixNano"`
					EndTimeUnixNano   string         `json:"endTimeUnixNano"`
					Attributes        []otlpKeyValue `json:"attributes"`
					Status            struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"status"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, false
	}
	var out []spanJSON
	for _, rs := range top.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				attrs := map[string]string{}
				for _, a := range sp.Attributes {
					if v := a.str(); v != "" {
						attrs[a.Key] = v
					}
				}
				// A span attribute wins over the resource's: it is the more
				// specific statement. Same precedence as the protobuf path.
				for _, a := range rs.Resource.Attributes {
					if _, taken := attrs[a.Key]; taken {
						continue
					}
					if v := a.str(); v != "" {
						attrs[a.Key] = v
					}
				}
				status := ""
				switch sp.Status.Code {
				case 1:
					status = "ok"
				case 2:
					status = "error"
				}
				if sp.Status.Message != "" {
					if status != "" {
						status += ": " + sp.Status.Message
					} else {
						status = sp.Status.Message
					}
				}
				out = append(out, spanJSON{
					TraceID:    sp.TraceID,
					SpanID:     sp.SpanID,
					ParentID:   sp.ParentSpanID,
					Name:       sp.Name,
					Kind:       sp.Kind,
					StartNano:  sp.StartTimeUnixNano,
					EndNano:    sp.EndTimeUnixNano,
					Status:     status,
					Attributes: attrs,
				})
			}
		}
	}
	return out, len(out) > 0
}

// otlpKeyValue is one OTLP attribute in proto3 JSON encoding. Both the span
// and the resource use it, and both need every scalar type: keeping only
// stringValue drops http.status_code and every duration, which are exactly the
// attributes worth filtering on.
type otlpKeyValue struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string `json:"stringValue"`
		BoolValue   *bool   `json:"boolValue"`
		// proto3 JSON encodes 64-bit integers as strings, so this is not a
		// number type by mistake.
		IntValue    *string  `json:"intValue"`
		DoubleValue *float64 `json:"doubleValue"`
	} `json:"value"`
}

func (kv otlpKeyValue) str() string {
	switch v := kv.Value; {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		return *v.IntValue
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	}
	return ""
}

func isJSON(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return true
	}
	s := strings.TrimSpace(string(body))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func hostID(resource []platform.Attr) string {
	for _, a := range resource {
		if a.Key == "host.id" {
			return a.Value
		}
	}
	return ""
}

func attrMap(attrs []platform.Attr) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		out[a.Key] = a.Value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mustJSON(v envelope) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// encodeInventory ships discovery entity events so a central view can
// reconstruct what runs on the host. Metrics cannot express this: a container
// or service is an identity, not a number, and the per-entity attributes are
// what the drill-down needs.
//
// The full retained set is sent each cycle rather than a delta. Entity events
// are keyed and idempotent on the receiving side, so a repeated send costs
// bandwidth but makes the view self-healing after a receiver restart or a
// dropped batch.
func encodeInventory(resource []platform.Attr, events []platform.Event, now time.Time) []byte {
	out := make([]eventJSON, 0, len(events))
	for _, ev := range events {
		// Entities AND relationships. An inventory of things with no edges
		// between them cannot answer the questions an operator actually has --
		// what is listening on that port, which container is that process in.
		// The topology was computed on every host, every cycle, and thrown
		// away here.
		if !strings.HasPrefix(ev.Name, "discovery.entity.") &&
			!strings.HasPrefix(ev.Name, "discovery.relationship.") {
			continue
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = now
		}
		out = append(out, eventJSON{
			Name:       ev.Name,
			Severity:   ev.Severity.String(),
			Timestamp:  ts.UTC().Format(time.RFC3339Nano),
			Attributes: attrMap(ev.Attrs),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return mustJSON(envelope{
		Schema:    payloadSchema,
		Signal:    "inventory",
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Host:      hostID(resource),
		Resource:  attrMap(resource),
		Events:    out,
	})
}
