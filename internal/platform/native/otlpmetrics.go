package native

import (
	"encoding/json"
	"math"
	"strconv"
)

// OTLP/protobuf metric decoding.
//
// The receiver has served /v1/metrics from the start, and until now the native
// exporter dropped every one of those payloads at the door: IngestTraces
// refused any signal that was not "traces" and returned, with no counter and no
// diagnostic. An application pointed at the receiver got 200 OK, the receiver's
// own accepted counter went up, and the metrics never left the host. Silence in
// both directions is the worst possible answer -- an operator checking either
// end sees a healthy pipeline.
//
// The shape below mirrors otlpproto.go deliberately: same walker, same
// key/value decoding, same forward-compatible "skip unknown fields by wire
// type" behaviour. What differs is only the field map.
//
// WHAT IS DECODED. Gauges and sums, which is what essentially all
// infrastructure telemetry is, plus histograms reduced to count/sum/min/max
// because that is what the envelope carries. Exponential histograms and
// summaries are counted as unsupported rather than approximated: inventing
// bucket boundaries would produce a number that looks authoritative and is not.

// Field numbers from opentelemetry/proto/metrics/v1/metrics.proto and
// collector/metrics/v1/metrics_service.proto.
const (
	fieldExportResourceMetrics = 1 // ExportMetricsServiceRequest.resource_metrics

	fieldResourceMetricsResource = 1 // ResourceMetrics.resource
	fieldResourceMetricsScope    = 2 // ResourceMetrics.scope_metrics

	fieldScopeMetricsMetrics = 2 // ScopeMetrics.metrics

	fieldMetricName      = 1
	fieldMetricGauge     = 5
	fieldMetricSum       = 7
	fieldMetricHistogram = 9
	// 10 (exponential_histogram) and 11 (summary) are recognised only so they
	// can be reported as unsupported instead of vanishing.
	fieldMetricExpHistogram = 10
	fieldMetricSummary      = 11

	fieldPointsGauge     = 1 // Gauge.data_points
	fieldPointsSum       = 1 // Sum.data_points
	fieldPointsHistogram = 1 // Histogram.data_points
	fieldSumIsMonotonic  = 3 // Sum.is_monotonic

	// NumberDataPoint. Field 1 is reserved, which is why attributes sit at 7.
	fieldNumberAsDouble   = 4 // double
	fieldNumberAsInt      = 6 // sfixed64
	fieldNumberAttributes = 7

	// HistogramDataPoint. Field 1 is reserved here too.
	fieldHistCount      = 4 // fixed64
	fieldHistSum        = 5 // double
	fieldHistAttributes = 9
	fieldHistMin        = 11 // double
	fieldHistMax        = 12 // double
)

// maxProtoPoints bounds one request, for the same reason maxProtoSpans does.
const maxProtoPoints = 4096

// otlpMetrics is a decoded batch, already in the envelope's shape so nothing
// downstream needs to learn a second representation.
type otlpMetrics struct {
	Gauges     []metricJSON
	Counters   []metricJSON
	Histograms []histJSON
	// Unsupported counts metrics whose type this does not render. Reported
	// rather than silently skipped, because "we dropped 12 summaries" is a
	// fact an operator can act on and an absence is not.
	Unsupported int
}

func (m otlpMetrics) points() int {
	return len(m.Gauges) + len(m.Counters) + len(m.Histograms)
}

// metricsFromOTLPProto decodes an ExportMetricsServiceRequest. The second
// result reports whether the body parsed as protobuf at all, so a caller can
// tell "not this wire format" from "no metrics in it".
func metricsFromOTLPProto(body []byte) (otlpMetrics, bool) {
	var out otlpMetrics
	ok := walkProto(body, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldExportResourceMetrics || wire != wireBytes {
			return true
		}
		return decodeResourceMetrics(val, &out)
	})
	if !ok {
		return otlpMetrics{}, false
	}
	return out, out.points() > 0 || out.Unsupported > 0
}

func decodeResourceMetrics(b []byte, out *otlpMetrics) bool {
	// service.name lives here, and without it a metric row says which host it
	// came from but not which application -- the same gap that made anonymous
	// spans useless.
	res := map[string]string{}
	ok := walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field == fieldResourceMetricsResource && wire == wireBytes {
			return decodeResource(val, res)
		}
		return true
	})
	if !ok {
		return false
	}
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldResourceMetricsScope || wire != wireBytes {
			return true
		}
		return walkProto(val, func(f, w int, v []byte, _ uint64) bool {
			if f != fieldScopeMetricsMetrics || w != wireBytes {
				return true
			}
			return decodeMetric(v, res, out)
		})
	})
}

func decodeMetric(b []byte, res map[string]string, out *otlpMetrics) bool {
	name := ""
	// The name arrives before the data in every encoder in practice, but the
	// proto does not promise ordering, so the body is walked twice rather than
	// trusting it.
	if !walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field == fieldMetricName && wire == wireBytes {
			name = string(val)
		}
		return true
	}) {
		return false
	}
	if name == "" {
		// A metric with no name cannot be charted, joined, or alerted on.
		return true
	}

	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		switch {
		case field == fieldMetricGauge && wire == wireBytes:
			return decodeNumberPoints(val, fieldPointsGauge, name, res, &out.Gauges, out)

		case field == fieldMetricSum && wire == wireBytes:
			// A monotonic sum is a counter. A non-monotonic one is a value
			// that goes up and down -- a queue depth, a pool size -- and
			// charting it as a counter would show it decreasing, which no
			// counter does.
			monotonic := false
			if !walkProto(val, func(f, w int, _ []byte, n uint64) bool {
				if f == fieldSumIsMonotonic && w == wireVarint {
					monotonic = n != 0
				}
				return true
			}) {
				return false
			}
			into := &out.Gauges
			if monotonic {
				into = &out.Counters
			}
			return decodeNumberPoints(val, fieldPointsSum, name, res, into, out)

		case field == fieldMetricHistogram && wire == wireBytes:
			return decodeHistogramPoints(val, name, res, out)

		case (field == fieldMetricExpHistogram || field == fieldMetricSummary) && wire == wireBytes:
			out.Unsupported++
		}
		return true
	})
}

func decodeNumberPoints(b []byte, pointField int, name string, res map[string]string, into *[]metricJSON, out *otlpMetrics) bool {
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != pointField || wire != wireBytes {
			return true
		}
		if out.points() >= maxProtoPoints {
			return true
		}
		var (
			value float64
			seen  bool
			attrs map[string]string
		)
		ok := walkProto(val, func(f, w int, v []byte, n uint64) bool {
			switch {
			case f == fieldNumberAsDouble && w == wireI64:
				value, seen = math.Float64frombits(n), true
			case f == fieldNumberAsInt && w == wireI64:
				// sfixed64: the bits are a signed two's-complement integer.
				value, seen = float64(int64(n)), true
			case f == fieldNumberAttributes && w == wireBytes:
				// Skipped rather than fatal, as in decodeResource: one bad
				// attribute must not discard an otherwise good batch.
				if k, val, ok := decodeKeyValue(v); ok && k != "" && val != "" {
					if attrs == nil {
						attrs = map[string]string{}
					}
					attrs[k] = val
				}
			}
			return true
		})
		if !ok {
			return false
		}
		if !seen {
			// No value of either type: not a data point, whatever else parsed.
			return true
		}
		*into = append(*into, metricJSON{Name: name, Value: value, Attributes: mergeResource(attrs, res)})
		return true
	})
}

func decodeHistogramPoints(b []byte, name string, res map[string]string, out *otlpMetrics) bool {
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldPointsHistogram || wire != wireBytes {
			return true
		}
		if out.points() >= maxProtoPoints {
			return true
		}
		h := histJSON{Name: name}
		var attrs map[string]string
		ok := walkProto(val, func(f, w int, v []byte, n uint64) bool {
			switch {
			case f == fieldHistCount && w == wireI64:
				h.Count = int64(n)
			case f == fieldHistSum && w == wireI64:
				h.Sum = math.Float64frombits(n)
			case f == fieldHistMin && w == wireI64:
				h.Min = math.Float64frombits(n)
			case f == fieldHistMax && w == wireI64:
				h.Max = math.Float64frombits(n)
			case f == fieldHistAttributes && w == wireBytes:
				if k, val, ok := decodeKeyValue(v); ok && k != "" && val != "" {
					if attrs == nil {
						attrs = map[string]string{}
					}
					attrs[k] = val
				}
			}
			return true
		})
		if !ok {
			return false
		}
		h.Attributes = mergeResource(attrs, res)
		out.Histograms = append(out.Histograms, h)
		return true
	})
}

// mergeResource folds resource attributes into a point's own, letting the
// point win. The point is the more specific statement, exactly as a span
// attribute outranks its resource.
func mergeResource(attrs, res map[string]string) map[string]string {
	if len(res) == 0 {
		return attrs
	}
	if attrs == nil {
		attrs = make(map[string]string, len(res))
	}
	for k, v := range res {
		if _, taken := attrs[k]; !taken {
			attrs[k] = v
		}
	}
	return attrs
}

// OTLP/JSON metrics. Protobuf is the default wire format and the one that was
// silently dropped, but an exporter configured with
// OTEL_EXPORTER_OTLP_PROTOCOL=http/json must not hit a second silent hole.
func metricsFromOTLPJSON(body []byte) (otlpMetrics, bool) {
	type numberPoint struct {
		Attributes []otlpKeyValue `json:"attributes"`
		// proto3 JSON writes 64-bit integers as strings and doubles as
		// numbers, so the two value forms cannot share one field.
		AsDouble *float64 `json:"asDouble"`
		AsInt    *string  `json:"asInt"`
	}
	type histPoint struct {
		Attributes []otlpKeyValue `json:"attributes"`
		Count      *string        `json:"count"`
		Sum        *float64       `json:"sum"`
		Min        *float64       `json:"min"`
		Max        *float64       `json:"max"`
	}
	var top struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpKeyValue `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name  string `json:"name"`
					Gauge *struct {
						DataPoints []numberPoint `json:"dataPoints"`
					} `json:"gauge"`
					Sum *struct {
						IsMonotonic bool          `json:"isMonotonic"`
						DataPoints  []numberPoint `json:"dataPoints"`
					} `json:"sum"`
					Histogram *struct {
						DataPoints []histPoint `json:"dataPoints"`
					} `json:"histogram"`
					ExponentialHistogram *json.RawMessage `json:"exponentialHistogram"`
					Summary              *json.RawMessage `json:"summary"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return otlpMetrics{}, false
	}

	var out otlpMetrics
	pointAttrs := func(kvs []otlpKeyValue, res map[string]string) map[string]string {
		var attrs map[string]string
		for _, a := range kvs {
			if v := a.str(); a.Key != "" && v != "" {
				if attrs == nil {
					attrs = map[string]string{}
				}
				attrs[a.Key] = v
			}
		}
		return mergeResource(attrs, res)
	}

	for _, rm := range top.ResourceMetrics {
		res := map[string]string{}
		for _, a := range rm.Resource.Attributes {
			if v := a.str(); a.Key != "" && v != "" {
				res[a.Key] = v
			}
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name == "" {
					continue
				}
				if m.ExponentialHistogram != nil || m.Summary != nil {
					out.Unsupported++
				}
				appendNumbers := func(pts []numberPoint, into *[]metricJSON) {
					for _, p := range pts {
						if out.points() >= maxProtoPoints {
							return
						}
						var value float64
						switch {
						case p.AsDouble != nil:
							value = *p.AsDouble
						case p.AsInt != nil:
							n, err := strconv.ParseInt(*p.AsInt, 10, 64)
							if err != nil {
								continue
							}
							value = float64(n)
						default:
							continue
						}
						*into = append(*into, metricJSON{
							Name:       m.Name,
							Value:      value,
							Attributes: pointAttrs(p.Attributes, res),
						})
					}
				}
				if m.Gauge != nil {
					appendNumbers(m.Gauge.DataPoints, &out.Gauges)
				}
				if m.Sum != nil {
					into := &out.Gauges
					if m.Sum.IsMonotonic {
						into = &out.Counters
					}
					appendNumbers(m.Sum.DataPoints, into)
				}
				if m.Histogram != nil {
					for _, p := range m.Histogram.DataPoints {
						if out.points() >= maxProtoPoints {
							break
						}
						h := histJSON{Name: m.Name, Attributes: pointAttrs(p.Attributes, res)}
						if p.Count != nil {
							if n, err := strconv.ParseInt(*p.Count, 10, 64); err == nil {
								h.Count = n
							}
						}
						if p.Sum != nil {
							h.Sum = *p.Sum
						}
						if p.Min != nil {
							h.Min = *p.Min
						}
						if p.Max != nil {
							h.Max = *p.Max
						}
						out.Histograms = append(out.Histograms, h)
					}
				}
			}
		}
	}
	return out, out.points() > 0 || out.Unsupported > 0
}
