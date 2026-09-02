package native

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

// OTLP/protobuf log decoding.
//
// Same story as otlpmetrics.go: /v1/logs was served, accepted, counted, and
// then dropped by the exporter because the signal was not "traces".
//
// Unlike metrics, an OTLP log body does NOT alias onto a span -- LogRecord's
// field 1 is a fixed64 timestamp where Span.trace_id is bytes, so the wire
// types disagree and the span decoder rejects it. That is luck rather than
// design, and it made the failure quieter: log bodies fell through to the
// envelope's `raw` array as base64, which nothing reads.

// Field numbers from opentelemetry/proto/logs/v1/logs.proto and
// collector/logs/v1/logs_service.proto.
const (
	fieldExportResourceLogs = 1 // ExportLogsServiceRequest.resource_logs

	fieldResourceLogsResource = 1 // ResourceLogs.resource
	fieldResourceLogsScope    = 2 // ResourceLogs.scope_logs

	fieldScopeLogsRecords = 2 // ScopeLogs.log_records

	fieldLogTimeNano         = 1 // fixed64
	fieldLogSeverityNumber   = 2 // varint
	fieldLogSeverityText     = 3
	fieldLogBody             = 5 // AnyValue
	fieldLogAttributes       = 6
	fieldLogTraceID          = 9  // bytes
	fieldLogSpanID           = 10 // bytes
	fieldLogObservedTimeNano = 11 // fixed64
)

// maxProtoLogs bounds one request, as elsewhere.
const maxProtoLogs = 4096

// logsFromOTLPProto decodes an ExportLogsServiceRequest into the envelope's
// own log shape, so the intake and the fleet view render application logs
// through exactly the path host logs already use.
func logsFromOTLPProto(body []byte, now time.Time) ([]logJSON, bool) {
	var out []logJSON
	ok := walkProto(body, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldExportResourceLogs || wire != wireBytes {
			return true
		}
		return decodeResourceLogs(val, now, &out)
	})
	if !ok {
		return nil, false
	}
	return out, len(out) > 0
}

func decodeResourceLogs(b []byte, now time.Time, out *[]logJSON) bool {
	res := map[string]string{}
	ok := walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field == fieldResourceLogsResource && wire == wireBytes {
			return decodeResource(val, res)
		}
		return true
	})
	if !ok {
		return false
	}
	return walkProto(b, func(field, wire int, val []byte, _ uint64) bool {
		if field != fieldResourceLogsScope || wire != wireBytes {
			return true
		}
		return walkProto(val, func(f, w int, v []byte, _ uint64) bool {
			if f != fieldScopeLogsRecords || w != wireBytes {
				return true
			}
			if len(*out) >= maxProtoLogs {
				return true
			}
			rec, ok := decodeLogRecord(v, res, now)
			if !ok {
				return false
			}
			if rec.Message == "" {
				// A log line with no body is not a log line.
				return true
			}
			*out = append(*out, rec)
			return true
		})
	})
}

func decodeLogRecord(b []byte, res map[string]string, now time.Time) (logJSON, bool) {
	var (
		rec          logJSON
		attrs        map[string]string
		sevNum       uint64
		sevText      string
		timeNano     uint64
		observedNano uint64
	)

	ok := walkProto(b, func(field, wire int, val []byte, num uint64) bool {
		switch {
		case field == fieldLogTimeNano && wire == wireI64:
			timeNano = num
		case field == fieldLogObservedTimeNano && wire == wireI64:
			observedNano = num
		case field == fieldLogSeverityNumber && wire == wireVarint:
			sevNum = num
		case field == fieldLogSeverityText && wire == wireBytes:
			sevText = string(val)
		case field == fieldLogBody && wire == wireBytes:
			body, ok := decodeAnyValue(val)
			if !ok {
				return false
			}
			rec.Message = body
		case field == fieldLogAttributes && wire == wireBytes:
			if k, v, ok := decodeKeyValue(val); ok && k != "" && v != "" {
				if attrs == nil {
					attrs = map[string]string{}
				}
				attrs[k] = v
			}
		case field == fieldLogTraceID && wire == wireBytes:
			if id := hex.EncodeToString(val); !allZeroHex(id) {
				if attrs == nil {
					attrs = map[string]string{}
				}
				attrs["trace_id"] = id
			}
		case field == fieldLogSpanID && wire == wireBytes:
			if id := hex.EncodeToString(val); !allZeroHex(id) {
				if attrs == nil {
					attrs = map[string]string{}
				}
				attrs["span_id"] = id
			}
		}
		return true
	})
	if !ok {
		return logJSON{}, false
	}

	// An SDK that cannot stamp an emit time still stamps an observed time, and
	// a record with neither is dated on arrival rather than in 1970.
	ts := timeNano
	if ts == 0 {
		ts = observedNano
	}
	if ts != 0 {
		rec.Timestamp = time.Unix(0, int64(ts)).UTC().Format(time.RFC3339Nano)
	} else {
		rec.Timestamp = now.UTC().Format(time.RFC3339Nano)
	}

	rec.Status = severityFromOTLP(sevNum, sevText)
	rec.Source = res["service.name"]
	rec.Attributes = mergeResource(attrs, res)
	return rec, true
}

// severityFromOTLP maps an OTLP severity onto the four levels this agent
// carries. The number is authoritative when set, because severity_text is
// free-form and an SDK may write anything in it; the text is the fallback.
//
// OTLP defines 24 numbered levels in six bands of four. TRACE has no
// counterpart here and folds into debug, and FATAL folds into error -- both
// downward into the nearest level that exists rather than inventing one.
func severityFromOTLP(num uint64, text string) string {
	switch {
	case num >= 1 && num <= 8: // TRACE, DEBUG
		return "debug"
	case num >= 9 && num <= 12: // INFO
		return "info"
	case num >= 13 && num <= 16: // WARN
		return "warn"
	case num >= 17 && num <= 24: // ERROR, FATAL
		return "error"
	}
	return severityFromText(text)
}

func severityFromText(text string) string {
	switch lowerASCII(text) {
	case "trace", "debug":
		return "debug"
	case "info", "information", "notice":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error", "err", "fatal", "critical", "crit", "alert", "emerg", "emergency":
		return "error"
	}
	return "unknown"
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// allZeroHex reports whether an ID is the all-zero placeholder OTLP uses to
// mean "absent". Carrying it as a real ID would make every uncorrelated record
// appear to belong to one trace.
func allZeroHex(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// OTLP/JSON logs, for the same reason metricsFromOTLPJSON exists: an exporter
// set to http/json must not find a second silent hole.
func logsFromOTLPJSON(body []byte, now time.Time) ([]logJSON, bool) {
	var top struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpKeyValue `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					// proto3 JSON writes 64-bit integers as strings.
					TimeUnixNano         string         `json:"timeUnixNano"`
					ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
					SeverityNumber       int            `json:"severityNumber"`
					SeverityText         string         `json:"severityText"`
					Body                 otlpAnyJSON    `json:"body"`
					Attributes           []otlpKeyValue `json:"attributes"`
					TraceID              string         `json:"traceId"`
					SpanID               string         `json:"spanId"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, false
	}

	var out []logJSON
	for _, rl := range top.ResourceLogs {
		res := map[string]string{}
		for _, a := range rl.Resource.Attributes {
			if v := a.str(); a.Key != "" && v != "" {
				res[a.Key] = v
			}
		}
		for _, sl := range rl.ScopeLogs {
			for _, r := range sl.LogRecords {
				if len(out) >= maxProtoLogs {
					break
				}
				msg := r.Body.str()
				if msg == "" {
					continue
				}
				var attrs map[string]string
				for _, a := range r.Attributes {
					if v := a.str(); a.Key != "" && v != "" {
						if attrs == nil {
							attrs = map[string]string{}
						}
						attrs[a.Key] = v
					}
				}
				if !allZeroHex(r.TraceID) {
					if attrs == nil {
						attrs = map[string]string{}
					}
					attrs["trace_id"] = r.TraceID
				}
				if !allZeroHex(r.SpanID) {
					if attrs == nil {
						attrs = map[string]string{}
					}
					attrs["span_id"] = r.SpanID
				}
				ts := r.TimeUnixNano
				if ts == "" || ts == "0" {
					ts = r.ObservedTimeUnixNano
				}
				stamp := now.UTC().Format(time.RFC3339Nano)
				if n, err := strconv.ParseInt(ts, 10, 64); err == nil && n > 0 {
					stamp = time.Unix(0, n).UTC().Format(time.RFC3339Nano)
				}
				out = append(out, logJSON{
					Timestamp:  stamp,
					Status:     severityFromOTLP(uint64(r.SeverityNumber), r.SeverityText),
					Message:    msg,
					Source:     res["service.name"],
					Attributes: mergeResource(attrs, res),
				})
			}
		}
	}
	return out, len(out) > 0
}

// otlpAnyJSON is an AnyValue in proto3 JSON. It exists separately from
// otlpKeyValue's inner struct because a log body is an AnyValue with no key.
type otlpAnyJSON struct {
	StringValue *string  `json:"stringValue"`
	BoolValue   *bool    `json:"boolValue"`
	IntValue    *string  `json:"intValue"`
	DoubleValue *float64 `json:"doubleValue"`
}

func (a otlpAnyJSON) str() string {
	switch {
	case a.StringValue != nil:
		return *a.StringValue
	case a.IntValue != nil:
		return *a.IntValue
	case a.BoolValue != nil:
		return strconv.FormatBool(*a.BoolValue)
	case a.DoubleValue != nil:
		return strconv.FormatFloat(*a.DoubleValue, 'g', -1, 64)
	}
	return ""
}
