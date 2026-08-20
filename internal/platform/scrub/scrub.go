// Package scrub redacts credential-shaped substrings from telemetry bodies
// before they reach exporters. It is the Stage 6 secret-scrubber: a single
// Telemetry wrapper so every Emit / EmitLog path is scrubbed once, regardless
// of which module produced the record.
package scrub

import (
	"context"
	"regexp"
	"strings"

	"github.com/obsagent/observability-agent/internal/platform"
)

const redacted = "[REDACTED]"

var (
	reAWSKey = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	reBearer = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-+=/]{8,}`)
	reAssign = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+`)
)

// String replaces credential-shaped substrings in s.
func String(s string) string {
	s = reAWSKey.ReplaceAllString(s, redacted)
	s = reBearer.ReplaceAllString(s, "${1}"+redacted)
	s = reAssign.ReplaceAllStringFunc(s, func(m string) string {
		sep := "="
		eq, col := strings.IndexByte(m, '='), strings.IndexByte(m, ':')
		if col >= 0 && (eq < 0 || col < eq) {
			sep = ":"
		}
		i := strings.Index(m, sep)
		if i < 0 {
			return redacted
		}
		return m[:i+1] + redacted
	})
	return s
}

func scrubAttrs(in []platform.Attr) []platform.Attr {
	if len(in) == 0 {
		return in
	}
	out := make([]platform.Attr, len(in))
	for i, a := range in {
		out[i] = platform.A(a.Key, String(a.Value))
	}
	return out
}

// Telemetry wraps an inner Telemetry and scrubs string bodies on emit paths.
type Telemetry struct {
	Inner platform.Telemetry
}

// Wrap returns a scrubbing Telemetry. Nil inner is returned unchanged.
func Wrap(inner platform.Telemetry) platform.Telemetry {
	if inner == nil {
		return nil
	}
	return &Telemetry{Inner: inner}
}

func (t *Telemetry) Counter(name string) platform.Counter { return t.Inner.Counter(name) }
func (t *Telemetry) Gauge(name string) platform.Gauge     { return t.Inner.Gauge(name) }
func (t *Telemetry) Histogram(name string) platform.Histogram {
	return t.Inner.Histogram(name)
}

func (t *Telemetry) Emit(ev platform.Event) {
	ev.Name = String(ev.Name)
	ev.Attrs = scrubAttrs(ev.Attrs)
	t.Inner.Emit(ev)
}

func (t *Telemetry) EmitLog(rec platform.LogRecord) {
	rec.Body = String(rec.Body)
	rec.Attrs = scrubAttrs(rec.Attrs)
	t.Inner.EmitLog(rec)
}

func (t *Telemetry) IngestTraces(p platform.TracePayload) {
	// Opaque OTLP bytes — scrubbing would corrupt protobuf.
	t.Inner.IngestTraces(p)
}

func (t *Telemetry) GaugeSnapshot() []platform.GaugePoint {
	return platform.SnapshotGauges(t.Inner)
}

func (t *Telemetry) CounterSnapshot() []platform.CounterPoint {
	if s, ok := t.Inner.(platform.CounterSnapshotter); ok {
		return s.CounterSnapshot()
	}
	return nil
}

func (t *Telemetry) HistogramSnapshot() []platform.HistogramPoint {
	if s, ok := t.Inner.(platform.HistogramSnapshotter); ok {
		return s.HistogramSnapshot()
	}
	return nil
}

func (t *Telemetry) LogSnapshot() []platform.LogRecord {
	return platform.SnapshotLogs(t.Inner)
}

func (t *Telemetry) TraceSnapshot() []platform.TracePayload {
	return platform.SnapshotTraces(t.Inner)
}

func (t *Telemetry) EventSnapshot() []platform.Event {
	return platform.SnapshotEvents(t.Inner)
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	if s, ok := t.Inner.(platform.Shutdowner); ok {
		return s.Shutdown(ctx)
	}
	return nil
}

var (
	_ platform.Telemetry          = (*Telemetry)(nil)
	_ platform.Shutdowner         = (*Telemetry)(nil)
	_ platform.GaugeSnapshotter   = (*Telemetry)(nil)
	_ platform.CounterSnapshotter = (*Telemetry)(nil)
	_ platform.LogSnapshotter     = (*Telemetry)(nil)
	_ platform.TraceSnapshotter   = (*Telemetry)(nil)
	_ platform.EventSnapshotter   = (*Telemetry)(nil)
)
