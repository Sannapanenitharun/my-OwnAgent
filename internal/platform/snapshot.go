package platform

// GaugePoint is one labelled gauge observation at a moment in time.
type GaugePoint struct {
	Name  string
	Value float64
	Attrs []Attr
}

// CounterPoint is one labelled counter observation at a moment in time.
type CounterPoint struct {
	Name  string
	Value int64
	Attrs []Attr
}

// HistogramPoint is one labelled histogram summary at a moment in time.
type HistogramPoint struct {
	Name  string
	Count int64
	Sum   float64
	Min   float64
	Max   float64
	Attrs []Attr
}

// GaugeSnapshotter is an optional Telemetry capability for the local status UI.
// Adapters that do not implement it yield an empty metric list.
type GaugeSnapshotter interface {
	GaugeSnapshot() []GaugePoint
}

// CounterSnapshotter is an optional Telemetry capability used by the OTLP
// exporter to flush counters without coupling to a specific adapter.
type CounterSnapshotter interface {
	CounterSnapshot() []CounterPoint
}

// HistogramSnapshotter is an optional Telemetry capability used by the OTLP
// exporter to flush histogram summaries.
type HistogramSnapshotter interface {
	HistogramSnapshot() []HistogramPoint
}

// SnapshotCounters returns current counters if tel can snapshot them.
func SnapshotCounters(tel Telemetry) []CounterPoint {
	s, ok := tel.(CounterSnapshotter)
	if !ok {
		return nil
	}
	return s.CounterSnapshot()
}

// SnapshotGauges returns current gauges if tel can snapshot them.
func SnapshotGauges(tel Telemetry) []GaugePoint {
	s, ok := tel.(GaugeSnapshotter)
	if !ok {
		return nil
	}
	return s.GaugeSnapshot()
}

// LogSnapshotter is an optional Telemetry capability for the local UI to show
// recent log records without draining the exporter queues.
type LogSnapshotter interface {
	LogSnapshot() []LogRecord
}

// TraceSnapshotter is an optional Telemetry capability for the local UI to show
// recent ingested trace payloads without draining exporter queues.
type TraceSnapshotter interface {
	TraceSnapshot() []TracePayload
}

// SnapshotLogs returns retained logs if tel can snapshot them.
func SnapshotLogs(tel Telemetry) []LogRecord {
	s, ok := tel.(LogSnapshotter)
	if !ok {
		return nil
	}
	return s.LogSnapshot()
}

// SnapshotTraces returns retained traces if tel can snapshot them.
func SnapshotTraces(tel Telemetry) []TracePayload {
	s, ok := tel.(TraceSnapshotter)
	if !ok {
		return nil
	}
	return s.TraceSnapshot()
}

// EventSnapshotter is an optional Telemetry capability for the local UI to show
// recent discovery/process events without draining exporter queues.
type EventSnapshotter interface {
	EventSnapshot() []Event
}

// SnapshotEvents returns retained events if tel can snapshot them.
func SnapshotEvents(tel Telemetry) []Event {
	s, ok := tel.(EventSnapshotter)
	if !ok {
		return nil
	}
	return s.EventSnapshot()
}

// SeriesRetirer is an optional Telemetry capability for withdrawing a gauge
// series whose subject no longer exists.
//
// A gauge is a LATEST VALUE, and a store of latest values has no way to learn
// that a program exited: the module simply stops setting it, and the last
// reading sits there being re-exported forever. That is wrong twice over. The
// value is a lie -- an executable that died at noon still reporting the memory
// it held at noon -- and the series is a leak, because an unbounded label like
// an executable name accumulates one dead series per program the host ever ran
// until the cardinality cap is full of things that no longer exist and starts
// refusing the ones that do.
//
// This is deliberately NOT a way to hide a zero. A metric that reaches zero
// must keep reporting zero, or nobody can alert on it; see the process module's
// emitAggregate, which emits zero counts on purpose. Retiring is for a series
// whose SUBJECT is gone, where there is no value to report because there is no
// longer anything to measure.
type SeriesRetirer interface {
	RetireSeries(name string, attrs ...Attr)
}

// RetireSeries withdraws a series if tel supports it, and is a no-op otherwise.
// A caller must treat retirement as best-effort: an adapter that cannot forget
// a series is not broken, it is just less tidy.
func RetireSeries(tel Telemetry, name string, attrs ...Attr) {
	if r, ok := tel.(SeriesRetirer); ok {
		r.RetireSeries(name, attrs...)
	}
}
