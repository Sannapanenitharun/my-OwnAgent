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

// SnapshotGauges returns current gauges if tel can snapshot them.
func SnapshotGauges(tel Telemetry) []GaugePoint {
	s, ok := tel.(GaugeSnapshotter)
	if !ok {
		return nil
	}
	return s.GaugeSnapshot()
}
