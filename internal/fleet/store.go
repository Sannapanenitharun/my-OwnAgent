// Package fleet keeps a bounded, in-memory view of every agent reporting to an
// intake, so one page can show a whole fleet rather than a single host.
//
// The store is deliberately lossy. An agent ships every series it collects, and
// a single real batch from one idle host already carries ~140 process.* series;
// a fleet of any size would exhaust memory if the intake kept everything. So
// each host holds the latest value for a capped number of series, short history
// for host.* only, and a ring of recent logs and spans. Anything past a cap is
// dropped rather than growing, and the stalest host is evicted once the host
// cap is reached.
package fleet

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits bound what one Store may retain. Zero values fall back to defaults.
type Limits struct {
	Hosts            int           // distinct hosts before the stalest is evicted
	SeriesPerHost    int           // latest-value series kept per host
	HistorySeries    int           // host.* series that also keep a sample ring
	HistoryPoints    int           // samples per history series
	LogsPerHost      int           // recent log lines kept per host
	SpansPerHost     int           // recent spans kept per host
	EntitiesPerHost  int           // discovered entities kept per host
	StaleAfter       time.Duration // silence before a host is reported stale
	SeriesStaleAfter time.Duration // silence before a series is treated as gone
}

func (l Limits) withDefaults() Limits {
	if l.Hosts <= 0 {
		l.Hosts = 512
	}
	if l.SeriesPerHost <= 0 {
		l.SeriesPerHost = 4096
	}
	// A series stops arriving when the thing it measured is gone. Nothing says
	// so explicitly -- the agent reports what exists, not what stopped -- so
	// the only evidence is silence, and the window is how long to wait before
	// believing it.
	//
	// It is sized against the metrics this is actually used on: process.* on a
	// 30s collection interval and host.filesystem.* on 60s, both re-exported
	// every export cycle. Five minutes is several missed collections for the
	// slowest of them, so a live series is never mistaken for a dead one,
	// while a program that exits leaves the view in minutes rather than
	// lingering for a quarter of an hour.
	if l.SeriesStaleAfter <= 0 {
		l.SeriesStaleAfter = 5 * time.Minute
	}
	if l.HistorySeries <= 0 {
		l.HistorySeries = 256
	}
	if l.HistoryPoints <= 0 {
		l.HistoryPoints = 120
	}
	if l.LogsPerHost <= 0 {
		l.LogsPerHost = 200
	}
	if l.SpansPerHost <= 0 {
		l.SpansPerHost = 100
	}
	if l.EntitiesPerHost <= 0 {
		l.EntitiesPerHost = 4096
	}
	if l.StaleAfter <= 0 {
		l.StaleAfter = 90 * time.Second
	}
	return l
}

// Store is safe for concurrent use by the intake's HTTP handlers.
type Store struct {
	mu     sync.Mutex
	hosts  map[string]*host
	limits Limits
	now    func() time.Time
}

// New returns an empty Store. A zero Limits uses the defaults.
func New(l Limits) *Store {
	return &Store{hosts: map[string]*host{}, limits: l.withDefaults(), now: time.Now}
}

type host struct {
	name      string
	hostID    string
	resource  map[string]string
	firstSeen time.Time
	lastSeen  time.Time

	batchLogs      int64
	batchMetrics   int64
	batchTraces    int64
	batchInventory int64
	dropped        int64

	series   map[string]*series
	entities map[string]*entity
	logs     *logRing
	spans    *spanRing
}

type series struct {
	name    string
	attrs   map[string]string
	value   float64
	updated time.Time
	history []Sample
}

// envelope mirrors the obsagent.v1 wire shape. The fleet store parses the body
// itself rather than borrowing the intake's type, so the two stay independent.
type envelope struct {
	Schema    string            `json:"schema"`
	Signal    string            `json:"signal"`
	Timestamp string            `json:"timestamp"`
	Host      string            `json:"host"`
	Resource  map[string]string `json:"resource"`
	Logs      []logJSON         `json:"logs"`
	Metrics   *metricsJSON      `json:"metrics"`
	Spans     []spanJSON        `json:"spans"`
	Events    []eventJSON       `json:"events"`
}

type logJSON struct {
	Timestamp  string            `json:"timestamp"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
	Source     string            `json:"source"`
	Attributes map[string]string `json:"attributes"`
}

type metricsJSON struct {
	Gauges   []metricJSON `json:"gauges"`
	Counters []metricJSON `json:"counters"`
}

type metricJSON struct {
	Name       string            `json:"name"`
	Value      float64           `json:"value"`
	Attributes map[string]string `json:"attributes"`
}

type eventJSON struct {
	Name       string            `json:"name"`
	Timestamp  string            `json:"timestamp"`
	Attributes map[string]string `json:"attributes"`
}

type spanJSON struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
}

// Ingest folds one received batch into the fleet view. A body that is not valid
// obsagent.v1 JSON is reported as an error; the intake still archives it, because
// the file on disk must not depend on this view being able to parse it.
func (s *Store) Ingest(signal string, body []byte) error {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	if env.Signal == "" {
		env.Signal = signal
	}

	now := s.now()
	ts := now
	if env.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, env.Timestamp); err == nil {
			ts = parsed
		}
	}

	name := strings.TrimSpace(env.Host)
	if name == "" {
		name = strings.TrimSpace(env.Resource["host.id"])
	}
	if name == "" {
		// Filing this under a shared name like "unknown" would MERGE every
		// agent that failed identity resolution into one row, silently mixing
		// the metrics of unrelated machines into a single incoherent host --
		// and the more agents are misconfigured, the more convincing the row
		// looks. Refusing is the honest answer. The caller still archives the
		// batch, so nothing is lost, and the reason is logged rather than
		// rendered as a fake host.
		return errors.New("batch has no host id: the agent could not resolve " +
			"one, so set OBSAGENT_HOST_ID or run it where instance metadata " +
			"is reachable")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	h := s.hosts[name]
	if h == nil {
		s.evictLocked()
		h = &host{
			name:      name,
			firstSeen: now,
			resource:  map[string]string{},
			series:    map[string]*series{},
			entities:  map[string]*entity{},
			logs:      newLogRing(s.limits.LogsPerHost),
			spans:     newSpanRing(s.limits.SpansPerHost),
		}
		s.hosts[name] = h
	}
	h.lastSeen = now
	for k, v := range env.Resource {
		h.resource[k] = v
	}
	if id := env.Resource["host.id"]; id != "" {
		h.hostID = id
	}

	switch env.Signal {
	case "logs":
		h.batchLogs++
		for _, rec := range env.Logs {
			lt := ts
			if rec.Timestamp != "" {
				if parsed, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil {
					lt = parsed
				}
			}
			h.logs.push(LogLine{
				Time:      lt,
				Status:    rec.Status,
				Source:    rec.Source,
				Message:   rec.Message,
				File:      rec.Attributes["file"],
				Container: rec.Attributes["container_id"],
				Stream:    rec.Attributes["stream"],
			})
		}
	case "traces":
		h.batchTraces++
		for _, sp := range env.Spans {
			h.spans.push(Span{
				TraceID: sp.TraceID,
				SpanID:  sp.SpanID,
				Name:    sp.Name,
				Status:  sp.Status,
				Time:    ts,
			})
		}
	case "inventory":
		h.batchInventory++
		s.ingestEventsLocked(h, env.Events)
	case "metrics":
		h.batchMetrics++
		if env.Metrics != nil {
			for _, m := range env.Metrics.Gauges {
				s.observeLocked(h, m, ts)
			}
			for _, m := range env.Metrics.Counters {
				s.observeLocked(h, m, ts)
			}
		}
	}
	return nil
}

// observeLocked records one metric point. The caller holds s.mu.
func (s *Store) observeLocked(h *host, m metricJSON, ts time.Time) {
	if m.Name == "" {
		return
	}
	key := seriesKey(m.Name, m.Attributes)
	ser := h.series[key]
	if ser == nil {
		if len(h.series) >= s.limits.SeriesPerHost {
			// Reclaim series nothing has reported in a long time first. A host
			// that churns through short-lived executables accumulates a dead
			// series per program, and without this the cap fills with things
			// that no longer exist and then rejects the ones that do.
			s.pruneSeriesLocked(h, ts)
		}
		// Still past the cap: drop the new series rather than evicting a live
		// one. Churn (a restarting process changing its pid attribute) would
		// otherwise evict the stable host.* series the UI depends on.
		if len(h.series) >= s.limits.SeriesPerHost {
			h.dropped++
			return
		}
		ser = &series{name: m.Name, attrs: copyAttrs(m.Attributes)}
		h.series[key] = ser
	}
	ser.value = m.Value
	ser.updated = ts

	// History feeds the charts, and only host.* is charted. Keeping it for
	// process.* would multiply memory by the process count.
	if !strings.HasPrefix(m.Name, "host.") {
		return
	}
	if len(ser.history) == 0 && s.historySeriesLocked(h) >= s.limits.HistorySeries {
		return
	}
	ser.history = append(ser.history, Sample{Time: ts, Value: m.Value})
	if over := len(ser.history) - s.limits.HistoryPoints; over > 0 {
		ser.history = append(ser.history[:0], ser.history[over:]...)
	}
}

func (s *Store) historySeriesLocked(h *host) int {
	n := 0
	for _, ser := range h.series {
		if len(ser.history) > 0 {
			n++
		}
	}
	return n
}

// evictLocked drops the least recently seen host once the cap is reached.
func (s *Store) evictLocked() {
	if len(s.hosts) < s.limits.Hosts {
		return
	}
	var oldest string
	var oldestAt time.Time
	for name, h := range s.hosts {
		if oldest == "" || h.lastSeen.Before(oldestAt) {
			oldest, oldestAt = name, h.lastSeen
		}
	}
	if oldest != "" {
		delete(s.hosts, oldest)
	}
}

func seriesKey(name string, attrs map[string]string) string {
	if len(attrs) == 0 {
		return name
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		// entity.id repeats the host on every series; it adds nothing to the
		// key and would only bloat it.
		if k == "entity.id" {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return name
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	for _, k := range keys {
		b.WriteByte(0x1f)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(attrs[k])
	}
	return b.String()
}

func copyAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "entity.id" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pruneSeriesLocked drops series nothing has reported within the staleness
// window. It runs only when the per-host cap is reached, so the common path
// pays nothing for it.
//
// A series that keeps its history ring is kept regardless: those are the
// host.* series the charts draw, they are few, and they are bounded
// separately. Losing one would put a hole in a chart to make room for a
// process that has already exited.
func (s *Store) pruneSeriesLocked(h *host, now time.Time) {
	cutoff := now.Add(-s.limits.SeriesStaleAfter)
	for key, ser := range h.series {
		if len(ser.history) > 0 {
			continue
		}
		if ser.updated.Before(cutoff) {
			delete(h.series, key)
		}
	}
}

// liveSeriesLocked reports whether a series has been reported recently enough
// to describe something that still exists. The view uses it so a program that
// exited stops being listed with the CPU and memory it last had.
func (s *Store) liveSeriesLocked(h *host, ser *series) bool {
	return !ser.updated.Before(h.lastSeen.Add(-s.limits.SeriesStaleAfter))
}
