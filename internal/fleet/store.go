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
	Hosts              int           // distinct hosts before the stalest is evicted
	SeriesPerHost      int           // latest-value series kept per host
	HistorySeries      int           // core (host.*, container gauge) series that keep a sample ring
	HistorySeriesExtra int           // application/other series that keep a sample ring
	HistoryPoints      int           // samples per history series
	LogsPerHost        int           // recent log lines kept per host
	SpansPerHost       int           // recent spans kept per host
	EntitiesPerHost    int           // discovered entities kept per host
	RelationsPerHost   int           // topology edges kept per host
	StaleAfter         time.Duration // silence before a host is reported stale
	SeriesStaleAfter   time.Duration // silence before a series is treated as gone
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
	// A SECOND, separate budget rather than a bigger shared one.
	//
	// Application metric names and label sets are unbounded -- that is the
	// difference between them and host.*, where the agent decides what exists.
	// One service emitting a route label per URL can produce thousands of
	// series in a burst. Sharing a budget would let that burst take the slots
	// the overview charts depend on, and "the CPU chart went blank because a
	// service got chatty" is a bad trade at any size.
	//
	// Two counters make that structurally impossible instead of a matter of
	// tuning. The arithmetic: a ring is HistoryPoints x sizeof(Sample), about
	// 3.8 KB at the defaults, so this doubles the worst case per host from
	// roughly 1 MB to 2 MB.
	if l.HistorySeriesExtra <= 0 {
		l.HistorySeriesExtra = 256
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
	// Edges outnumber nodes: a host with 400 entities had 477 relationships,
	// most of them parent_process. Bounded separately so a dense process tree
	// cannot crowd out the entities its edges refer to.
	if l.RelationsPerHost <= 0 {
		l.RelationsPerHost = 8192
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

	series map[string]*series
	// historySeries counts series holding a sample ring. Maintained rather
	// than counted on demand: the check runs on every observation of an
	// uncharted series, and scanning all of them there is quadratic in the
	// series count on a host with many containers.
	historySeries int
	// historyExtra counts rings held by non-core series, against its own cap.
	historyExtra int
	entities     map[string]*entity
	relations    map[string]*relation
	logs         *logRing
	spans        *spanRing
}

type series struct {
	name    string
	attrs   map[string]string
	value   float64
	updated time.Time
	history []Sample
	// seen counts observations. It exists to answer one question about
	// non-core series -- has this one ever reported twice? -- which is the
	// cheapest available test for "worth drawing"; see observeLocked.
	seen int
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
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Attributes map[string]string `json:"attributes"`
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
			relations: map[string]*relation{},
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
				TraceID:   rec.Attributes["trace_id"],
				SpanID:    rec.Attributes["span_id"],
			})
		}
	case "traces":
		h.batchTraces++
		for _, sp := range env.Spans {
			h.spans.push(Span{
				TraceID: sp.TraceID,
				SpanID:  sp.SpanID,
				Name:    sp.Name,
				Service: spanService(sp.Attributes),
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

	ser.seen++

	// History feeds the charts. Which budget a series draws on depends on
	// what kind of series it is; see chartClassOf.
	switch chartClassOf(m.Name) {
	case chartNone:
		return

	case chartCore:
		if len(ser.history) == 0 {
			if h.historySeries >= s.limits.HistorySeries {
				return
			}
			h.historySeries++
		}

	case chartExtra:
		if len(ser.history) == 0 {
			// A series must report TWICE before it earns a ring.
			//
			// This is the cardinality guard, and it is aimed at one specific
			// failure: a label that is unique per request -- an order ID in a
			// route, a request ID, a trace ID that leaked into an attribute.
			// Those series are each seen exactly once, so first-come budgeting
			// would let a single burst take every slot and hold it until the
			// staleness sweep, starving the recurring series that are actually
			// worth drawing.
			//
			// A series that has reported twice is, by the only evidence
			// available here, recurring. It costs one sample of delay before a
			// chart starts, which is invisible next to a 120-point ring.
			if ser.seen < 2 {
				return
			}
			if h.historyExtra >= s.limits.HistorySeriesExtra {
				return
			}
			h.historyExtra++
		}
	}
	ser.history = append(ser.history, Sample{Time: ts, Value: m.Value})
	if over := len(ser.history) - s.limits.HistoryPoints; over > 0 {
		ser.history = append(ser.history[:0], ser.history[over:]...)
	}
}

// chartClass says which history budget a series draws on, if any.
type chartClass int

const (
	// chartNone earns no sample ring.
	chartNone chartClass = iota
	// chartCore is the fixed set the overview draws: host.* and the two
	// container instance gauges. Reserved budget, charted from first sight,
	// never reclaimed while it keeps reporting.
	chartCore
	// chartExtra is everything else worth drawing -- application metrics
	// received over OTLP, and the agent's own httpcheck and export series.
	// Separate budget, and must prove recurring first.
	chartExtra
)

// chartClassOf classifies a metric name.
//
// This used to be isChartable, which answered yes only for host.* and two
// container gauges. That was right while the only metrics in the store were
// ones the agent itself decided to collect. It stopped being right when the
// OTLP receiver began decoding application metrics: an application's series
// arrived, was stored, showed a current value, and could never be drawn -- so
// "request latency is climbing" was a fact the store held and could not show.
//
// Splitting the answer in two, rather than widening the yes, is what keeps the
// overview safe. Application names and label sets are unbounded; host.* is
// not. They must not compete for the same slots.
func chartClassOf(name string) chartClass {
	if strings.HasPrefix(name, "host.") {
		return chartCore
	}
	switch name {
	case "container.instance.memory_bytes", "container.instance.cpu_utilization":
		return chartCore
	}

	// process.* stays excluded on purpose, and for the original reason: it is
	// keyed per executable, so a host running a few hundred programs would
	// multiply the sample ring by that count for charts nothing draws.
	if strings.HasPrefix(name, "process.") {
		return chartNone
	}
	// The container network counters are cumulative and shown as totals. A
	// rising cumulative line is a poor chart in any case -- the useful form is
	// a rate, and that is not what is stored here.
	if strings.HasPrefix(name, "container.instance.network.") {
		return chartNone
	}
	return chartExtra
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
		if !ser.updated.Before(cutoff) {
			continue
		}
		// A charted host.* series is never reclaimed: those are the charts the
		// overview draws, they are few, and a gap in them reads as an outage.
		// Everything else can genuinely stop for good -- a container is
		// removed, a service is undeployed -- and without reclaiming, its ring
		// would hold a slot forever and eventually crowd out what is still
		// running. The slot goes back to the budget it came from, or the two
		// counters drift apart and the caps stop meaning anything.
		if len(ser.history) > 0 {
			if strings.HasPrefix(ser.name, "host.") {
				continue
			}
			if chartClassOf(ser.name) == chartExtra {
				h.historyExtra--
			} else {
				h.historySeries--
			}
		}
		delete(h.series, key)
	}
}

// liveSeriesLocked reports whether a series has been reported recently enough
// to describe something that still exists. The view uses it so a program that
// exited stops being listed with the CPU and memory it last had.
func (s *Store) liveSeriesLocked(h *host, ser *series) bool {
	return !ser.updated.Before(h.lastSeen.Add(-s.limits.SeriesStaleAfter))
}

// spanService names the application a span came from, and only ever from the
// sender's own OTLP resource.
//
// It deliberately does NOT fall back to the batch's resource. That resource
// belongs to the AGENT, so falling back to it labels a span from an
// application that declared no service.name as "observability-agent" -- which
// is not a missing answer but a wrong one, pointing an operator at the
// collector instead of at whatever actually emitted the span. An unknown
// service reads as unknown.
func spanService(attrs map[string]string) string {
	for _, k := range []string{"service.name", "service_name"} {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}
