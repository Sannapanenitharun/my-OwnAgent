package fleet

import (
	"sort"
	"strings"
	"time"
)

// Sample is one point of a charted series.
type Sample struct {
	Time  time.Time `json:"t"`
	Value float64   `json:"v"`
}

// LogLine is one recent log record as the fleet page shows it.
type LogLine struct {
	Time    time.Time `json:"time"`
	Status  string    `json:"status,omitempty"`
	Source  string    `json:"source,omitempty"`
	Message string    `json:"message"`

	// Origin. A fleet-wide log view is unreadable without it: "all the logs
	// on the server" is many files and many containers interleaved.
	File      string `json:"file,omitempty"`
	Container string `json:"container_id,omitempty"`
	Stream    string `json:"stream,omitempty"`
	// TraceID is the request this line belongs to, where the application wrote
	// its trace context into the line. It is the join between the Logs tab and
	// the Traces tab -- without it the two are separate lists of the same
	// incident.
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
}

// Span is one recent span, reduced to what a list can usefully show.
type Span struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
	Name    string `json:"name"`
	// Service is service.name from the sender's OTLP resource. Without it a
	// list of spans from a host running twenty applications is twenty sets of
	// anonymous operation names with no way to tell which sent which.
	Service string    `json:"service,omitempty"`
	Status  string    `json:"status,omitempty"`
	Time    time.Time `json:"time"`
}

// Summary is one row of the fleet list: enough to judge a host at a glance
// without shipping its whole series set.
type Summary struct {
	// Host is the stable key: the instance id on EC2. Name is what a person
	// recognises. They are separate because two instances can share a Name tag,
	// so the name can never be the key.
	Host      string    `json:"host"`
	Name      string    `json:"name"`
	HostID    string    `json:"host_id,omitempty"`
	Provider  string    `json:"cloud_provider,omitempty"`
	OS        string    `json:"os,omitempty"`
	Platform  string    `json:"platform,omitempty"`
	Version   string    `json:"platform_version,omitempty"`
	Arch      string    `json:"architecture,omitempty"`
	Agent     string    `json:"agent_version,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	AgeSec    float64   `json:"age_seconds"`
	Stale     bool      `json:"stale"`

	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	MemUsed    float64 `json:"mem_used_bytes"`
	MemTotal   float64 `json:"mem_total_bytes"`
	DiskPct    float64 `json:"disk_percent"`
	IOWait     float64 `json:"iowait_percent"`
	Load1      float64 `json:"load_1m"`
	Load5      float64 `json:"load_5m"`
	Load15     float64 `json:"load_15m"`
	HasLoad    bool    `json:"has_load"`
	Uptime     float64 `json:"uptime_seconds"`
	Processes  float64 `json:"processes"`

	Series       int            `json:"series"`
	Dropped      int64          `json:"dropped_series"`
	BatchLogs    int64          `json:"batches_logs"`
	BatchMetrics int64          `json:"batches_metrics"`
	BatchTraces  int64          `json:"batches_traces"`
	BatchInvent  int64          `json:"batches_inventory"`
	InvCounts    map[string]int `json:"inventory_counts,omitempty"`
	LogCount     int            `json:"log_count"`
	SpanCount    int            `json:"span_count"`
}

// Fleet is the whole-fleet document the list page polls.
type Fleet struct {
	Now      time.Time `json:"now"`
	Hosts    []Summary `json:"hosts"`
	Total    int       `json:"total"`
	Live     int       `json:"live"`
	StaleFor string    `json:"stale_after"`
}

// SeriesView is one series in a host detail document.
type SeriesView struct {
	Name    string            `json:"name"`
	Attrs   map[string]string `json:"attrs,omitempty"`
	Value   float64           `json:"value"`
	Updated time.Time         `json:"updated"`
	History []Sample          `json:"history,omitempty"`
}

// Detail is everything the page shows for one host.
type Detail struct {
	Summary
	Resource  map[string]string `json:"resource,omitempty"`
	Inventory Inventory         `json:"inventory"`
	Metrics   []SeriesView      `json:"metrics"`
	Logs      []LogLine         `json:"logs"`
	Spans     []Span            `json:"spans"`
}

// Fleet returns the summary of every known host, freshest first.
func (s *Store) Fleet() Fleet {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	out := Fleet{
		Now:      now,
		Hosts:    make([]Summary, 0, len(s.hosts)),
		StaleFor: s.limits.StaleAfter.String(),
	}
	for _, h := range s.hosts {
		sum := s.summarise(h, now)
		if !sum.Stale {
			out.Live++
		}
		out.Hosts = append(out.Hosts, sum)
	}
	out.Total = len(out.Hosts)
	sort.Slice(out.Hosts, func(i, j int) bool {
		if out.Hosts[i].Stale != out.Hosts[j].Stale {
			return !out.Hosts[i].Stale
		}
		return out.Hosts[i].Host < out.Hosts[j].Host
	})
	return out
}

// Host returns the detail document for one host, and whether it is known.
func (s *Store) Host(name string) (Detail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := s.hosts[name]
	if h == nil {
		return Detail{}, false
	}
	now := s.now()
	d := Detail{
		Summary:   s.summarise(h, now),
		Resource:  map[string]string{},
		Metrics:   make([]SeriesView, 0, len(h.series)),
		Logs:      h.logs.snapshot(),
		Spans:     h.spans.snapshot(),
		Inventory: s.inventoryLocked(h),
	}
	for k, v := range h.resource {
		d.Resource[k] = v
	}
	for _, ser := range h.series {
		view := SeriesView{
			Name:    ser.name,
			Attrs:   ser.attrs,
			Value:   ser.value,
			Updated: ser.updated,
		}
		if len(ser.history) > 0 {
			view.History = append([]Sample(nil), ser.history...)
		}
		d.Metrics = append(d.Metrics, view)
	}
	sort.Slice(d.Metrics, func(i, j int) bool {
		if d.Metrics[i].Name != d.Metrics[j].Name {
			return d.Metrics[i].Name < d.Metrics[j].Name
		}
		return attrString(d.Metrics[i].Attrs) < attrString(d.Metrics[j].Attrs)
	})
	return d, true
}

// summarise reduces a host to its headline numbers. The caller holds s.mu.
func (s *Store) summarise(h *host, now time.Time) Summary {
	age := now.Sub(h.lastSeen)
	sum := Summary{
		Host:         h.name,
		Name:         displayName(h),
		HostID:       h.hostID,
		Provider:     h.resource["cloud.provider"],
		Agent:        h.resource["service.version"],
		FirstSeen:    h.firstSeen,
		LastSeen:     h.lastSeen,
		AgeSec:       age.Seconds(),
		Stale:        age > s.limits.StaleAfter,
		Series:       len(h.series),
		Dropped:      h.dropped,
		BatchLogs:    h.batchLogs,
		BatchMetrics: h.batchMetrics,
		BatchTraces:  h.batchTraces,
		BatchInvent:  h.batchInventory,
		InvCounts:    s.inventoryCountsLocked(h),
		LogCount:     h.logs.len(),
		SpanCount:    h.spans.len(),
	}

	// host.info is a constant-1 gauge whose attributes carry the OS identity.
	for _, ser := range h.series {
		if ser.name == "host.info" {
			sum.OS = ser.attrs["os"]
			sum.Platform = ser.attrs["platform"]
			sum.Version = ser.attrs["platform_version"]
			sum.Arch = ser.attrs["architecture"]
			break
		}
	}

	// CPU is reported per state; "busy" is the one a fleet list wants.
	if v, ok := findSeries(h, "host.cpu.utilization", "state", "busy"); ok {
		sum.CPUPercent = v * 100
	}
	if v, ok := findSeries(h, "host.memory.utilization", "", ""); ok {
		sum.MemPercent = v * 100
	}
	if v, ok := findSeries(h, "host.memory.used_bytes", "", ""); ok {
		sum.MemUsed = v
	}
	if v, ok := findSeries(h, "host.memory.total_bytes", "", ""); ok {
		sum.MemTotal = v
	}
	if sum.MemPercent == 0 && sum.MemTotal > 0 {
		sum.MemPercent = sum.MemUsed / sum.MemTotal * 100
	}
	if v, ok := findSeries(h, "host.uptime_seconds", "", ""); ok {
		sum.Uptime = v
	}
	if v, ok := findSeries(h, "host.cpu.utilization", "state", "iowait"); ok {
		sum.IOWait = v * 100
	}
	// Load average is POSIX-only; Windows reports none, and a zero there would
	// read as an idle machine rather than an unavailable metric.
	if v, ok := findSeries(h, "host.load.1m", "", ""); ok {
		sum.Load1, sum.HasLoad = v, true
	}
	if v, ok := findSeries(h, "host.load.5m", "", ""); ok {
		sum.Load5 = v
	}
	if v, ok := findSeries(h, "host.load.15m", "", ""); ok {
		sum.Load15 = v
	}
	// process.instances is emitted once per executable, so the fleet-level
	// process count is their sum; any single series is meaningless on its own.
	for _, ser := range h.series {
		if ser.name == "process.instances" {
			sum.Processes += ser.value
		}
	}

	// Report the fullest filesystem: one full disk is what matters, not the mean.
	for _, ser := range h.series {
		if ser.name == "host.filesystem.utilization" && ser.value*100 > sum.DiskPct {
			sum.DiskPct = ser.value * 100
		}
	}
	return sum
}

// findSeries returns the value of a series, optionally requiring one attribute.
// With no attribute filter it prefers the series carrying no attributes, so a
// per-state or per-device breakdown never stands in for the aggregate.
func findSeries(h *host, name, attrKey, attrVal string) (float64, bool) {
	var fallback float64
	var haveFallback bool
	for _, ser := range h.series {
		if ser.name != name {
			continue
		}
		if attrKey != "" {
			if ser.attrs[attrKey] == attrVal {
				return ser.value, true
			}
			continue
		}
		if len(ser.attrs) == 0 {
			return ser.value, true
		}
		if !haveFallback {
			fallback, haveFallback = ser.value, true
		}
	}
	return fallback, haveFallback
}

func attrString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(' ')
	}
	return b.String()
}

// logRing and spanRing keep the most recent N entries and nothing older.

type logRing struct {
	buf  []LogLine
	next int
	full bool
}

func newLogRing(n int) *logRing { return &logRing{buf: make([]LogLine, n)} }

func (r *logRing) push(v LogLine) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *logRing) len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// snapshot returns the entries newest first.
func (r *logRing) snapshot() []LogLine {
	n := r.len()
	out := make([]LogLine, 0, n)
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + len(r.buf)*2) % len(r.buf)
		out = append(out, r.buf[idx])
	}
	return out
}

type spanRing struct {
	buf  []Span
	next int
	full bool
}

func newSpanRing(n int) *spanRing { return &spanRing{buf: make([]Span, n)} }

func (r *spanRing) push(v Span) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *spanRing) len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

func (r *spanRing) snapshot() []Span {
	n := r.len()
	out := make([]Span, 0, n)
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + len(r.buf)*2) % len(r.buf)
		out = append(out, r.buf[idx])
	}
	return out
}

// displayName prefers the EC2 Name tag, which the agent resolves from IMDS
// instance tags when they are enabled. It falls back to the host key, which is
// the instance id on EC2 and the hostname elsewhere: an id is a poor label but
// a correct one, and better than showing nothing.
func displayName(h *host) string {
	if n := strings.TrimSpace(h.resource["host.name"]); n != "" {
		return n
	}
	return h.name
}
