// Package localui is the agent's local status UI.
//
// It is not a multi-host console and not a cloud-account product. It shows
// this process: identity, module health, and Explore views for recent metrics,
// logs, and OTLP traces retained in memory on this host.
package localui

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/supervisor"
)

// Status is the JSON document the UI polls.
type Status struct {
	Hostname    string      `json:"hostname"`
	Identity    Identity    `json:"identity"`
	Host        HostDetails `json:"host"`
	Health      string      `json:"health"`
	StartedAt   time.Time   `json:"started_at,omitempty"`
	Revision    uint64      `json:"config_revision"`
	Modules     []Module    `json:"modules"`
	Highlights  []Highlight `json:"highlights"`
	Metrics     []Metric    `json:"metrics"`
	Counters    []Counter   `json:"counters"`
	Logs        []LogLine       `json:"logs"`
	Traces      []TraceRow      `json:"traces"`
	Inventory   HostInventory   `json:"inventory"`
	Diagnostics []Diag          `json:"diagnostics"`
}

// HostInventory is what is running / discovered on this host for drill-down.
type HostInventory struct {
	Containers  []InventoryItem `json:"containers"`
	Services    []InventoryItem `json:"services"`
	Processes   []InventoryItem `json:"processes"`
	Endpoints   []InventoryItem `json:"endpoints"`
	Other       []InventoryItem `json:"other"`
	EntityCount map[string]int  `json:"entity_counts,omitempty"`
}

// InventoryItem is one discovered or observed workload on the host.
type InventoryItem struct {
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	Detail string  `json:"detail,omitempty"`
	CPU    float64 `json:"cpu,omitempty"`
	Memory float64 `json:"memory,omitempty"`
	Count  float64 `json:"count,omitempty"`
}

// HostDetails is cloud/OS facts for the Hosts page. Empty strings mean unresolved.
type HostDetails struct {
	Hostname       string  `json:"hostname,omitempty"`
	InstanceID     string  `json:"instance_id,omitempty"`
	InstanceName   string  `json:"instance_name,omitempty"`
	Region         string  `json:"region,omitempty"`
	AZ             string  `json:"availability_zone,omitempty"`
	InstanceType   string  `json:"instance_type,omitempty"`
	AMIID          string  `json:"ami_id,omitempty"`
	AccountID      string  `json:"account_id,omitempty"`
	CloudProvider  string  `json:"cloud_provider,omitempty"`
	LocalHostname  string  `json:"local_hostname,omitempty"`
	PublicHostname string  `json:"public_hostname,omitempty"`
	LocalIPv4      string  `json:"local_ipv4,omitempty"`
	PublicIPv4     string  `json:"public_ipv4,omitempty"`
	OS             string  `json:"os,omitempty"`
	Platform       string  `json:"platform,omitempty"`
	PlatformVer    string  `json:"platform_version,omitempty"`
	Kernel         string  `json:"kernel_version,omitempty"`
	Arch           string  `json:"architecture,omitempty"`
	UptimeSeconds  float64 `json:"uptime_seconds,omitempty"`
}

// Counter is one labelled counter (disk/network cumulative totals).
type Counter struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
	Attrs string `json:"attrs,omitempty"`
}

// LogLine is one recent log record for the Explore → Logs view.
type LogLine struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Body      string    `json:"body"`
	Attrs     string    `json:"attrs,omitempty"`
}

// TraceRow summarises one retained OTLP payload for the Explore → Traces view.
type TraceRow struct {
	Signal      string `json:"signal"`
	ContentType string `json:"content_type"`
	Bytes       int    `json:"bytes"`
	Summary     string `json:"summary,omitempty"`
}

// Identity is resolved platform identity. Empty strings mean unresolved.
type Identity struct {
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`
	HostID   string `json:"host_id"`
}

// Module is one collector's lifecycle and health.
type Module struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Health   string `json:"health"`
	Required bool   `json:"required"`
	Enabled  bool   `json:"enabled"`
	Message  string `json:"message,omitempty"`
	Restarts int64  `json:"restarts"`
}

// Highlight is a named headline gauge for the overview cards.
type Highlight struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
	OK    bool    `json:"ok"`
}

// Metric is one labelled gauge.
type Metric struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Attrs string  `json:"attrs,omitempty"`
}

// Diag is an operator-facing diagnostic.
type Diag struct {
	Code      string            `json:"code"`
	Severity  string            `json:"severity"`
	Source    string            `json:"source"`
	Message   string            `json:"message"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// BuildStatus snapshots the running agent for the UI.
func BuildStatus(ctx context.Context, ident platform.Identity, tel platform.Telemetry, sup *supervisor.Supervisor, diags *diagnostics.Recorder, host HostDetails) Status {
	st := Status{Health: "unknown", Host: host}
	if h, err := os.Hostname(); err == nil {
		st.Hostname = h
		if st.Host.Hostname == "" {
			st.Host.Hostname = h
		}
	}
	if ident != nil {
		st.Identity.AgentID, _ = ident.AgentID(ctx)
		st.Identity.TenantID, _ = ident.TenantID(ctx)
		st.Identity.HostID, _ = ident.HostID(ctx)
		if st.Host.InstanceID == "" {
			st.Host.InstanceID = st.Identity.HostID
		}
	}
	if st.Host.CloudProvider == "" && st.Host.InstanceID != "" {
		st.Host.CloudProvider = "aws"
	}
	enrichHostFromMetrics(&st.Host, platform.SnapshotGauges(tel))
	if sup != nil {
		snap := sup.Snapshot(ctx)
		st.Health = snap.Health.Status.String()
		st.StartedAt = snap.StartedAt
		st.Revision = snap.ConfigRevision
		for _, m := range snap.Modules {
			st.Modules = append(st.Modules, Module{
				ID:       string(m.ID),
				State:    m.State.String(),
				Health:   m.Health.Status.String(),
				Required: m.Required,
				Enabled:  m.Enabled,
				Message:  m.Health.Message,
				Restarts: m.Restarts,
			})
		}
	}
	points := platform.SnapshotGauges(tel)
	st.Metrics = flatten(points)
	st.Counters = flattenCounters(platform.SnapshotCounters(tel))
	st.Highlights = highlights(points)
	st.Logs = flattenLogs(platform.SnapshotLogs(tel))
	st.Traces = flattenTraces(platform.SnapshotTraces(tel))
	st.Inventory = buildInventory(platform.SnapshotEvents(tel), st.Metrics, st.Counters)
	if diags != nil {
		for _, r := range diags.Records() {
			st.Diagnostics = append(st.Diagnostics, Diag{
				Code:      string(r.Code),
				Severity:  r.Severity.String(),
				Source:    r.Source,
				Message:   r.Message,
				Attrs:     r.Attrs,
				Timestamp: r.Timestamp,
			})
		}
	}
	return st
}

func enrichHostFromMetrics(h *HostDetails, points []platform.GaugePoint) {
	for _, p := range points {
		switch p.Name {
		case "host.uptime_seconds":
			h.UptimeSeconds = p.Value
		case "host.info":
			for _, a := range p.Attrs {
				switch a.Key {
				case "os":
					if h.OS == "" {
						h.OS = a.Value
					}
				case "platform":
					if h.Platform == "" {
						h.Platform = a.Value
					}
				case "platform_version":
					if h.PlatformVer == "" {
						h.PlatformVer = a.Value
					}
				case "kernel_version":
					if h.Kernel == "" {
						h.Kernel = a.Value
					}
				case "architecture":
					if h.Arch == "" {
						h.Arch = a.Value
					}
				}
			}
		}
	}
}

func flatten(points []platform.GaugePoint) []Metric {
	out := make([]Metric, 0, len(points))
	for _, p := range points {
		out = append(out, Metric{Name: p.Name, Value: p.Value, Attrs: attrString(p.Attrs)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Attrs < out[j].Attrs
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func flattenCounters(points []platform.CounterPoint) []Counter {
	out := make([]Counter, 0, len(points))
	for _, p := range points {
		out = append(out, Counter{Name: p.Name, Value: p.Value, Attrs: attrString(p.Attrs)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Attrs < out[j].Attrs
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func highlights(points []platform.GaugePoint) []Highlight {
	find := func(name string, key, val string) (float64, bool) {
		for _, p := range points {
			if p.Name != name {
				continue
			}
			if key == "" {
				return p.Value, true
			}
			for _, a := range p.Attrs {
				if a.Key == key && a.Value == val {
					return p.Value, true
				}
			}
		}
		return 0, false
	}
	var out []Highlight
	if v, ok := find("host.cpu.utilization", "state", "busy"); ok {
		out = append(out, Highlight{Label: "CPU busy", Value: v * 100, Unit: "%", OK: true})
	}
	if v, ok := find("host.memory.utilization", "", ""); ok {
		out = append(out, Highlight{Label: "Memory", Value: v * 100, Unit: "%", OK: true})
	}
	if v, ok := find("host.load.1m", "", ""); ok {
		out = append(out, Highlight{Label: "Load 1m", Value: v, Unit: "", OK: true})
	}
	if v, ok := find("process.count", "", ""); ok {
		out = append(out, Highlight{Label: "Processes", Value: v, Unit: "", OK: true})
	}
	return out
}

func attrString(attrs []platform.Attr) string {
	var parts []string
	for _, a := range attrs {
		if a.Key == "" || a.Key == "entity.id" {
			continue
		}
		parts = append(parts, a.Key+"="+a.Value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func flattenLogs(recs []platform.LogRecord) []LogLine {
	out := make([]LogLine, 0, len(recs))
	for _, r := range recs {
		out = append(out, LogLine{
			Timestamp: r.Timestamp,
			Severity:  r.Severity.String(),
			Body:      r.Body,
			Attrs:     attrString(r.Attrs),
		})
	}
	// Newest first for the explore view.
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	const maxShow = 200
	if len(out) > maxShow {
		out = out[:maxShow]
	}
	return out
}

func flattenTraces(payloads []platform.TracePayload) []TraceRow {
	out := make([]TraceRow, 0, len(payloads))
	for _, p := range payloads {
		sig := p.Signal
		if sig == "" {
			sig = "traces"
		}
		out = append(out, TraceRow{
			Signal:      sig,
			ContentType: p.ContentType,
			Bytes:       len(p.Body),
			Summary:     traceSummary(p.Body),
		})
	}
	const maxShow = 100
	if len(out) > maxShow {
		out = out[len(out)-maxShow:]
	}
	return out
}

func traceSummary(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	// Best-effort JSON OTLP: pull a few span names if present.
	s := string(body)
	const marker = `"name":"`
	var names []string
	for i := 0; i < len(s) && len(names) < 3; {
		j := strings.Index(s[i:], marker)
		if j < 0 {
			break
		}
		i += j + len(marker)
		end := strings.IndexByte(s[i:], '"')
		if end < 0 {
			break
		}
		name := s[i : i+end]
		if name != "" && name != "default" {
			names = append(names, name)
		}
		i += end + 1
	}
	if len(names) == 0 {
		if len(body) > 80 {
			return fmt.Sprintf("%d bytes (opaque)", len(body))
		}
		return string(body)
	}
	return strings.Join(names, ", ")
}

func buildInventory(events []platform.Event, metrics []Metric, _ []Counter) HostInventory {
	inv := HostInventory{EntityCount: map[string]int{}}
	type ent struct {
		kind, name, detail string
		gone               bool
	}
	byKey := map[string]*ent{}

	for _, ev := range events {
		switch ev.Name {
		case "discovery.entity.discovered", "discovery.entity.changed":
			kind, name, detail, key := inventoryFromAttrs(ev.Attrs)
			if kind == "" || key == "" {
				continue
			}
			byKey[key] = &ent{kind: kind, name: name, detail: detail}
		case "discovery.entity.removed":
			kind, name, _, key := inventoryFromAttrs(ev.Attrs)
			if key == "" {
				key = kind + "|" + name
			}
			if e, ok := byKey[key]; ok {
				e.gone = true
			}
		}
	}

	for _, e := range byKey {
		if e.gone || e.name == "" {
			continue
		}
		item := InventoryItem{Kind: e.kind, Name: e.name, Detail: e.detail}
		switch e.kind {
		case "container":
			inv.Containers = append(inv.Containers, item)
		case "service":
			inv.Services = append(inv.Services, item)
		case "network_endpoint":
			inv.Endpoints = append(inv.Endpoints, item)
		case "process", "application", "database":
			inv.Processes = append(inv.Processes, item)
		default:
			inv.Other = append(inv.Other, item)
		}
		inv.EntityCount[e.kind]++
	}

	// Applications from process module rollups (executables).
	type proc struct {
		name string
		cpu  float64
		rss  float64
		n    float64
	}
	procs := map[string]*proc{}
	for _, m := range metrics {
		exe := attrValue(m.Attrs, "executable")
		if exe == "" {
			continue
		}
		p := procs[exe]
		if p == nil {
			p = &proc{name: exe}
			procs[exe] = p
		}
		switch m.Name {
		case "process.cpu.utilization":
			p.cpu = m.Value
		case "process.memory.rss":
			p.rss = m.Value
		case "process.instances":
			p.n = m.Value
		}
	}
	for _, p := range procs {
		inv.Processes = append(inv.Processes, InventoryItem{
			Kind:   "process",
			Name:   p.name,
			Detail: fmt.Sprintf("instances=%.0f", p.n),
			CPU:    p.cpu,
			Memory: p.rss,
			Count:  p.n,
		})
	}

	sort.Slice(inv.Containers, func(i, j int) bool { return inv.Containers[i].Name < inv.Containers[j].Name })
	sort.Slice(inv.Services, func(i, j int) bool { return inv.Services[i].Name < inv.Services[j].Name })
	sort.Slice(inv.Endpoints, func(i, j int) bool { return inv.Endpoints[i].Name < inv.Endpoints[j].Name })
	sort.Slice(inv.Processes, func(i, j int) bool { return inv.Processes[i].CPU > inv.Processes[j].CPU })
	sort.Slice(inv.Other, func(i, j int) bool { return inv.Other[i].Name < inv.Other[j].Name })

	const maxProc = 100
	if len(inv.Processes) > maxProc {
		inv.Processes = inv.Processes[:maxProc]
	}
	return inv
}

func inventoryFromAttrs(attrs []platform.Attr) (kind, name, detail, key string) {
	var containerID, runtime, state, address, port, protocol string
	for _, a := range attrs {
		switch a.Key {
		case "entity.kind", "kind":
			kind = a.Value
		case "name", "display_name":
			if name == "" {
				name = a.Value
			}
		case "container_id":
			containerID = a.Value
		case "runtime":
			runtime = a.Value
		case "state":
			state = a.Value
		case "address":
			address = a.Value
		case "port":
			port = a.Value
		case "protocol":
			protocol = a.Value
		}
	}
	if name == "" {
		name = containerID
	}
	if name == "" && address != "" {
		name = address
		if port != "" {
			name += ":" + port
		}
	}
	switch kind {
	case "container":
		parts := []string{}
		if runtime != "" {
			parts = append(parts, "runtime="+runtime)
		}
		if containerID != "" {
			id := containerID
			if len(id) > 12 {
				id = id[:12]
			}
			parts = append(parts, "id="+id)
		}
		detail = strings.Join(parts, " ")
	case "service":
		if state != "" {
			detail = "state=" + state
		}
	case "network_endpoint":
		detail = strings.TrimSpace(protocol + " " + address)
		if port != "" {
			if detail != "" {
				detail += ":"
			}
			detail += port
		}
	}
	key = kind + "|" + name + "|" + containerID
	return kind, name, strings.TrimSpace(detail), key
}

func attrValue(attrs, key string) string {
	for _, part := range strings.Split(attrs, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == key {
			return v
		}
	}
	return ""
}
