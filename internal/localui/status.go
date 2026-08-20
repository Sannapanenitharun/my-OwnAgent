// Package localui is the agent's local status UI.
//
// It is not a multi-host console and not a cloud-account product. It shows
// this process: identity (including the EC2 instance id when IMDS resolved
// it), module health, and the gauges the collectors have already emitted.
package localui

import (
	"context"
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
	Health      string      `json:"health"`
	StartedAt   time.Time   `json:"started_at,omitempty"`
	Revision    uint64      `json:"config_revision"`
	Modules     []Module    `json:"modules"`
	Highlights  []Highlight `json:"highlights"`
	Metrics     []Metric    `json:"metrics"`
	Diagnostics []Diag      `json:"diagnostics"`
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
func BuildStatus(ctx context.Context, ident platform.Identity, tel platform.Telemetry, sup *supervisor.Supervisor, diags *diagnostics.Recorder) Status {
	st := Status{Health: "unknown"}
	if h, err := os.Hostname(); err == nil {
		st.Hostname = h
	}
	if ident != nil {
		st.Identity.AgentID, _ = ident.AgentID(ctx)
		st.Identity.TenantID, _ = ident.TenantID(ctx)
		st.Identity.HostID, _ = ident.HostID(ctx)
	}
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
	st.Highlights = highlights(points)
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
		out = append(out, Highlight{Label: "CPU busy", Value: v, Unit: "%", OK: true})
	}
	if v, ok := find("host.memory.utilization", "", ""); ok {
		out = append(out, Highlight{Label: "Memory", Value: v, Unit: "%", OK: true})
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
