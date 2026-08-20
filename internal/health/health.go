// Package health defines the agent's health model and aggregation rules.
//
// There is exactly one health model in the agent. Modules report their own
// health; the supervisor aggregates. Aggregation is deliberately asymmetric:
// a failing REQUIRED module makes the agent unhealthy, while a failing OPTIONAL
// module can only degrade it. Without that asymmetry every unsupported
// capability — eBPF on Windows, profiling on a locked-down host — would page an
// operator for a condition that is expected and harmless.
package health

import (
	"sort"

	"github.com/obsagent/observability-agent/internal/diagnostics"
)

// Status is a component's health state.
type Status int

const (
	// Unknown means health has not yet been determined. It aggregates as
	// worse than Healthy but better than Degraded, so a starting agent is
	// never reported as failing.
	Unknown Status = iota
	// Healthy means fully functional.
	Healthy
	// Degraded means functional with reduced fidelity or coverage.
	Degraded
	// Unhealthy means not functional.
	Unhealthy
)

func (s Status) String() string {
	switch s {
	case Unknown:
		return "unknown"
	case Healthy:
		return "healthy"
	case Degraded:
		return "degraded"
	case Unhealthy:
		return "unhealthy"
	default:
		return "invalid"
	}
}

// severity orders statuses for aggregation. Higher is worse.
func (s Status) severity() int {
	switch s {
	case Healthy:
		return 0
	case Unknown:
		return 1
	case Degraded:
		return 2
	case Unhealthy:
		return 3
	default:
		return 3
	}
}

// WorseOf returns the worse of two statuses.
func WorseOf(a, b Status) Status {
	if b.severity() > a.severity() {
		return b
	}
	return a
}

// Report is a component's health at a point in time.
type Report struct {
	Status  Status
	Message string
	// Diagnostics explain a non-Healthy status. They are advisory; the
	// supervisor also records them centrally.
	Diagnostics []diagnostics.Record
}

// Healthy returns a healthy Report.
func OK(message string) Report { return Report{Status: Healthy, Message: message} }

// DegradedReport returns a degraded Report.
func DegradedReport(message string, diags ...diagnostics.Record) Report {
	return Report{Status: Degraded, Message: message, Diagnostics: diags}
}

// UnhealthyReport returns an unhealthy Report.
func UnhealthyReport(message string, diags ...diagnostics.Record) Report {
	return Report{Status: Unhealthy, Message: message, Diagnostics: diags}
}

// ComponentHealth pairs a component identifier with its report and whether the
// component is required for the agent to be considered healthy.
type ComponentHealth struct {
	ID       string
	Required bool
	Report   Report
}

// Aggregate is the agent-level health view.
type Aggregate struct {
	Status     Status
	Components []ComponentHealth
}

// Component returns the health of a single component.
func (a Aggregate) Component(id string) (ComponentHealth, bool) {
	for _, c := range a.Components {
		if c.ID == id {
			return c, true
		}
	}
	return ComponentHealth{}, false
}

// Aggregate combines component health into an agent-level status.
//
// Rules:
//   - A required component's status propagates unchanged.
//   - An optional component's status is capped at Degraded; an optional
//     component can never make the agent Unhealthy.
//   - No components at all is Unknown, not Healthy: an agent supervising
//     nothing has not proven it is working.
func AggregateOf(components []ComponentHealth) Aggregate {
	sorted := make([]ComponentHealth, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	if len(sorted) == 0 {
		return Aggregate{Status: Unknown, Components: sorted}
	}

	status := Healthy
	for _, c := range sorted {
		s := c.Report.Status
		if !c.Required && s == Unhealthy {
			s = Degraded
		}
		status = WorseOf(status, s)
	}
	return Aggregate{Status: status, Components: sorted}
}
