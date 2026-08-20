package health

import "testing"

func comp(id string, required bool, s Status) ComponentHealth {
	return ComponentHealth{ID: id, Required: required, Report: Report{Status: s}}
}

func TestAggregateEmptyIsUnknown(t *testing.T) {
	// An agent supervising nothing has not proven anything works.
	if got := AggregateOf(nil).Status; got != Unknown {
		t.Fatalf("empty aggregate = %v, want %v", got, Unknown)
	}
}

func TestAggregateRules(t *testing.T) {
	tests := []struct {
		name       string
		components []ComponentHealth
		want       Status
	}{
		{
			name:       "all healthy",
			components: []ComponentHealth{comp("a", true, Healthy), comp("b", false, Healthy)},
			want:       Healthy,
		},
		{
			name:       "required unhealthy fails the agent",
			components: []ComponentHealth{comp("a", true, Unhealthy), comp("b", true, Healthy)},
			want:       Unhealthy,
		},
		{
			name:       "optional unhealthy only degrades",
			components: []ComponentHealth{comp("a", false, Unhealthy), comp("b", true, Healthy)},
			want:       Degraded,
		},
		{
			name:       "optional degraded degrades",
			components: []ComponentHealth{comp("a", false, Degraded), comp("b", true, Healthy)},
			want:       Degraded,
		},
		{
			name:       "unknown is worse than healthy but better than degraded",
			components: []ComponentHealth{comp("a", true, Unknown), comp("b", true, Healthy)},
			want:       Unknown,
		},
		{
			name:       "degraded beats unknown",
			components: []ComponentHealth{comp("a", true, Unknown), comp("b", true, Degraded)},
			want:       Degraded,
		},
		{
			name: "many optional failures never reach unhealthy",
			components: []ComponentHealth{
				comp("a", false, Unhealthy), comp("b", false, Unhealthy), comp("c", false, Unhealthy),
			},
			want: Degraded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AggregateOf(tc.components).Status; got != tc.want {
				t.Fatalf("status = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAggregateIsDeterministicallyOrdered(t *testing.T) {
	agg := AggregateOf([]ComponentHealth{comp("z", true, Healthy), comp("a", true, Healthy)})
	if agg.Components[0].ID != "a" || agg.Components[1].ID != "z" {
		t.Fatalf("components not sorted by ID: %+v", agg.Components)
	}
}

func TestComponentLookup(t *testing.T) {
	agg := AggregateOf([]ComponentHealth{comp("host", true, Degraded)})
	c, ok := agg.Component("host")
	if !ok || c.Report.Status != Degraded {
		t.Fatalf("Component(host) = %+v, %v", c, ok)
	}
	if _, ok := agg.Component("absent"); ok {
		t.Fatal("Component reported a component that does not exist")
	}
}

func TestWorseOf(t *testing.T) {
	if got := WorseOf(Healthy, Degraded); got != Degraded {
		t.Fatalf("WorseOf(Healthy, Degraded) = %v", got)
	}
	if got := WorseOf(Unhealthy, Degraded); got != Unhealthy {
		t.Fatalf("WorseOf(Unhealthy, Degraded) = %v", got)
	}
	if got := WorseOf(Healthy, Healthy); got != Healthy {
		t.Fatalf("WorseOf(Healthy, Healthy) = %v", got)
	}
}
