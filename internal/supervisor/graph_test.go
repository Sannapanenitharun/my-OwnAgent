package supervisor

import (
	"errors"
	"reflect"
	"testing"

	"github.com/obsagent/observability-agent/internal/module"
)

func manifests(specs map[string][]string) map[module.ID]module.Manifest {
	out := make(map[module.ID]module.Manifest, len(specs))
	for id, deps := range specs {
		m := module.Manifest{ID: module.ID(id), Version: "1.0.0"}
		for _, d := range deps {
			m.Dependencies = append(m.Dependencies, module.ID(d))
		}
		out[module.ID(id)] = m
	}
	return out
}

func TestResolveOrdersDependenciesFirst(t *testing.T) {
	// A shape close to the real agent: collectors depend on the pipeline, the
	// pipeline depends on the scrubber.
	g, err := Resolve(manifests(map[string][]string{
		"secret-scrubber": nil,
		"otel-engine":     {"secret-scrubber"},
		"discovery":       {"otel-engine"},
		"host":            {"otel-engine", "discovery"},
		"process":         {"otel-engine", "discovery"},
	}))
	if err != nil {
		t.Fatal(err)
	}

	pos := map[module.ID]int{}
	for i, id := range g.StartOrder() {
		pos[id] = i
	}
	for _, pair := range [][2]string{
		{"secret-scrubber", "otel-engine"},
		{"otel-engine", "discovery"},
		{"discovery", "host"},
		{"discovery", "process"},
	} {
		if pos[module.ID(pair[0])] >= pos[module.ID(pair[1])] {
			t.Errorf("%s must start before %s", pair[0], pair[1])
		}
	}
}

func TestResolveIsDeterministic(t *testing.T) {
	// A nondeterministic start order turns an ordering bug into one that
	// reproduces on a single host in a fleet and nowhere else.
	spec := map[string][]string{
		"a": nil, "b": nil, "c": nil, "d": {"a"}, "e": {"a"}, "f": {"b", "c"},
	}
	first, err := Resolve(manifests(spec))
	if err != nil {
		t.Fatal(err)
	}
	want := first.StartOrder()
	for i := 0; i < 50; i++ {
		g, err := Resolve(manifests(spec))
		if err != nil {
			t.Fatal(err)
		}
		if got := g.StartOrder(); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d produced %v, want %v", i, got, want)
		}
	}
}

func TestStopOrderIsExactlyReversed(t *testing.T) {
	g, err := Resolve(manifests(map[string][]string{"a": nil, "b": {"a"}, "c": {"b"}}))
	if err != nil {
		t.Fatal(err)
	}
	start, stop := g.StartOrder(), g.StopOrder()
	if len(start) != len(stop) {
		t.Fatalf("lengths differ: %d vs %d", len(start), len(stop))
	}
	for i := range start {
		if start[i] != stop[len(stop)-1-i] {
			t.Fatalf("stop order is not the reverse of start order:\nstart=%v\nstop=%v", start, stop)
		}
	}
}

func TestResolveDetectsMissingDependency(t *testing.T) {
	_, err := Resolve(manifests(map[string][]string{"host": {"otel-engine"}}))
	var mde *MissingDependencyError
	if !errors.As(err, &mde) {
		t.Fatalf("error = %v, want *MissingDependencyError", err)
	}
	if mde.Module != "host" || mde.Dependency != "otel-engine" {
		t.Fatalf("error identifies %q -> %q", mde.Module, mde.Dependency)
	}
}

func TestResolveDetectsSelfDependency(t *testing.T) {
	_, err := Resolve(manifests(map[string][]string{"host": {"host"}}))
	var sde *SelfDependencyError
	if !errors.As(err, &sde) {
		t.Fatalf("error = %v, want *SelfDependencyError", err)
	}
}

func TestResolveDetectsCycleAndNamesIt(t *testing.T) {
	_, err := Resolve(manifests(map[string][]string{
		"a": {"c"}, "b": {"a"}, "c": {"b"},
	}))
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want *CycleError", err)
	}
	// The message must let an operator act without reading manifests.
	if len(ce.Cycle) < 3 {
		t.Fatalf("cycle %v does not describe the loop", ce.Cycle)
	}
	if ce.Cycle[0] != ce.Cycle[len(ce.Cycle)-1] {
		t.Fatalf("cycle %v is not closed", ce.Cycle)
	}
}

func TestResolveDetectsTwoNodeCycle(t *testing.T) {
	_, err := Resolve(manifests(map[string][]string{"a": {"b"}, "b": {"a"}}))
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want *CycleError", err)
	}
}

func TestResolveIgnoresDuplicateDependencyEntries(t *testing.T) {
	// A manifest listing the same dependency twice is harmless, but it must
	// not corrupt the indegree count and strand the module.
	g, err := Resolve(map[module.ID]module.Manifest{
		"a": {ID: "a", Version: "1"},
		"b": {ID: "b", Version: "1", Dependencies: []module.ID{"a", "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := g.StartOrder(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("start order = %v", got)
	}
}

func TestResolveEmptyGraph(t *testing.T) {
	g, err := Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.StartOrder()) != 0 {
		t.Fatalf("expected an empty order, got %v", g.StartOrder())
	}
}

func TestTransitiveDependentsInStopOrder(t *testing.T) {
	g, err := Resolve(manifests(map[string][]string{
		"scrubber":  nil,
		"otel":      {"scrubber"},
		"host":      {"otel"},
		"process":   {"otel"},
		"unrelated": nil,
	}))
	if err != nil {
		t.Fatal(err)
	}

	got := g.TransitiveDependents("scrubber")
	want := map[module.ID]bool{"otel": true, "host": true, "process": true}
	if len(got) != len(want) {
		t.Fatalf("transitive dependents = %v, want %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected dependent %q", id)
		}
	}
	// otel must be stopped last among them, since host and process need it.
	if got[len(got)-1] != "otel" {
		t.Fatalf("otel should stop last among dependents, order was %v", got)
	}
}

func TestDependenciesAndDependents(t *testing.T) {
	g, err := Resolve(manifests(map[string][]string{"a": nil, "b": {"a"}, "c": {"a"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Dependencies("b"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("Dependencies(b) = %v", got)
	}
	if got := g.Dependents("a"); len(got) != 2 {
		t.Fatalf("Dependents(a) = %v, want 2 entries", got)
	}
	if got := g.Dependents("b"); len(got) != 0 {
		t.Fatalf("Dependents(b) = %v, want none", got)
	}
}

func TestGraphAccessorsReturnCopies(t *testing.T) {
	// The graph is immutable for the life of a configuration revision; callers
	// must not be able to reach in and reorder it.
	g, err := Resolve(manifests(map[string][]string{"a": nil, "b": {"a"}}))
	if err != nil {
		t.Fatal(err)
	}
	order := g.StartOrder()
	order[0] = "mutated"
	if g.StartOrder()[0] == "mutated" {
		t.Fatal("StartOrder exposes internal state")
	}

	deps := g.Dependencies("b")
	deps[0] = "mutated"
	if g.Dependencies("b")[0] == "mutated" {
		t.Fatal("Dependencies exposes internal state")
	}
}
