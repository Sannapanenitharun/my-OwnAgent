package supervisor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/obsagent/observability-agent/internal/module"
)

// Graph is the resolved module dependency graph.
//
// It is computed once per configuration revision and is immutable thereafter.
// Recomputing it on every start would let a module's manifest change the start
// order at runtime, which is exactly the kind of hidden coupling the module
// contract forbids.
type Graph struct {
	order      []module.ID
	deps       map[module.ID][]module.ID
	dependents map[module.ID][]module.ID
}

// MissingDependencyError reports a dependency on a module that is not present
// or not enabled.
type MissingDependencyError struct {
	Module     module.ID
	Dependency module.ID
}

func (e *MissingDependencyError) Error() string {
	return fmt.Sprintf("supervisor: module %q depends on %q, which is not registered or not enabled",
		e.Module, e.Dependency)
}

// SelfDependencyError reports a module that depends on itself.
type SelfDependencyError struct {
	Module module.ID
}

func (e *SelfDependencyError) Error() string {
	return fmt.Sprintf("supervisor: module %q depends on itself", e.Module)
}

// CycleError reports a dependency cycle, including the cycle itself so an
// operator can act on the message without reading the manifests.
type CycleError struct {
	Cycle []module.ID
}

func (e *CycleError) Error() string {
	parts := make([]string, 0, len(e.Cycle))
	for _, id := range e.Cycle {
		parts = append(parts, string(id))
	}
	return "supervisor: dependency cycle: " + strings.Join(parts, " -> ")
}

// Resolve builds a start-ordered dependency graph from module manifests.
//
// The order is deterministic: among modules whose dependencies are all
// satisfied, the lowest ID starts first. Determinism matters more than it
// looks — a nondeterministic start order turns an ordering bug into an
// intermittent one that reproduces on one host in a fleet and nowhere else.
func Resolve(manifests map[module.ID]module.Manifest) (*Graph, error) {
	g := &Graph{
		deps:       make(map[module.ID][]module.ID, len(manifests)),
		dependents: make(map[module.ID][]module.ID, len(manifests)),
	}

	ids := make([]module.ID, 0, len(manifests))
	for id := range manifests {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	indegree := make(map[module.ID]int, len(ids))
	for _, id := range ids {
		indegree[id] = 0
	}

	for _, id := range ids {
		seen := make(map[module.ID]bool)
		for _, dep := range manifests[id].Dependencies {
			if dep == id {
				return nil, &SelfDependencyError{Module: id}
			}
			if _, ok := manifests[dep]; !ok {
				return nil, &MissingDependencyError{Module: id, Dependency: dep}
			}
			// Tolerate a manifest listing the same dependency twice; it is
			// harmless and rejecting it would be pedantry, but it must not
			// corrupt the indegree count.
			if seen[dep] {
				continue
			}
			seen[dep] = true
			g.deps[id] = append(g.deps[id], dep)
			g.dependents[dep] = append(g.dependents[dep], id)
			indegree[id]++
		}
	}

	// Kahn's algorithm with a sorted ready set for determinism.
	ready := make([]module.ID, 0, len(ids))
	for _, id := range ids {
		if indegree[id] == 0 {
			ready = append(ready, id)
		}
	}

	order := make([]module.ID, 0, len(ids))
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return ready[i] < ready[j] })
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)

		dependents := append([]module.ID(nil), g.dependents[id]...)
		sort.Slice(dependents, func(i, j int) bool { return dependents[i] < dependents[j] })
		for _, dep := range dependents {
			indegree[dep]--
			if indegree[dep] == 0 {
				ready = append(ready, dep)
			}
		}
	}

	if len(order) != len(ids) {
		remaining := make(map[module.ID]bool, len(ids)-len(order))
		for _, id := range ids {
			if indegree[id] > 0 {
				remaining[id] = true
			}
		}
		return nil, &CycleError{Cycle: findCycle(remaining, g.deps)}
	}

	g.order = order
	for id := range g.dependents {
		sort.Slice(g.dependents[id], func(i, j int) bool { return g.dependents[id][i] < g.dependents[id][j] })
	}
	return g, nil
}

// findCycle returns one cycle among the unresolved nodes, for diagnostics.
func findCycle(remaining map[module.ID]bool, deps map[module.ID][]module.ID) []module.ID {
	start := make([]module.ID, 0, len(remaining))
	for id := range remaining {
		start = append(start, id)
	}
	sort.Slice(start, func(i, j int) bool { return start[i] < start[j] })

	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[module.ID]int, len(remaining))
	var stack []module.ID
	var cycle []module.ID

	var visit func(module.ID) bool
	visit = func(id module.ID) bool {
		color[id] = grey
		stack = append(stack, id)
		neighbours := append([]module.ID(nil), deps[id]...)
		sort.Slice(neighbours, func(i, j int) bool { return neighbours[i] < neighbours[j] })
		for _, dep := range neighbours {
			if !remaining[dep] {
				continue
			}
			switch color[dep] {
			case grey:
				for i, s := range stack {
					if s == dep {
						cycle = append(append([]module.ID(nil), stack[i:]...), dep)
						return true
					}
				}
				return true
			case white:
				if visit(dep) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
		return false
	}

	for _, id := range start {
		if color[id] == white && visit(id) {
			break
		}
	}
	if cycle == nil {
		// Unreachable for a genuine cycle, but returning the unresolved set is
		// strictly better than an empty message if it ever happens.
		cycle = start
	}
	return cycle
}

// StartOrder returns modules in dependency order: every module appears after
// all of its dependencies.
func (g *Graph) StartOrder() []module.ID {
	return append([]module.ID(nil), g.order...)
}

// StopOrder returns the reverse of StartOrder. Stopping in reverse guarantees
// a module is never left running with a stopped dependency.
func (g *Graph) StopOrder() []module.ID {
	out := make([]module.ID, len(g.order))
	for i, id := range g.order {
		out[len(g.order)-1-i] = id
	}
	return out
}

// Dependencies returns the modules id depends on.
func (g *Graph) Dependencies(id module.ID) []module.ID {
	return append([]module.ID(nil), g.deps[id]...)
}

// Dependents returns the modules that depend on id, directly.
func (g *Graph) Dependents(id module.ID) []module.ID {
	return append([]module.ID(nil), g.dependents[id]...)
}

// TransitiveDependents returns every module that depends on id, directly or
// indirectly, in stop order. The supervisor uses it to stop the affected
// subtree when a dependency fails.
func (g *Graph) TransitiveDependents(id module.ID) []module.ID {
	seen := make(map[module.ID]bool)
	var walk func(module.ID)
	walk = func(cur module.ID) {
		for _, d := range g.dependents[cur] {
			if seen[d] {
				continue
			}
			seen[d] = true
			walk(d)
		}
	}
	walk(id)

	out := make([]module.ID, 0, len(seen))
	for _, candidate := range g.StopOrder() {
		if seen[candidate] {
			out = append(out, candidate)
		}
	}
	return out
}
