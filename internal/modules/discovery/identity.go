package discovery

import (
	"context"

	"github.com/obsagent/observability-agent/internal/platform"
)

// resolver resolves discovered entities through the platform seam.
//
// The rule it enforces is the same one the process module enforces, and with
// twelve entity kinds in play it matters more rather than less: THE MODULE NEVER
// MINTS AN ENTITY ID. It observes a natural key, asks the platform what that key
// denotes, and accepts the answer — including "I cannot tell you", which
// degrades fidelity and never function.
//
// A collector that computed identifiers locally would fork the platform's entity
// graph the first time any other component computed one differently. With one
// kind that is a bad day; with twelve it is twelve independent forks, each
// discovered separately, months apart.
//
// Caching lives in the topology rather than here, on the entity itself. That is
// deliberate: a cache of its own would need its own eviction policy, and a
// second bounded structure that must be kept in step with the first is exactly
// the kind of state that leaks. Binding the resolved ID to the entity means it
// is released when the entity is.
type resolver struct {
	identity   platform.Identity
	hostEntity string

	// supported is false once the platform adapter has told us it cannot
	// resolve entities, so the module stops asking. Retrying an unsupported
	// operation once per entity per cycle is how a missing capability becomes a
	// CPU problem.
	supported bool
	checked   bool

	resolutions int64
	failures    int64
}

func newResolver(identity platform.Identity) *resolver {
	return &resolver{identity: identity, supported: true}
}

func (r *resolver) setHostEntity(id string) { r.hostEntity = id }

// canResolve reports whether entity resolution is available at all.
//
// It requires a resolved HOST, not just a resolver: every entity this module
// discovers hangs off the host, and an entity resolved without its parent would
// be an orphan in the platform's graph. Reporting "cannot resolve" is the honest
// answer, and it is why an agent with no configured host identity still collects
// and still reports a complete local topology — it simply cannot name it.
func (r *resolver) canResolve() bool {
	if !r.checked {
		_, r.supported = r.identity.(platform.EntityResolver)
		r.checked = true
	}
	return r.supported && r.hostEntity != ""
}

// resolve maps one natural key onto a platform EntityID.
//
// A failure returns the empty string and no error: the caller records a
// diagnostic and emits the entity with no binding. It never falls back to a
// locally computed identifier.
func (r *resolver) resolve(ctx context.Context, ref platform.EntityRef) (string, bool) {
	if !r.canResolve() {
		return "", false
	}
	id, err := platform.ResolveEntity(ctx, r.identity, ref)
	if err != nil || id == "" {
		r.failures++
		return "", false
	}
	r.resolutions++
	return id, true
}
