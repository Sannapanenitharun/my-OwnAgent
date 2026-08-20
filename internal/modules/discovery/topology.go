package discovery

import (
	"context"
	"sort"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The bounded topology.
//
// This is the module's memory model and its incremental-emission engine, and the
// two are the same object because they answer the same question: what does this
// host look like now, and what is different from last time.
//
// Three properties are non-negotiable, and the scale and churn tests exist to
// prove them:
//
//   - It never grows without bound. Entities are admitted against per-kind caps
//     and a global cap, deterministically, and what does not fit is counted.
//   - It never retains a vanished entity. An entity not seen in a cycle is
//     removed in that cycle, not on a timer.
//   - A stable host converges to emitting NOTHING. Fingerprints make "unchanged"
//     cheap to establish, and unchanged entities produce no output at all.

// changeKind classifies what happened to an entity in a cycle.
type changeKind int

const (
	changeNone changeKind = iota
	// changeAdded is an entity observed for the first time.
	changeAdded
	// changeUpdated is a tracked entity whose attributes differ from last cycle.
	changeUpdated
	// changeRemoved is a tracked entity that was not observed this cycle.
	changeRemoved
)

func (c changeKind) String() string {
	switch c {
	case changeAdded:
		return "added"
	case changeUpdated:
		return "updated"
	case changeRemoved:
		return "removed"
	default:
		return "none"
	}
}

// change is one entity transition worth telling a consumer about.
type change struct {
	Kind   changeKind
	Entity *entity
}

// candidate is one entity a source proposed, before capacity is applied.
//
// It carries the platform natural key alongside the local key because the two
// are needed at different moments — the local key to recognise the entity across
// cycles, the natural key to ask the platform what it is — and computing the
// natural key twice would mean two chances to compute it differently.
type candidate struct {
	kind platform.EntityKind
	key  string
	ref  platform.EntityRef
	// attrs must already be sanitised and bounded by the caller. The topology
	// sorts them, because a stable fingerprint depends on it.
	attrs []platform.Attr
	// resolvedID short-circuits resolution for entities whose identifier is
	// already known. Exactly one kind uses it: the HOST, whose identifier came
	// from Identity.HostID before the cycle began. Asking the platform to
	// resolve the identifier it just handed us would be a round trip to learn
	// nothing, and would fail on any adapter that implements Identity but not
	// EntityResolver.
	resolvedID string
	// rank orders candidates of the same kind when capacity is short. LOWER IS
	// KEPT. Builders choose it to mean something domain-specific: a process
	// ranks by PID, so a host over its cap keeps the low-numbered system
	// services and sheds the churn.
	rank int
}

// kindPriority orders entity kinds when the GLOBAL cap is short.
//
// The ordering is not a preference, it is a dependency order. Singleton context
// entities — the host's runtime, its cloud platform, its pod — cost almost
// nothing and are what everything else is interpreted against, so they are kept
// first. Services and containers come next because they are the structure an
// operator actually navigates. Processes come last because there are the most of
// them and because the process module already reports them in detail.
func kindPriority(k platform.EntityKind) int {
	switch k {
	case platform.EntityKindRuntime, platform.EntityKindCloudInstance,
		platform.EntityKindKubernetesPod:
		return 0
	case platform.EntityKindService:
		return 1
	case platform.EntityKindContainer:
		return 2
	case platform.EntityKindNetworkEndpoint:
		return 3
	case platform.EntityKindNetworkInterface:
		return 4
	case platform.EntityKindFilesystem:
		return 5
	case platform.EntityKindProcess:
		return 6
	default:
		return 7
	}
}

// topology is the bounded entity table.
type topology struct {
	entities map[string]*entity
	cycle    uint64

	// Lifetime counters, all monotonic.
	added        int64
	updated      int64
	removed      int64
	droppedByCap int64
}

func newTopology() *topology {
	return &topology{entities: make(map[string]*entity, 128)}
}

func (t *topology) size() int { return len(t.entities) }

// countsByKind returns the number of tracked entities per kind, with an entry
// for every kind so that the emitted series count is fixed.
func (t *topology) countsByKind() map[platform.EntityKind]int {
	out := make(map[platform.EntityKind]int, len(platform.AllEntityKinds))
	for _, k := range platform.AllEntityKinds {
		out[k] = 0
	}
	for _, e := range t.entities {
		out[e.kind]++
	}
	return out
}

// reconcile folds one cycle's candidates into the table and reports what changed.
//
// The order of operations matters. Capacity is applied to the CANDIDATES, before
// anything is stored, so that an over-capacity host never transiently allocates
// the entities it is about to reject. Removal happens last, after every
// candidate has been seen, because an entity is only known to be gone once the
// whole cycle has failed to mention it.
func (t *topology) reconcile(candidates []candidate, caps capacity) []change {
	t.cycle++

	admitted, dropped := caps.apply(candidates)
	t.droppedByCap += int64(dropped)

	changes := make([]change, 0, 16)

	for i := range admitted {
		c := &admitted[i]
		sortAttrs(c.attrs)
		fp := fingerprint(c.kind, c.key, c.attrs)

		existing, had := t.entities[c.key]
		if !had {
			e := &entity{
				kind:       c.kind,
				key:        c.key,
				attrs:      c.attrs,
				fp:         fp,
				cycle:      t.cycle,
				firstCycle: t.cycle,
			}
			if c.resolvedID != "" {
				e.entityID = c.resolvedID
				e.tried = true
			}
			t.entities[c.key] = e
			t.added++
			changes = append(changes, change{Kind: changeAdded, Entity: e})
			continue
		}

		existing.cycle = t.cycle
		if existing.fp == fp {
			// Unchanged. This is the common case on a stable host and it must
			// cost nothing: no allocation, no event, no resolution.
			continue
		}
		existing.attrs = c.attrs
		existing.fp = fp
		t.updated++
		changes = append(changes, change{Kind: changeUpdated, Entity: existing})
	}

	// Anything not observed this cycle is gone.
	for key, e := range t.entities {
		if e.cycle == t.cycle {
			continue
		}
		delete(t.entities, key)
		t.removed++
		changes = append(changes, change{Kind: changeRemoved, Entity: e})
	}

	// Deterministic order, so that two runs against the same host produce the
	// same event sequence and a diff of two cycles shows only real differences.
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Entity.key < b.Entity.key
	})
	return changes
}

// snapshot returns every tracked entity in a deterministic order. It is what a
// full resync emits.
func (t *topology) snapshot() []*entity {
	out := make([]*entity, 0, len(t.entities))
	for _, e := range t.entities {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// lookup returns the tracked entity for a local key.
func (t *topology) lookup(key string) (*entity, bool) {
	e, ok := t.entities[key]
	return e, ok
}

// capacity is the set of caps applied to one cycle's candidates.
type capacity struct {
	// Total bounds the whole table.
	Total int
	// PerKind bounds each kind separately. A per-kind cap is what stops one
	// noisy domain — ten thousand containers on a busy node — from consuming
	// the whole budget and evicting the services an operator actually navigates
	// by.
	PerKind map[platform.EntityKind]int
}

// apply enforces the caps deterministically and reports how many candidates did
// not fit.
//
// Nothing is sampled and nothing is dropped silently. The ordering is total —
// kind priority, then the builder's rank, then the key — so a host permanently
// over its cap tracks THE SAME entities every cycle. That property is what makes
// an over-capacity host merely incomplete rather than actively misleading: a
// table that reported a different subset each cycle would show every entity
// flapping between existing and not existing.
func (c capacity) apply(in []candidate) (kept []candidate, dropped int) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if pa, pb := kindPriority(a.kind), kindPriority(b.kind); pa != pb {
			return pa < pb
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.key < b.key
	})

	perKind := make(map[platform.EntityKind]int, len(c.PerKind))
	kept = in[:0]
	for _, cand := range in {
		if limit, ok := c.PerKind[cand.kind]; ok && limit > 0 && perKind[cand.kind] >= limit {
			dropped++
			continue
		}
		if c.Total > 0 && len(kept) >= c.Total {
			dropped++
			continue
		}
		perKind[cand.kind]++
		kept = append(kept, cand)
	}
	return kept, dropped
}

// resolveEntities binds admitted entities to platform EntityIDs.
//
// Resolution is per ENTITY, not per cycle, and is cached for the entity's life.
// A host whose topology is stable resolves nothing after its first cycle, which
// is what makes resolution affordable at all — and is the same property that
// made per-process resolution affordable in the process module.
//
// A failure binds nothing and records the fact. It never falls back to a locally
// computed identifier: an invented ID forks the platform's entity graph, and
// with twelve kinds in play it would fork it twelve ways.
func (t *topology) resolveEntities(ctx context.Context, res *resolver, budget int, cands []candidate) (resolved, unresolved int) {
	// The natural key lives on the candidate, not on the entity, so resolution
	// walks the candidates and writes through to the tracked entity. Retaining
	// the ref on every entity would cost an EntityRef per entity for a value
	// used at most once in the entity's life.
	for i := range cands {
		c := &cands[i]
		e, ok := t.entities[c.key]
		if !ok || e.tried || c.ref.Kind == "" {
			continue
		}
		if budget <= 0 || ctx.Err() != nil {
			return resolved, unresolved
		}
		budget--
		e.tried = true
		if id, ok := res.resolve(ctx, c.ref); ok {
			e.entityID = id
			resolved++
			continue
		}
		unresolved++
	}
	return resolved, unresolved
}

// entityID returns the platform identifier for a local key, if one is bound.
func (t *topology) entityID(key string) (string, bool) {
	e, ok := t.entities[key]
	if !ok || e.entityID == "" {
		return "", false
	}
	return e.entityID, true
}
