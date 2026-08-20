package process

import (
	"context"
	"strconv"

	"github.com/obsagent/observability-agent/internal/platform"
)

// InstanceKey identifies one process INSTANCE, as opposed to one PID.
//
// This distinction is the correctness foundation of the whole module. PIDs are
// reused — on Linux the default pid_max is 32768 and a busy host cycles through
// it in minutes, on Windows PIDs are recycled aggressively — so a key of
// (host, pid) means that:
//
//	PID 1234 starts at T1, runs, accumulates 40 seconds of CPU time, exits
//	PID 1234 starts again at T2, a completely different program
//
// would be one entity to the agent. The new process would inherit the old one's
// counter baseline, and its first CPU sample would be a negative delta or, worse,
// a plausible small positive one. Its metrics would be attributed to the wrong
// executable. Its lifetime would be reported as the sum of two programs'.
//
// The start stamp is what breaks the tie, and it is used RAW rather than as a
// wall-clock time: on Linux it is jiffies since boot, so two consecutive
// instances of a recycled PID differ by at least one jiffy, while their derived
// wall-clock times could easily round to the same second.
//
// Boot is included because the raw stamp is boot-relative on Linux. Without it,
// a process started 500 jiffies after boot and another started 500 jiffies after
// the next boot share a key.
type InstanceKey struct {
	Boot  string
	PID   PID
	Start uint64
	// HasStart records whether the platform could supply a start stamp. An
	// instance without one is IDENTITY-LIMITED: it is counted in aggregates but
	// never given counter baselines and never resolved to an entity, because
	// there is no way to tell it apart from the next process to hold its PID.
	HasStart bool
}

// String renders the key for logs and for the local state map. It is NOT an
// entity ID and must never be emitted as one.
func (k InstanceKey) String() string {
	s := k.Boot + "/" + strconv.Itoa(int(k.PID))
	if k.HasStart {
		return s + "/" + strconv.FormatUint(k.Start, 10)
	}
	return s + "/?"
}

// SameInstance reports whether two keys denote the same process instance.
func (k InstanceKey) SameInstance(o InstanceKey) bool {
	return k.PID == o.PID && k.Boot == o.Boot &&
		k.HasStart == o.HasStart && k.Start == o.Start
}

// instanceKey builds the key for one observed process.
func instanceKey(boot string, info Info) InstanceKey {
	return InstanceKey{
		Boot:     boot,
		PID:      info.PID,
		Start:    info.StartRaw,
		HasStart: info.HasStartRaw,
	}
}

// entityRef builds the platform natural key for a process instance.
//
// Note what this function does NOT do: it does not hash anything, and it does
// not return an identifier. It states the facts that identify the process and
// hands them to the platform, which owns the mapping onto an EntityID. A
// collector that derived the identifier itself would fork the platform's entity
// graph the moment any other component derived it differently — and reconciling
// a forked entity graph after the fact is vastly more expensive than an
// unresolved attribute.
//
// The KEY SHAPE lives in internal/platform rather than here, and that is not
// tidiness. The discovery module also observes processes and also resolves them;
// two modules that cannot import each other, each holding its own copy of a key
// shape that must stay byte-identical forever, is a fork waiting to happen. The
// shape belongs with the EntityKind it identifies. See platform/entity.go.
//
// Every key value is bounded and non-secret. The executable NAME is included and
// the command line is not, deliberately: the name is already sanitised and
// bounded, while an argument vector could carry a credential into the platform's
// permanent entity store.
func entityRef(hostEntity string, key InstanceKey, name string) platform.EntityRef {
	return platform.ProcessRef(hostEntity, key.Boot, int64(key.PID), key.Start, name)
}

// resolver resolves process entities through the platform seam, with a cache.
//
// The cache is what makes per-process entity resolution affordable. Resolution
// is per INSTANCE, not per cycle: a process that has been running for a week is
// resolved once, and every subsequent cycle is a map lookup. In steady state on
// a stable host the number of resolutions per cycle is zero.
//
// It is bounded by the same state store that bounds everything else, because the
// resolved identifier is stored on the tracked instance rather than in a
// separate map that would need its own eviction policy.
type resolver struct {
	identity   platform.Identity
	hostEntity string

	// supported is false once the platform adapter has told us it cannot
	// resolve entities, so the module stops asking. Retrying an unsupported
	// operation once per process per cycle is how an agent turns a missing
	// capability into a CPU problem.
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
func (r *resolver) canResolve() bool {
	if !r.checked {
		_, r.supported = r.identity.(platform.EntityResolver)
		r.checked = true
	}
	return r.supported && r.hostEntity != ""
}

// resolve maps one process instance onto a platform EntityID.
//
// A failure returns the empty string and no error: the caller emits the
// observation with no process entity binding and records a diagnostic. It never
// falls back to a locally computed identifier.
func (r *resolver) resolve(ctx context.Context, key InstanceKey, name string) (string, bool) {
	if !r.canResolve() || !key.HasStart {
		return "", false
	}
	id, err := platform.ResolveEntity(ctx, r.identity, entityRef(r.hostEntity, key, name))
	if err != nil || id == "" {
		r.failures++
		return "", false
	}
	r.resolutions++
	return id, true
}
