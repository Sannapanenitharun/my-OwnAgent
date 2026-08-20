package discovery

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cand(kind platform.EntityKind, key string, attrs ...platform.Attr) candidate {
	return candidate{kind: kind, key: entityKey(kind, key), attrs: attrs}
}

func noCaps() capacity { return capacity{} }

func changeKinds(changes []change) map[changeKind]int {
	out := map[changeKind]int{}
	for _, c := range changes {
		out[c.Kind]++
	}
	return out
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

func TestTopologyReportsAddChangeAndRemove(t *testing.T) {
	topo := newTopology()

	first := topo.reconcile([]candidate{
		cand(platform.EntityKindService, "nginx", platform.A(AttrState, "running")),
		cand(platform.EntityKindService, "sshd", platform.A(AttrState, "running")),
	}, noCaps())
	if got := changeKinds(first); got[changeAdded] != 2 {
		t.Fatalf("first cycle: %v, want 2 added", got)
	}

	// Same facts again: nothing changed, nothing emitted.
	second := topo.reconcile([]candidate{
		cand(platform.EntityKindService, "nginx", platform.A(AttrState, "running")),
		cand(platform.EntityKindService, "sshd", platform.A(AttrState, "running")),
	}, noCaps())
	if len(second) != 0 {
		t.Errorf("an unchanged host produced %d changes: %+v", len(second), second)
	}

	// One attribute differs, one entity is gone.
	third := topo.reconcile([]candidate{
		cand(platform.EntityKindService, "nginx", platform.A(AttrState, "failed")),
	}, noCaps())
	got := changeKinds(third)
	if got[changeUpdated] != 1 || got[changeRemoved] != 1 || got[changeAdded] != 0 {
		t.Errorf("third cycle: %v, want 1 updated and 1 removed", got)
	}
	if topo.size() != 1 {
		t.Errorf("topology holds %d entities, want 1", topo.size())
	}
}

// TestTopologyIsStableAgainstAttributeOrder is the defect that would turn an
// incremental discovery system into a full one that also lies about what
// changed.
//
// A source that enumerated addresses in a different order each cycle would make
// every interface look modified, every cycle, forever. The fingerprint must
// depend on CONTENT, not on the order facts arrived in.
func TestTopologyIsStableAgainstAttributeOrder(t *testing.T) {
	topo := newTopology()

	topo.reconcile([]candidate{cand(platform.EntityKindNetworkInterface, "eth0",
		platform.A(AttrAddress, "10.0.0.1"),
		platform.A(AttrUp, "true"),
		platform.A(AttrMTU, "1500"))}, noCaps())

	shuffled := topo.reconcile([]candidate{cand(platform.EntityKindNetworkInterface, "eth0",
		platform.A(AttrMTU, "1500"),
		platform.A(AttrAddress, "10.0.0.1"),
		platform.A(AttrUp, "true"))}, noCaps())

	if len(shuffled) != 0 {
		t.Errorf("reordering the same attributes produced %d changes: %+v", len(shuffled), shuffled)
	}
}

func TestTopologyRemovesVanishedEntitiesImmediately(t *testing.T) {
	topo := newTopology()
	topo.reconcile([]candidate{cand(platform.EntityKindContainer, "abc")}, noCaps())

	changes := topo.reconcile(nil, noCaps())
	if len(changes) != 1 || changes[0].Kind != changeRemoved {
		t.Fatalf("got %+v, want one removal", changes)
	}
	if topo.size() != 0 {
		t.Errorf("topology retained %d entities after everything vanished", topo.size())
	}
	// Retention on a timer would leave state behind on a churning host. There is
	// deliberately no timer: the entity is released in the cycle its
	// disappearance is noticed.
	if _, ok := topo.lookup(entityKey(platform.EntityKindContainer, "abc")); ok {
		t.Error("a removed entity is still addressable")
	}
}

func TestTopologyChangesAreDeterministicallyOrdered(t *testing.T) {
	// Go randomises map iteration. Without an explicit sort, two runs against
	// the same host would produce different event sequences, and a diff of two
	// cycles would show noise instead of real differences.
	build := func() []change {
		topo := newTopology()
		var cands []candidate
		for i := 0; i < 20; i++ {
			cands = append(cands, cand(platform.EntityKindService, "svc"+strconv.Itoa(i)))
		}
		topo.reconcile(cands, noCaps())
		return topo.reconcile(nil, noCaps())
	}

	first, second := build(), build()
	if len(first) != len(second) {
		t.Fatalf("runs produced %d and %d changes", len(first), len(second))
	}
	for i := range first {
		if first[i].Entity.key != second[i].Entity.key {
			t.Fatalf("change %d differs between runs: %q vs %q",
				i, first[i].Entity.key, second[i].Entity.key)
		}
	}
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

func TestCapacityIsDeterministicAcrossCycles(t *testing.T) {
	// A host permanently over its cap must track THE SAME entities every cycle.
	// A table that reported a different subset each time would show every entity
	// flapping between existing and not existing — worse than reporting nothing.
	caps := capacity{Total: 5}
	var cands []candidate
	for i := 0; i < 50; i++ {
		c := cand(platform.EntityKindService, fmt.Sprintf("svc%03d", i))
		c.rank = i
		cands = append(cands, c)
	}

	topo := newTopology()
	topo.reconcile(append([]candidate(nil), cands...), caps)
	firstKeys := keysOf(topo)

	for cycle := 0; cycle < 5; cycle++ {
		changes := topo.reconcile(append([]candidate(nil), cands...), caps)
		if len(changes) != 0 {
			t.Fatalf("cycle %d produced %d changes on identical input: %+v",
				cycle, len(changes), changes)
		}
	}
	if got := keysOf(topo); !equalStringSets(firstKeys, got) {
		t.Errorf("the tracked set changed between cycles:\n first = %v\n now   = %v", firstKeys, got)
	}
	if topo.size() != 5 {
		t.Errorf("topology holds %d entities, want the cap of 5", topo.size())
	}
	if topo.droppedByCap == 0 {
		t.Error("dropped entities were not counted; nothing may be dropped silently")
	}
}

// TestPerKindCapsProtectOtherKinds is why per-kind caps exist at all.
//
// A build node that starts ten thousand containers must not push out the
// services, filesystems and endpoints an operator navigates by. Without a
// per-kind cap the topology stays within its global limit and becomes useless.
func TestPerKindCapsProtectOtherKinds(t *testing.T) {
	caps := capacity{
		Total: 1000,
		PerKind: map[platform.EntityKind]int{
			platform.EntityKindContainer: 10,
			platform.EntityKindService:   50,
		},
	}

	var cands []candidate
	for i := 0; i < 5000; i++ {
		cands = append(cands, cand(platform.EntityKindContainer, fmt.Sprintf("c%05d", i)))
	}
	for i := 0; i < 20; i++ {
		cands = append(cands, cand(platform.EntityKindService, fmt.Sprintf("svc%02d", i)))
	}

	topo := newTopology()
	topo.reconcile(cands, caps)

	counts := topo.countsByKind()
	if counts[platform.EntityKindContainer] != 10 {
		t.Errorf("containers = %d, want the per-kind cap of 10", counts[platform.EntityKindContainer])
	}
	if counts[platform.EntityKindService] != 20 {
		t.Errorf("services = %d, want all 20 — the container flood must not evict them",
			counts[platform.EntityKindService])
	}
}

func TestCapacityKeepsHighPriorityKindsFirst(t *testing.T) {
	// The global cap is short enough that only the singleton context entities
	// fit. They must be the ones that survive: everything else is interpreted
	// against them.
	caps := capacity{Total: 2}
	cands := []candidate{
		cand(platform.EntityKindProcess, "p1"),
		cand(platform.EntityKindFilesystem, "/"),
		cand(platform.EntityKindRuntime, "host"),
		cand(platform.EntityKindCloudInstance, "aws"),
		cand(platform.EntityKindService, "nginx"),
	}

	topo := newTopology()
	topo.reconcile(cands, caps)

	counts := topo.countsByKind()
	if counts[platform.EntityKindRuntime] != 1 || counts[platform.EntityKindCloudInstance] != 1 {
		t.Errorf("the context entities were evicted: %v", counts)
	}
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

func TestResolutionIsCachedForTheEntityLifetime(t *testing.T) {
	// A stable host must resolve NOTHING after its first cycle. Resolution is
	// per entity, not per cycle, and that is what makes it affordable.
	id := &countingIdentity{Identity: inproc.NewIdentity("a", "t", "host-1")}
	res := newResolver(id)
	res.setHostEntity("host-1")

	topo := newTopology()
	cands := []candidate{
		{kind: platform.EntityKindService, key: entityKey(platform.EntityKindService, "nginx"),
			ref: serviceRef("host-1", ServiceKindSystemd, "nginx.service")},
	}

	topo.reconcile(cands, noCaps())
	topo.resolveEntities(context.Background(), res, 100, cands)
	afterFirst := id.calls

	for i := 0; i < 5; i++ {
		topo.reconcile(cands, noCaps())
		topo.resolveEntities(context.Background(), res, 100, cands)
	}
	if id.calls != afterFirst {
		t.Errorf("resolution ran %d times after the first cycle; a stable host must resolve nothing",
			id.calls-afterFirst)
	}
	if _, ok := topo.entityID(cands[0].key); !ok {
		t.Error("the entity was not bound to an identifier")
	}
}

func TestResolutionFailureBindsNothingAndInventsNothing(t *testing.T) {
	// An adapter that cannot resolve must leave the entity unbound. Falling back
	// to a locally computed identifier would fork the platform's entity graph —
	// with twelve kinds in play, twelve ways.
	res := newResolver(&nonResolvingIdentity{})
	res.setHostEntity("host-1")

	topo := newTopology()
	cands := []candidate{
		{kind: platform.EntityKindService, key: entityKey(platform.EntityKindService, "nginx"),
			ref: serviceRef("host-1", ServiceKindSystemd, "nginx.service")},
	}
	topo.reconcile(cands, noCaps())
	_, unresolved := topo.resolveEntities(context.Background(), res, 100, cands)

	if unresolved != 1 {
		t.Errorf("unresolved = %d, want 1", unresolved)
	}
	if id, ok := topo.entityID(cands[0].key); ok {
		t.Errorf("an identifier was invented for an unresolvable entity: %q", id)
	}
}

func TestResolutionRespectsItsPerCycleBudget(t *testing.T) {
	id := &countingIdentity{Identity: inproc.NewIdentity("a", "t", "host-1")}
	res := newResolver(id)
	res.setHostEntity("host-1")

	topo := newTopology()
	var cands []candidate
	for i := 0; i < 100; i++ {
		name := "svc" + strconv.Itoa(i)
		cands = append(cands, candidate{
			kind: platform.EntityKindService,
			key:  entityKey(platform.EntityKindService, name),
			ref:  serviceRef("host-1", ServiceKindSystemd, name),
		})
	}
	topo.reconcile(cands, noCaps())
	resolved, _ := topo.resolveEntities(context.Background(), res, 10, cands)

	if resolved != 10 {
		t.Errorf("resolved %d entities, want the budget of 10", resolved)
	}
}

func TestHostEntityIsNeverResolved(t *testing.T) {
	// The host identifier came from Identity.HostID before the cycle began.
	// Asking the platform to resolve it would be a round trip to learn nothing,
	// and would fail on an adapter that implements Identity but not
	// EntityResolver.
	id := &countingIdentity{Identity: inproc.NewIdentity("a", "t", "host-1")}
	res := newResolver(id)
	res.setHostEntity("host-1")

	topo := newTopology()
	cands := []candidate{{
		kind:       platform.EntityKindHost,
		key:        entityKey(platform.EntityKindHost, "host-1"),
		resolvedID: "host-1",
	}}
	topo.reconcile(cands, noCaps())
	topo.resolveEntities(context.Background(), res, 100, cands)

	if id.calls != 0 {
		t.Errorf("the host entity was sent for resolution %d times", id.calls)
	}
	if got, ok := topo.entityID(cands[0].key); !ok || got != "host-1" {
		t.Errorf("host entity ID = %q (%v), want host-1", got, ok)
	}
}

// ---------------------------------------------------------------------------
// Keys and fingerprints
// ---------------------------------------------------------------------------

// TestEntityKeysCannotCollideAcrossComponentBoundaries is a subtle but real
// source of merged entities in systems that join key parts naively.
func TestEntityKeysCannotCollideAcrossComponentBoundaries(t *testing.T) {
	a := entityKey(platform.EntityKindService, "a/b", "c")
	b := entityKey(platform.EntityKindService, "a", "b/c")
	if a == b {
		t.Errorf("two different key component splits produced the same key: %q", a)
	}
}

func TestEntityKeysAreKindScoped(t *testing.T) {
	// A service named "docker" and a container named "docker" are two entities.
	svc := entityKey(platform.EntityKindService, "docker")
	ctr := entityKey(platform.EntityKindContainer, "docker")
	if svc == ctr {
		t.Errorf("a service and a container with the same name share a key: %q", svc)
	}
}

func TestFingerprintDependsOnContentNotConcatenation(t *testing.T) {
	// Without a separator byte, ("ab","c") and ("a","bc") hash identically — so
	// two genuinely different attribute sets would look unchanged.
	a := fingerprint(platform.EntityKindService, "k", []platform.Attr{platform.A("ab", "c")})
	b := fingerprint(platform.EntityKindService, "k", []platform.Attr{platform.A("a", "bc")})
	if a == b {
		t.Error("attribute sets that differ only in where the boundary falls hash identically")
	}
}

func TestProcessNaturalKeyComesFromThePlatform(t *testing.T) {
	// The process module and this module both resolve process entities. If their
	// natural keys differed, the platform would mint two identifiers for every
	// process on the host. The shape lives in internal/platform for exactly that
	// reason, and this asserts the builder uses it.
	ref := platform.ProcessRef("host-1", "boot-9", 1234, 987654, "nginx")
	if ref.Kind != platform.EntityKindProcess {
		t.Errorf("kind = %q", ref.Kind)
	}
	if ref.Parent != "host-1" {
		t.Errorf("parent = %q, want host-1", ref.Parent)
	}
	want := []platform.Attr{
		platform.A("boot", "boot-9"),
		platform.A("pid", "1234"),
		platform.A("start", "987654"),
		platform.A("executable", "nginx"),
	}
	if len(ref.Keys) != len(want) {
		t.Fatalf("got %d key components, want %d", len(ref.Keys), len(want))
	}
	for i := range want {
		if ref.Keys[i] != want[i] {
			t.Errorf("key %d = %v, want %v", i, ref.Keys[i], want[i])
		}
	}
	// The command line must never be a key component: it is attacker-controlled,
	// unbounded, and routinely carries credentials into a store that may keep it
	// forever.
	for _, k := range ref.Keys {
		if strings.Contains(k.Key, "cmd") || strings.Contains(k.Key, "arg") {
			t.Errorf("the process natural key contains %q", k.Key)
		}
	}
}

func TestPodKeyPrefersUIDOverName(t *testing.T) {
	// namespace/name is reused across pod generations: a Deployment rollout
	// produces a new pod from the same template. Keying on the name would merge
	// every generation into one entity with an impossible lifetime.
	withUID := podRef("h", "default", "web-abc", "uid-1")
	if len(withUID.Keys) != 1 || withUID.Keys[0].Key != "uid" {
		t.Errorf("with a UID the key is %v, want uid alone", withUID.Keys)
	}
	// Two generations of the same Deployment must be two entities.
	gen1 := podRef("h", "default", "web-abc", "uid-1")
	gen2 := podRef("h", "default", "web-abc", "uid-2")
	if gen1.Keys[0] == gen2.Keys[0] {
		t.Error("two pod generations share a natural key")
	}

	withoutUID := podRef("h", "default", "web-abc", "")
	if len(withoutUID.Keys) != 2 {
		t.Errorf("without a UID the key is %v, want namespace and pod", withoutUID.Keys)
	}
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type countingIdentity struct {
	*inproc.Identity
	calls int
}

func (c *countingIdentity) ResolveEntity(ctx context.Context, ref platform.EntityRef) (string, error) {
	c.calls++
	return c.Identity.ResolveEntity(ctx, ref)
}

// nonResolvingIdentity implements Identity but NOT EntityResolver, which is the
// shape of every adapter written before the resolver extension existed.
type nonResolvingIdentity struct{}

func (nonResolvingIdentity) AgentID(context.Context) (string, error)  { return "a", nil }
func (nonResolvingIdentity) TenantID(context.Context) (string, error) { return "t", nil }
func (nonResolvingIdentity) HostID(context.Context) (string, error)   { return "host-1", nil }

func keysOf(t *topology) []string {
	out := make([]string, 0, t.size())
	for k := range t.entities {
		out = append(out, k)
	}
	return out
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
