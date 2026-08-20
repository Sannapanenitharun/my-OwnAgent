package discovery

import (
	"fmt"
	"testing"
)

// The relationship tests exist to defend ONE property above all others: that the
// topology is linear in entity count rather than quadratic. Everything else in
// this file supports that claim or bounds its edges.

// TestRelationshipsAreFunctional is the mechanism behind the linear bound.
//
// For a given source entity and relationship type there is at most one target.
// A second insertion cannot be stored — it is counted as a conflict and
// discarded — so |relationships| <= |entities| x |types| holds by construction
// and not by anyone remembering to apply a cap.
func TestRelationshipsAreFunctional(t *testing.T) {
	rs := newRelationSet()

	if !rs.add(relationship{Type: RelationRunsService, From: "p1", To: "svc-a", Evidence: EvidenceCgroupUnit}) {
		t.Fatal("the first relationship was rejected")
	}
	if rs.add(relationship{Type: RelationRunsService, From: "p1", To: "svc-b", Evidence: EvidenceCgroupUnit}) {
		t.Error("a second target was accepted for a functional relationship")
	}
	if rs.conflicts != 1 {
		t.Errorf("conflicts = %d, want 1; a violated functional assumption must be visible", rs.conflicts)
	}
	if rs.len() != 1 {
		t.Errorf("the set holds %d relationships, want 1", rs.len())
	}

	// The FIRST writer wins, deterministically, so a host in a conflicting state
	// reports the same edge every cycle rather than flapping between two.
	if got := rs.all()[0].To; got != "svc-a" {
		t.Errorf("target = %q, want the first writer's svc-a", got)
	}
}

func TestRelationshipsAllowDifferentTypesFromOneSource(t *testing.T) {
	// Functional means "one target per (source, TYPE)", not "one edge per
	// source". A process legitimately has a parent, a service and a container.
	rs := newRelationSet()
	rs.add(relationship{Type: RelationParentProcess, From: "p1", To: "p0"})
	rs.add(relationship{Type: RelationRunsService, From: "p1", To: "svc"})
	rs.add(relationship{Type: RelationRunsInContainer, From: "p1", To: "ctr"})

	if rs.len() != 3 {
		t.Errorf("got %d relationships, want 3", rs.len())
	}
	if rs.conflicts != 0 {
		t.Errorf("conflicts = %d, want 0", rs.conflicts)
	}
}

func TestRelationshipsRejectSelfEdges(t *testing.T) {
	// Reachable in practice: a process whose parent has exited is re-parented,
	// and on some platforms a process can transiently appear to be its own
	// parent.
	rs := newRelationSet()
	if rs.add(relationship{Type: RelationParentProcess, From: "p1", To: "p1"}) {
		t.Error("a self-edge was accepted")
	}
	if rs.add(relationship{Type: RelationParentProcess, From: "", To: "p1"}) {
		t.Error("an edge from nothing was accepted")
	}
	if rs.len() != 0 {
		t.Errorf("the set holds %d relationships, want 0", rs.len())
	}
}

// TestTopologyIsLinearNotQuadratic is the headline architectural claim, asserted
// against the shape a naive design would produce.
//
// With N processes each in a service and a container, plus N endpoints, a
// design that allowed many-to-many edges could emit O(N²). The functional
// constraint holds it to a small multiple of N.
func TestTopologyIsLinearNotQuadratic(t *testing.T) {
	for _, n := range []int{10, 100, 1000, 5000} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			rs := newRelationSet()

			procKeys := make(map[PID]string, n)
			endpointKeys := make(map[string]string, n)
			var procs []ProcessFacts
			var endpoints []EndpointFacts
			evidence := make(map[PID]cgroupEvidence, n)
			serviceKeys := map[string]string{"app.service": "svc-app"}
			containerKeys := map[string]string{"deadbeefcafe": "ctr-1"}

			for i := 0; i < n; i++ {
				pid := PID(i + 100)
				procKeys[pid] = fmt.Sprintf("proc-%d", pid)
				procs = append(procs, ProcessFacts{PID: pid, PPID: PID(100), Name: "worker"})
				evidence[pid] = cgroupEvidence{Unit: "app.service", ContainerID: "deadbeefcafe"}

				local := endpointLocalKey(ProtocolTCP, "10.0.0.1", uint16(1024+i%40000))
				endpointKeys[local] = fmt.Sprintf("ep-%d", i)
				endpoints = append(endpoints, EndpointFacts{
					Protocol: ProtocolTCP, Address: "10.0.0.1", Port: uint16(1024 + i%40000),
					OwnerPID: pid, HasOwnerPID: true, Inode: uint64(i + 1),
				})
			}

			relateProcesses(rs, procs, evidence, procKeys, serviceKeys, containerKeys, nil)
			relateEndpoints(rs, endpoints, endpointKeys, procKeys,
				map[string]string{"10.0.0.1": "iface-eth0"})

			entities := n /* processes */ + n /* endpoints */ + 1 /* service */ + 1 /* container */ + 1 /* iface */
			bound := entities * len(AllRelationTypes)
			if rs.len() > bound {
				t.Fatalf("%d relationships from %d entities exceeds the linear bound of %d",
					rs.len(), entities, bound)
			}
			// And the real figure is far below the bound: it is one parent edge,
			// one service edge and one container edge per process, plus one
			// owner edge and one interface edge per endpoint.
			if ratio := float64(rs.len()) / float64(entities); ratio > 3 {
				t.Errorf("%.2f relationships per entity; the functional constraint should keep this small", ratio)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

// TestServiceManagerEvidenceBeatsCgroupEvidence covers the precedence that keeps
// a main process labelled as such.
func TestServiceManagerEvidenceBeatsCgroupEvidence(t *testing.T) {
	rs := newRelationSet()
	procs := []ProcessFacts{{PID: 10, Name: "nginx"}}
	evidence := map[PID]cgroupEvidence{10: {Unit: "nginx.service"}}
	procKeys := map[PID]string{10: "proc-10"}
	serviceKeys := map[string]string{"nginx.service": "svc-nginx"}
	mainPIDs := map[PID]string{10: "svc-nginx"}

	relateProcesses(rs, procs, evidence, procKeys, serviceKeys, nil, mainPIDs)

	all := rs.all()
	if len(all) != 1 {
		t.Fatalf("got %d relationships, want 1: %+v", len(all), all)
	}
	if all[0].Evidence != EvidenceServiceManager {
		t.Errorf("evidence = %v, want service_manager (the stronger proof)", all[0].Evidence)
	}
	if all[0].Role != "main" {
		t.Errorf("role = %q, want main", all[0].Role)
	}
}

func TestCgroupEvidenceMarksMembershipNotMainProcess(t *testing.T) {
	rs := newRelationSet()
	procs := []ProcessFacts{{PID: 11, Name: "nginx"}}
	evidence := map[PID]cgroupEvidence{11: {Unit: "nginx.service"}}

	relateProcesses(rs, procs, evidence,
		map[PID]string{11: "proc-11"},
		map[string]string{"nginx.service": "svc-nginx"}, nil, nil)

	all := rs.all()
	if len(all) != 1 {
		t.Fatalf("got %d relationships, want 1", len(all))
	}
	if all[0].Evidence != EvidenceCgroupUnit {
		t.Errorf("evidence = %v, want cgroup_unit", all[0].Evidence)
	}
	if all[0].Role != "" {
		t.Errorf("role = %q, want empty — a worker is a member, not the main process", all[0].Role)
	}
}

// TestEdgesToUnadmittedEntitiesAreNotCreated is what keeps the topology
// referentially complete when the capacity budget bites.
func TestEdgesToUnadmittedEntitiesAreNotCreated(t *testing.T) {
	rs := newRelationSet()
	procs := []ProcessFacts{{PID: 20, PPID: 1, Name: "app"}}
	evidence := map[PID]cgroupEvidence{20: {Unit: "app.service", ContainerID: "abcdef012345"}}

	// The process is admitted; the service and container were dropped by a cap,
	// and the parent was never promoted.
	relateProcesses(rs, procs, evidence, map[PID]string{20: "proc-20"}, nil, nil, nil)

	if rs.len() != 0 {
		t.Errorf("got %d relationships pointing at entities that do not exist: %+v", rs.len(), rs.all())
	}
}

// ---------------------------------------------------------------------------
// The interface edge — the one place functionality had to be earned
// ---------------------------------------------------------------------------

// TestWildcardListenersProduceNoInterfaceEdge is the rule that stops this one
// relationship making topology quadratic.
//
// A socket bound to 0.0.0.0 listens on every interface. A host with 200
// listeners and 100 interfaces would produce 20,000 edges from that single rule,
// which is precisely the shape the whole design excludes.
func TestWildcardListenersProduceNoInterfaceEdge(t *testing.T) {
	ifaces := []InterfaceFacts{
		{Name: "eth0", Addresses: []string{"10.0.0.1/24"}},
		{Name: "eth1", Addresses: []string{"10.0.1.1/24"}},
	}
	ifaceKeys := map[string]string{"eth0": "if-eth0", "eth1": "if-eth1"}
	owners := buildAddressOwners(ifaces, ifaceKeys)

	rs := newRelationSet()
	endpoints := []EndpointFacts{
		{Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 80},
		{Protocol: ProtocolTCP6, Address: "::", Port: 443},
		{Protocol: ProtocolTCP, Address: "10.0.0.1", Port: 8080},
	}
	endpointKeys := map[string]string{
		endpointLocalKey(ProtocolTCP, "0.0.0.0", 80):    "ep-80",
		endpointLocalKey(ProtocolTCP6, "::", 443):       "ep-443",
		endpointLocalKey(ProtocolTCP, "10.0.0.1", 8080): "ep-8080",
	}
	relateEndpoints(rs, endpoints, endpointKeys, nil, owners)

	all := rs.all()
	if len(all) != 1 {
		t.Fatalf("got %d interface edges, want exactly 1 (only the specifically-bound listener): %+v",
			len(all), all)
	}
	if all[0].From != "ep-8080" || all[0].To != "if-eth0" {
		t.Errorf("edge = %s -> %s, want ep-8080 -> if-eth0", all[0].From, all[0].To)
	}
}

// TestAmbiguousAddressesProduceNoEdge covers bonded pairs, bridges and their
// members, and loopback aliases — all real configurations where one address
// appears on two interfaces. Picking one would be a guess with no evidence.
func TestAmbiguousAddressesProduceNoEdge(t *testing.T) {
	ifaces := []InterfaceFacts{
		{Name: "eth0", Addresses: []string{"10.0.0.1/24"}},
		{Name: "bond0", Addresses: []string{"10.0.0.1/24"}},
		{Name: "eth2", Addresses: []string{"10.0.2.1/24"}},
	}
	owners := buildAddressOwners(ifaces, map[string]string{
		"eth0": "if-eth0", "bond0": "if-bond0", "eth2": "if-eth2",
	})

	if _, ok := owners["10.0.0.1"]; ok {
		t.Error("an address present on two interfaces was attributed to one of them")
	}
	if got := owners["10.0.2.1"]; got != "if-eth2" {
		t.Errorf("an unambiguous address resolved to %q, want if-eth2", got)
	}
}

func TestEndpointOwnershipRecordsWhichMechanismProvedIt(t *testing.T) {
	rs := newRelationSet()
	endpoints := []EndpointFacts{
		// Linux: an inode was matched to a descriptor.
		{Protocol: ProtocolTCP, Address: "10.0.0.1", Port: 80, OwnerPID: 5, HasOwnerPID: true, Inode: 42},
		// Windows: the OS named the owner directly, so there is no inode.
		{Protocol: ProtocolTCP, Address: "10.0.0.1", Port: 81, OwnerPID: 6, HasOwnerPID: true},
	}
	endpointKeys := map[string]string{
		endpointLocalKey(ProtocolTCP, "10.0.0.1", 80): "ep-80",
		endpointLocalKey(ProtocolTCP, "10.0.0.1", 81): "ep-81",
	}
	relateEndpoints(rs, endpoints, endpointKeys, map[PID]string{5: "proc-5", 6: "proc-6"}, nil)

	byFrom := map[string]Evidence{}
	for _, r := range rs.all() {
		byFrom[r.From] = r.Evidence
	}
	if byFrom["ep-80"] != EvidenceSocketInode {
		t.Errorf("inode-proved edge carries %v, want socket_inode", byFrom["ep-80"])
	}
	if byFrom["ep-81"] != EvidenceSocketTable {
		t.Errorf("OS-reported edge carries %v, want socket_table", byFrom["ep-81"])
	}
}

// ---------------------------------------------------------------------------
// Determinism and telemetry shape
// ---------------------------------------------------------------------------

func TestRelationshipOrderIsDeterministic(t *testing.T) {
	build := func() []relationship {
		rs := newRelationSet()
		for i := 0; i < 50; i++ {
			rs.add(relationship{
				Type: RelationParentProcess,
				From: fmt.Sprintf("p%03d", i),
				To:   fmt.Sprintf("p%03d", i/2),
			})
		}
		return rs.all()
	}
	a, b := build(), build()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("relationship %d differs between runs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestRelationCountsCoverEveryTypeSoSeriesCountIsFixed(t *testing.T) {
	rs := newRelationSet()
	rs.add(relationship{Type: RelationParentProcess, From: "a", To: "b"})

	counts := rs.counts()
	if len(counts) != len(AllRelationTypes) {
		t.Errorf("counts has %d entries, want one per relation type (%d)",
			len(counts), len(AllRelationTypes))
	}
	for _, typ := range AllRelationTypes {
		if _, ok := counts[typ]; !ok {
			t.Errorf("no count reported for %v; a gauge that vanishes at zero cannot be alerted on", typ)
		}
	}
}

func TestRelationAttrsCarryNoLocalKeys(t *testing.T) {
	// Local topology keys are internal to this process, meaningless to a
	// consumer, and unbounded. What leaves is two platform identifiers plus
	// closed-set attributes.
	r := relationship{
		Type: RelationRunsService, From: "some/long/local/key", To: "another/local/key",
		Evidence: EvidenceCgroupUnit, Role: "main",
	}
	attrs := relationAttrs(r, "ent-from", "ent-to")

	for _, a := range attrs {
		if a.Value == r.From || a.Value == r.To {
			t.Errorf("attribute %q leaked a local topology key", a.Key)
		}
	}
	found := map[string]string{}
	for _, a := range attrs {
		found[a.Key] = a.Value
	}
	if found[AttrFromEntity] != "ent-from" || found[AttrToEntity] != "ent-to" {
		t.Errorf("entity identifiers were not carried: %v", found)
	}
	if found[AttrEvidence] != "cgroup_unit" {
		t.Errorf("evidence = %q, want cgroup_unit", found[AttrEvidence])
	}
}

// TestEveryEvidenceKindIsNamed guards the closed set. An unnamed member would
// render as "unknown" and make a whole class of edges untraceable.
func TestEveryEvidenceKindIsNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range AllEvidence {
		name := e.String()
		if e != EvidenceUnknown && name == "unknown" {
			t.Errorf("evidence %d has no name", int(e))
		}
		if seen[name] {
			t.Errorf("two evidence kinds share the name %q", name)
		}
		seen[name] = true
	}
	// There is deliberately no `heuristic` member. A topology assembled from a
	// mixture of proof and plausible correlation is worse than a smaller one
	// built only from proof, because a consumer cannot tell which edges to trust.
	if seen["heuristic"] || seen["inferred"] || seen["guessed"] {
		t.Error("an inference-based evidence kind exists; relationships must be proved")
	}
}

func TestEveryRelationTypeIsNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, typ := range AllRelationTypes {
		name := typ.String()
		if name == "unknown" {
			t.Errorf("relation type %d has no name", int(typ))
		}
		if seen[name] {
			t.Errorf("two relation types share the name %q", name)
		}
		seen[name] = true
	}
}
