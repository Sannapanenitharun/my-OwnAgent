package discovery

import (
	"sort"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The relationship engine.
//
// THIS FILE CONTAINS THE PHASE'S CENTRAL BOUND, so it is worth stating plainly
// before any code.
//
// The obvious fear about topology is quadratic growth: N entities admit N²
// relationships, so a host with 10,000 entities could produce 100,000,000 edges
// and any cap on that number is arbitrary. Discovery systems that hit this
// problem usually respond by sampling edges or by capping fan-out, and both
// answers are bad — a sampled topology is a topology nobody can trust, and a
// capped fan-out silently omits the one edge someone needed.
//
// This module does not need either answer, because EVERY RELATIONSHIP IT EMITS
// IS FUNCTIONAL: for a given source entity and relationship type there is AT
// MOST ONE target. A process has one parent, belongs to at most one service, and
// runs in at most one container. An endpoint has at most one owning process. A
// container is in at most one pod. That is not a policy applied to the data; it
// is a property of the things themselves, and it means
//
//	|relationships| <= |entities| x |relationship types|
//
// which is LINEAR in entity count with a constant of six. The bound is enforced
// mechanically by relationSet below, which refuses a second target for a pair it
// already has, counts the conflict, and keeps the deterministic winner — so a
// future change that introduced a non-functional relationship would fail a test
// rather than quietly making topology quadratic.
//
// WHAT WOULD BREAK IT. Network flows. A connection is a relationship between two
// endpoints and it is emphatically not functional: one endpoint has thousands of
// peers, the peer set changes every second, and the peers are third parties. If
// a later phase adds flows, it needs its own aggregation model — flows rolled up
// by peer SERVICE rather than peer address, exactly as Phase 3 rolled processes
// up by executable — and it must not reach for this file's model. That is why
// connections are out of scope here rather than half-implemented here.

// RelationType is a kind of relationship. The set is CLOSED, which is what makes
// the linear bound a fixed constant rather than something that grows whenever
// somebody adds an edge type.
type RelationType int

const (
	// RelationParentProcess links a process to the process that started it.
	RelationParentProcess RelationType = iota
	// RelationRunsService links a process to the managed service it belongs to.
	RelationRunsService
	// RelationRunsInContainer links a process to its container.
	RelationRunsInContainer
	// RelationContainerInPod links a container to its Kubernetes pod.
	RelationContainerInPod
	// RelationEndpointOwnedBy links a listening socket to the process holding it.
	RelationEndpointOwnedBy
	// RelationEndpointBoundTo links a listening socket to the network interface
	// carrying its address.
	RelationEndpointBoundTo
)

// AllRelationTypes is every type, in a stable order. Tests use it to assert the
// set is closed, and the emitter uses it to produce a fixed series count.
var AllRelationTypes = []RelationType{
	RelationParentProcess, RelationRunsService, RelationRunsInContainer,
	RelationContainerInPod, RelationEndpointOwnedBy, RelationEndpointBoundTo,
}

func (r RelationType) String() string {
	switch r {
	case RelationParentProcess:
		return "parent_process"
	case RelationRunsService:
		return "runs_service"
	case RelationRunsInContainer:
		return "runs_in_container"
	case RelationContainerInPod:
		return "container_in_pod"
	case RelationEndpointOwnedBy:
		return "endpoint_owned_by"
	case RelationEndpointBoundTo:
		return "endpoint_bound_to"
	default:
		return "unknown"
	}
}

// Evidence names the MECHANISM that proved a relationship.
//
// Every relationship carries one, and that is a correctness feature rather than
// a debugging nicety. A topology assembled from a mixture of hard evidence and
// plausible correlation is worse than a smaller one built only from hard
// evidence, because a consumer cannot tell which edges to trust. Carrying the
// mechanism makes the distinction machine-readable: an operator can ask for only
// the edges proved by a kernel structure, and can see immediately that a
// relationship came from a cgroup path rather than from a name that looked
// similar.
//
// There is no `heuristic` member, and there is deliberately no way to add one
// without editing this closed set.
type Evidence int

const (
	EvidenceUnknown Evidence = iota
	// EvidencePPID is the kernel-reported parent process ID.
	EvidencePPID
	// EvidenceCgroupUnit is a systemd unit named in a process's cgroup path.
	EvidenceCgroupUnit
	// EvidenceCgroupContainer is a container ID in a process's cgroup path.
	EvidenceCgroupContainer
	// EvidenceCgroupPod is a Kubernetes pod UID in a cgroup path.
	EvidenceCgroupPod
	// EvidenceServiceManager is the service manager's own report of a service's
	// main process — systemd's MainPID, the SCM's process ID.
	EvidenceServiceManager
	// EvidenceSocketInode is a socket inode matched to a file descriptor.
	EvidenceSocketInode
	// EvidenceSocketTable is an owning PID reported directly by the OS in its
	// socket table, as Windows does.
	EvidenceSocketTable
	// EvidenceInterfaceAddress is a listener's bind address matching exactly one
	// interface address.
	EvidenceInterfaceAddress
	// EvidenceDownwardAPI is the agent's own pod context, supplied by the
	// container platform through the environment and the mounted namespace file.
	EvidenceDownwardAPI
)

// AllEvidence is every evidence kind, in a stable order.
var AllEvidence = []Evidence{
	EvidenceUnknown, EvidencePPID, EvidenceCgroupUnit, EvidenceCgroupContainer,
	EvidenceCgroupPod, EvidenceServiceManager, EvidenceSocketInode,
	EvidenceSocketTable, EvidenceInterfaceAddress, EvidenceDownwardAPI,
}

func (e Evidence) String() string {
	switch e {
	case EvidencePPID:
		return "ppid"
	case EvidenceCgroupUnit:
		return "cgroup_unit"
	case EvidenceCgroupContainer:
		return "cgroup_container"
	case EvidenceCgroupPod:
		return "cgroup_pod"
	case EvidenceServiceManager:
		return "service_manager"
	case EvidenceSocketInode:
		return "socket_inode"
	case EvidenceSocketTable:
		return "socket_table"
	case EvidenceInterfaceAddress:
		return "interface_address"
	case EvidenceDownwardAPI:
		return "downward_api"
	default:
		return "unknown"
	}
}

// relationship is one edge of the topology, expressed in LOCAL entity keys.
//
// Local keys rather than EntityIDs, because a relationship is discovered before
// either end is necessarily resolved. The emitter looks both ends up at emission
// time and omits the edge if either is unresolved — an edge between two
// identifiers the platform does not recognise is not a useful thing to send.
type relationship struct {
	Type     RelationType
	From     string
	To       string
	Evidence Evidence
	// Role is an optional bounded qualifier: "main" for a service's primary
	// process. It carries the distinction between "this IS the service" and
	// "this belongs to the service" without needing a second relationship type.
	Role string
}

// relationSet accumulates relationships while ENFORCING functionality.
//
// This type is where the linear bound stops being an argument and becomes a
// mechanism. Every insertion is keyed by (source, type), so a second target for
// a pair that already has one cannot be stored: it is counted as a conflict and
// discarded. Two consequences follow, and both are intended.
//
// First, the relationship count is bounded by construction, not by a cap
// somebody has to remember to apply.
//
// Second, a conflict is a SIGNAL. If evidence ever says a process belongs to two
// services, that means the evidence is being misread — and the conflict counter
// surfaces it instead of letting the topology silently gain an edge that makes
// it quadratic. The counter is exposed in Statistics for exactly that reason.
type relationSet struct {
	byKey map[relationKey]relationship
	// conflicts counts insertions rejected because the pair already had a
	// target. A non-zero value means a functional assumption is being violated
	// somewhere and wants investigating.
	conflicts int64
}

type relationKey struct {
	from string
	typ  RelationType
}

func newRelationSet() *relationSet {
	return &relationSet{byKey: make(map[relationKey]relationship, 64)}
}

// add records a relationship, or counts a conflict if the pair already has one.
//
// The FIRST writer wins, and callers add in a fixed order, so the outcome is
// deterministic: a host in a conflicting state reports the same edge every
// cycle rather than flapping between two.
func (rs *relationSet) add(r relationship) bool {
	if r.From == "" || r.To == "" || r.From == r.To {
		// A self-edge is never meaningful here, and it is reachable: a process
		// whose parent has exited is re-parented, and on some platforms a
		// process can transiently appear to be its own parent.
		return false
	}
	k := relationKey{from: r.From, typ: r.Type}
	if existing, ok := rs.byKey[k]; ok {
		if existing.To != r.To {
			rs.conflicts++
		}
		return false
	}
	rs.byKey[k] = r
	return true
}

func (rs *relationSet) len() int { return len(rs.byKey) }

// all returns the relationships in a deterministic order.
//
// Sorted, because the emitter's output must not depend on Go's randomised map
// iteration: an operator diffing two cycles should see the changes and nothing
// else.
func (rs *relationSet) all() []relationship {
	out := make([]relationship, 0, len(rs.byKey))
	for _, r := range rs.byKey {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out
}

// counts returns the number of relationships of each type, for telemetry. The
// result has one entry per type in AllRelationTypes, so the series count is
// fixed regardless of what is on the host.
func (rs *relationSet) counts() map[RelationType]int {
	out := make(map[RelationType]int, len(AllRelationTypes))
	for _, t := range AllRelationTypes {
		out[t] = 0
	}
	for _, r := range rs.byKey {
		out[r.Type]++
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction. Each function takes facts plus the index of entities that were
// actually admitted, and emits edges only where BOTH ends exist.
//
// "Both ends exist" is doing real work. Entities are bounded, so a process may
// be observed without being admitted to the topology; an edge to an entity that
// was dropped would be a dangling reference that no consumer can resolve. The
// edge is dropped with it, and the drop is counted.
// ─────────────────────────────────────────────────────────────────────────────

// relateProcesses builds the process-rooted edges: parent, service and
// container membership.
//
// procKeys maps a PID to the local entity key of the process entity admitted for
// it, and is empty for processes that were observed but not promoted to
// entities. Passing PIDs rather than instance keys is safe HERE and only here,
// because the map is rebuilt from a single enumeration every cycle and never
// outlives it — a PID recycled between cycles cannot be confused, because the
// map from the previous cycle is gone.
func relateProcesses(
	rs *relationSet,
	facts []ProcessFacts,
	evidence map[PID]cgroupEvidence,
	procKeys map[PID]string,
	serviceKeys map[string]string,
	containerKeys map[string]string,
	mainPIDs map[PID]string,
) {
	for i := range facts {
		f := &facts[i]
		from, ok := procKeys[f.PID]
		if !ok {
			continue
		}

		// Parent. The kernel reports it directly, so the evidence is as strong
		// as evidence gets — but the parent must itself be an admitted entity,
		// and on a host where init is not tracked most processes will have no
		// parent edge. That is correct: an edge to nothing is worse than none.
		if parent, ok := procKeys[f.PPID]; ok {
			rs.add(relationship{
				Type: RelationParentProcess, From: from, To: parent,
				Evidence: EvidencePPID,
			})
		}

		// Service membership, from the service manager where it reports a main
		// PID, otherwise from the cgroup path.
		//
		// The manager's own report is checked first because it is the stronger
		// evidence and because it is the ONLY evidence available on Windows,
		// where there are no cgroups. Where both agree the manager's wins and
		// carries the "main" role; where only the cgroup knows, the process is
		// a member rather than the main process.
		if svcKey, ok := mainPIDs[f.PID]; ok {
			rs.add(relationship{
				Type: RelationRunsService, From: from, To: svcKey,
				Evidence: EvidenceServiceManager, Role: "main",
			})
		} else if ev, ok := evidence[f.PID]; ok && ev.Unit != "" {
			if svcKey, ok := serviceKeys[ev.Unit]; ok {
				rs.add(relationship{
					Type: RelationRunsService, From: from, To: svcKey,
					Evidence: EvidenceCgroupUnit,
				})
			}
		}

		// Container membership.
		if ev, ok := evidence[f.PID]; ok && ev.ContainerID != "" {
			if cKey, ok := containerKeys[ev.ContainerID]; ok {
				rs.add(relationship{
					Type: RelationRunsInContainer, From: from, To: cKey,
					Evidence: EvidenceCgroupContainer,
				})
			}
		}
	}
}

// relateContainersToPods links containers to the pod that owns them.
func relateContainersToPods(
	rs *relationSet,
	containers []ContainerFacts,
	containerKeys map[string]string,
	podKeys map[string]string,
) {
	for i := range containers {
		c := &containers[i]
		if c.PodUID == "" {
			continue
		}
		from, ok := containerKeys[c.ID]
		if !ok {
			continue
		}
		if to, ok := podKeys[c.PodUID]; ok {
			rs.add(relationship{
				Type: RelationContainerInPod, From: from, To: to,
				Evidence: EvidenceCgroupPod,
			})
		}
	}
}

// relateEndpoints links listening sockets to their owning process and to the
// interface carrying their address.
//
// THE INTERFACE EDGE IS THE ONE PLACE FUNCTIONALITY HAD TO BE EARNED rather than
// inherited from the domain. A socket bound to 0.0.0.0 listens on every
// interface, which is a one-to-many relationship and exactly the shape that
// would make topology quadratic — a host with 200 listeners and 100 interfaces
// would produce 20,000 edges from this one rule.
//
// So the rule is narrowed until it is functional: the edge is emitted only when
// the bind address matches EXACTLY ONE interface address. A wildcard bind
// produces no interface edge at all, which is the honest answer — "this listener
// is on every interface" is a fact about the listener, already visible in its
// own address attribute, and not an edge to any particular interface.
func relateEndpoints(
	rs *relationSet,
	endpoints []EndpointFacts,
	endpointKeys map[string]string,
	procKeys map[PID]string,
	addressOwners map[string]string,
) {
	for i := range endpoints {
		e := &endpoints[i]
		from, ok := endpointKeys[endpointLocalKey(e.Protocol, e.Address, e.Port)]
		if !ok {
			continue
		}

		if e.HasOwnerPID {
			if to, ok := procKeys[e.OwnerPID]; ok {
				ev := EvidenceSocketInode
				if e.Inode == 0 {
					// No inode means the OS named the owner directly, which is
					// what Windows does; recording which mechanism proved it
					// lets an operator tell the two apart.
					ev = EvidenceSocketTable
				}
				rs.add(relationship{
					Type: RelationEndpointOwnedBy, From: from, To: to,
					Evidence: ev,
				})
			}
		}

		if to, ok := addressOwners[e.Address]; ok {
			rs.add(relationship{
				Type: RelationEndpointBoundTo, From: from, To: to,
				Evidence: EvidenceInterfaceAddress,
			})
		}
	}
}

// buildAddressOwners maps an address to the interface that owns it, keeping only
// addresses owned by EXACTLY ONE interface.
//
// Ambiguous addresses are removed rather than resolved. An address on two
// interfaces happens for real — bonded pairs, a bridge and its member, a
// loopback alias — and picking one would be a guess with no evidence behind it.
//
// Wildcard addresses are excluded outright: they belong to no interface, and
// matching them would attach every wildcard listener on the host to whichever
// interface happened to be enumerated first.
func buildAddressOwners(ifaces []InterfaceFacts, ifaceKeys map[string]string) map[string]string {
	owners := make(map[string]string, len(ifaces)*2)
	ambiguous := make(map[string]bool)

	for i := range ifaces {
		f := &ifaces[i]
		key, ok := ifaceKeys[f.Name]
		if !ok {
			continue
		}
		for _, cidr := range f.Addresses {
			addr := addressOf(cidr)
			if addr == "" || isWildcardAddress(addr) {
				continue
			}
			if prev, seen := owners[addr]; seen && prev != key {
				ambiguous[addr] = true
				continue
			}
			owners[addr] = key
		}
	}
	for addr := range ambiguous {
		delete(owners, addr)
	}
	return owners
}

// addressOf strips the prefix length from a CIDR string.
func addressOf(cidr string) string {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

// isWildcardAddress reports whether an address means "every interface".
func isWildcardAddress(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == ""
}

// endpointLocalKey builds the local topology key for a listener. It is defined
// here, beside the code that looks endpoints up, so that the two cannot drift.
func endpointLocalKey(proto Protocol, addr string, port uint16) string {
	return proto.String() + ":" + addr + ":" + itoa(int(port))
}

// itoa is a tiny local decimal formatter, used on paths that run once per
// endpoint per cycle.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// relationAttrs renders a relationship as bounded event attributes.
//
// Note what is NOT here: the local entity keys. They are internal to this
// process, meaningless to a consumer, and would be an unbounded attribute value.
// What leaves is the pair of platform-resolved EntityIDs plus three closed-set
// attributes, so a relationship event has a fixed shape and a bounded size.
func relationAttrs(r relationship, fromID, toID string) []platform.Attr {
	attrs := make([]platform.Attr, 0, 5)
	attrs = append(attrs,
		platform.A(AttrRelation, r.Type.String()),
		platform.A(AttrFromEntity, fromID),
		platform.A(AttrToEntity, toID),
		platform.A(AttrEvidence, r.Evidence.String()),
	)
	if r.Role != "" {
		attrs = append(attrs, platform.A(AttrRole, r.Role))
	}
	return attrs
}
