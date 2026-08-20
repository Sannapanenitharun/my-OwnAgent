package discovery

import (
	"context"
	"sort"
)

// Derivation: turning process cgroup evidence into container and pod entities.
//
// This file carries NO BUILD TAG even though it implements a Linux capability,
// for the same reason parse.go does not: it is pure logic over data structures,
// it is where the subtle mistakes live, and its tests are worth running on every
// developer platform. The build-tagged file merely decides whether to wire it in.

// cgroupContainers is the container source backed by control-group evidence.
//
// It needs no container runtime socket, and that is the security argument for
// this whole approach rather than a convenience. The Docker socket is
// root-equivalent — anything that can write to it can start a privileged
// container and own the host — so an observability agent holding it becomes the
// most valuable target on the machine. Reading cgroup paths is unprivileged,
// read-only, and yields the same container inventory.
type cgroupContainers struct{}

// DiscoverContainers derives the container inventory from process cgroups.
//
// Deduplication is by container ID, and the result is sorted, so that the
// inventory is a stable set rather than one entry per process in the container.
// A container running four hundred processes is one container.
func (cgroupContainers) DiscoverContainers(_ context.Context, procs []ProcessFacts) ([]ContainerFacts, error) {
	byID := make(map[string]*ContainerFacts, 16)

	for i := range procs {
		ev := parseCgroupPath(procs[i].CgroupPath)
		if ev.ContainerID == "" {
			continue
		}
		c, ok := byID[ev.ContainerID]
		if !ok {
			c = &ContainerFacts{ID: ev.ContainerID, Runtime: ev.Runtime}
			byID[ev.ContainerID] = c
		}
		// The first process to prove a runtime wins, and later processes may
		// only ADD facts rather than change them. Two processes in one container
		// cannot legitimately disagree about its runtime, so a disagreement
		// means a path was misparsed — and quietly taking the last writer would
		// make the reported runtime depend on enumeration order.
		if c.Runtime == ContainerRuntimeUnknown {
			c.Runtime = ev.Runtime
		}
		if c.PodUID == "" {
			c.PodUID = ev.PodUID
		}
	}

	out := make([]ContainerFacts, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// cgroupEvidenceFor parses each process's cgroup path once per cycle.
//
// Once, and cached in the returned map, because the evidence is consumed four
// times downstream — for service membership, for container membership, for
// container derivation and for structural promotion. Parsing it at each use
// would be four string walks per process per cycle, which at ten thousand
// processes is the module's largest avoidable cost.
//
// Processes with no cgroup path, and those whose path proves nothing, are
// omitted rather than stored with an empty value: on a host where most processes
// are in the root cgroup that is the difference between a map of ten thousand
// useless entries and one of fifty useful ones.
func cgroupEvidenceFor(procs []ProcessFacts) map[PID]cgroupEvidence {
	out := make(map[PID]cgroupEvidence, 32)
	for i := range procs {
		if procs[i].CgroupPath == "" {
			continue
		}
		ev := parseCgroupPath(procs[i].CgroupPath)
		if ev.Empty() {
			continue
		}
		out[procs[i].PID] = ev
	}
	return out
}

// podsFrom collects the distinct pods proved by container evidence, merging in
// the agent's own pod context where the two describe the same pod.
//
// The merge is why podRef keys on UID. Containers yield a pod UID and nothing
// else; the downward API yields a namespace, a name and a UID. Keying on the UID
// means the agent's own pod is ENRICHED by its context rather than duplicated
// beside the pod its cgroup already proved.
func podsFrom(containers []ContainerFacts, self KubernetesFacts) []podFacts {
	byUID := make(map[string]*podFacts, 8)

	for i := range containers {
		uid := containers[i].PodUID
		if uid == "" {
			continue
		}
		if _, ok := byUID[uid]; !ok {
			byUID[uid] = &podFacts{UID: uid}
		}
	}

	if self.InCluster && self.PodUID != "" {
		p, ok := byUID[self.PodUID]
		if !ok {
			p = &podFacts{UID: self.PodUID}
			byUID[self.PodUID] = p
		}
		p.Namespace = self.Namespace
		p.Name = self.PodName
		p.NodeName = self.NodeName
		p.Self = true
	} else if self.InCluster && self.PodName != "" {
		// In cluster, with a name but no UID: the downward API was configured
		// for the name and not the UID. The pod is still worth reporting, keyed
		// on namespace and name, and the weaker key is a consequence of the
		// deployment's own configuration rather than a guess by the agent.
		byUID["\x00self"] = &podFacts{
			Namespace: self.Namespace, Name: self.PodName,
			NodeName: self.NodeName, Self: true,
		}
	}

	out := make([]podFacts, 0, len(byUID))
	for _, p := range byUID {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UID != out[j].UID {
			return out[i].UID < out[j].UID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// podFacts is a pod as the module assembles it, from one or two sources.
type podFacts struct {
	UID       string
	Namespace string
	Name      string
	NodeName  string
	// Self marks the pod the agent itself runs in, which is the one an operator
	// most often wants to find.
	Self bool
}

// structuralPIDs computes which processes are promoted to entities.
//
// A process earns an entity when EVIDENCE CONNECTS IT TO SOMETHING — see the
// ProcessMode documentation in config.go for why that is the default rather than
// promoting everything. The four qualifying kinds of evidence are exactly the
// four that produce a relationship, which is what makes the rule "no process
// entity is ever an isolated node".
//
// A CONSEQUENCE WORTH STATING: the process tree is therefore PARTIAL by design.
// A parent edge appears only between two processes that are each independently
// structural, so an operator cannot always walk from a listener up to init. That
// is the deliberate trade — a complete tree costs one entity per process, which
// is the cardinality problem this rule exists to avoid — and processes.mode=all
// buys the complete tree for hosts where it is affordable.
func structuralPIDs(
	procs []ProcessFacts,
	evidence map[PID]cgroupEvidence,
	services []ServiceFacts,
	endpoints []EndpointFacts,
	includeNames []string,
) map[PID]struct{} {
	out := make(map[PID]struct{}, 64)

	for _, s := range services {
		if s.HasMainPID && s.MainPID > 0 {
			out[s.MainPID] = struct{}{}
		}
	}
	for i := range endpoints {
		if endpoints[i].HasOwnerPID && endpoints[i].OwnerPID > 0 {
			out[endpoints[i].OwnerPID] = struct{}{}
		}
	}
	for pid, ev := range evidence {
		if ev.Unit != "" || ev.ContainerID != "" {
			out[pid] = struct{}{}
		}
	}
	if len(includeNames) > 0 {
		for i := range procs {
			if matchesAny(procs[i].Name, includeNames) {
				out[procs[i].PID] = struct{}{}
			}
		}
	}
	return out
}
