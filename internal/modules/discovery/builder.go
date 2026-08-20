package discovery

import (
	"strconv"

	"github.com/obsagent/observability-agent/internal/platform"
)

// builder turns one cycle's facts into entity candidates.
//
// It is the single place where untrusted strings become attribute values and
// natural-key components, which is why every string that passes through here
// goes through sanitiseValue. Sanitisation spread across ten sources would be
// sanitisation that is correct in nine.
//
// It also builds the KEY INDEXES the relationship engine needs — PID to entity
// key, unit name to entity key, container ID to entity key. Building them here,
// while the facts are in hand, is what lets the relationship engine be a pure
// function of evidence and keys rather than something that re-derives identity.
type builder struct {
	settings Settings
	host     string

	candidates []candidate

	procKeys      map[PID]string
	serviceKeys   map[string]string
	containerKeys map[string]string
	podKeys       map[string]string
	ifaceKeys     map[string]string
	endpointKeys  map[string]string
	// mainPIDs maps a service's main process ID to the SERVICE's entity key.
	mainPIDs map[PID]string

	// sanitised counts values that had to be rewritten. A sudden rise usually
	// means a runtime is writing a path shape nobody has seen before, which is
	// worth knowing.
	sanitised int
}

func newBuilder(s Settings, host string) *builder {
	return &builder{
		settings:      s,
		host:          host,
		candidates:    make([]candidate, 0, 64),
		procKeys:      make(map[PID]string, 32),
		serviceKeys:   make(map[string]string, 32),
		containerKeys: make(map[string]string, 16),
		podKeys:       make(map[string]string, 8),
		ifaceKeys:     make(map[string]string, 8),
		endpointKeys:  make(map[string]string, 32),
		mainPIDs:      make(map[PID]string, 32),
	}
}

// clean sanitises a value and counts the rewrite.
func (b *builder) clean(s string, max int) string {
	out, modified := sanitiseValue(s, max)
	if modified {
		b.sanitised++
	}
	return out
}

func (b *builder) add(c candidate) { b.candidates = append(b.candidates, c) }

// addHost records the host's own descriptive facts.
//
// The host entity itself is the platform's, not this module's: it comes from
// Identity.HostID and is never minted here. What the module contributes is what
// the host IS — its OS, kernel, architecture and time zone — as attributes of an
// entity the platform already knows about. That is why there is no hostRef.
func (b *builder) addHost(f facts) {
	if !f.hasHost || b.host == "" {
		return
	}
	attrs := []platform.Attr{
		platform.A(AttrHostname, b.clean(f.host.Hostname, maxNameLen)),
		platform.A(AttrOS, b.clean(f.host.OS, maxNameLen)),
	}
	attrs = appendIf(attrs, AttrDistribution, b.cleanOptional(f.host.Distribution, maxNameLen))
	attrs = appendIf(attrs, AttrVersion, b.cleanOptional(f.host.Version, maxNameLen))
	attrs = appendIf(attrs, AttrKernel, b.cleanOptional(f.host.KernelVersion, maxNameLen))
	attrs = appendIf(attrs, AttrArch, b.cleanOptional(f.host.Architecture, maxNameLen))
	attrs = appendIf(attrs, AttrTimeZone, b.cleanOptional(f.host.TimeZone, maxNameLen))
	if f.host.HasBootTime {
		attrs = append(attrs, platform.A("boot_time",
			strconv.FormatInt(f.host.BootTime.Unix(), 10)))
	}

	b.add(candidate{
		kind: platform.EntityKindHost,
		key:  entityKey(platform.EntityKindHost, b.host),
		// No ref, and a pre-resolved identifier: the host entity is the one the
		// platform already named, through Identity.HostID, before this cycle
		// began.
		resolvedID: b.host,
		attrs:      attrs,
	})
}

func (b *builder) cleanOptional(s string, max int) string {
	if s == "" {
		return ""
	}
	return b.clean(s, max)
}

func appendIf(attrs []platform.Attr, key, value string) []platform.Attr {
	if value == "" {
		return attrs
	}
	return append(attrs, platform.A(key, value))
}

// addRuntime records the execution environment the host is in.
func (b *builder) addRuntime(f facts) {
	if !f.hasRuntime || b.host == "" {
		return
	}
	attrs := []platform.Attr{
		platform.A(AttrInContainer, boolValue(f.runtime.InContainer)),
	}
	if f.runtime.InContainer {
		attrs = appendIf(attrs, AttrContainerID, b.cleanOptional(f.runtime.ContainerID, maxNameLen))
		attrs = append(attrs, platform.A(AttrRuntimeName, f.runtime.Runtime.String()))
	}
	if f.hasKube && f.kube.InCluster {
		attrs = append(attrs, platform.A("kubernetes", boolValue(true)))
		attrs = appendIf(attrs, AttrNamespace, b.cleanOptional(f.kube.Namespace, maxNameLen))
		attrs = appendIf(attrs, AttrNodeName, b.cleanOptional(f.kube.NodeName, maxNameLen))
	}

	b.add(candidate{
		kind:  platform.EntityKindRuntime,
		key:   entityKey(platform.EntityKindRuntime, "host"),
		ref:   runtimeRef(b.host),
		attrs: attrs,
	})
}

// addCloud records the platform underneath the host.
//
// An Unknown provider is still emitted, carrying the raw vendor and product
// strings. That is the useful behaviour: an operator on an unrecognised platform
// gets the evidence and can tell the module about it, whereas suppressing the
// entity would leave them unable to distinguish "not a cloud" from "a cloud this
// agent has not heard of".
func (b *builder) addCloud(f facts) {
	if !f.hasCloud || b.host == "" {
		return
	}
	attrs := []platform.Attr{
		platform.A(AttrProvider, f.cloud.Provider.String()),
	}
	attrs = appendIf(attrs, AttrInstanceID, b.cleanOptional(f.cloud.InstanceID, maxNameLen))
	attrs = appendIf(attrs, AttrVendor, b.cleanOptional(f.cloud.Vendor, maxNameLen))
	attrs = appendIf(attrs, AttrProduct, b.cleanOptional(f.cloud.Product, maxNameLen))

	b.add(candidate{
		kind:  platform.EntityKindCloudInstance,
		key:   entityKey(platform.EntityKindCloudInstance, f.cloud.Provider.String()),
		ref:   cloudRef(b.host, f.cloud.Provider, f.cloud.InstanceID),
		attrs: attrs,
	})
}

// addServices records managed services.
//
// Rank is by state, so that a host over its service cap keeps the RUNNING and
// FAILED services and sheds the merely-stopped ones. A failed service is the
// most interesting thing in the list and must never be the first thing dropped.
func (b *builder) addServices(services []ServiceFacts) {
	if b.host == "" {
		return
	}
	for i := range services {
		s := &services[i]
		name := b.clean(s.Name, maxNameLen)
		if name == sentinelUnknown || !b.settings.admitService(name) {
			continue
		}
		key := entityKey(platform.EntityKindService, s.Kind.String(), name)

		attrs := []platform.Attr{
			platform.A(AttrName, name),
			platform.A(AttrManager, s.Kind.String()),
			platform.A(AttrState, s.State.String()),
		}
		attrs = appendIf(attrs, AttrDisplayName, b.cleanOptional(s.DisplayName, maxNameLen))
		if s.HasEnabled {
			attrs = append(attrs, platform.A(AttrEnabled, boolValue(s.Enabled)))
		}
		if s.HasMainPID {
			attrs = append(attrs, platform.A(AttrPID, strconv.Itoa(int(s.MainPID))))
			b.mainPIDs[s.MainPID] = key
		}

		b.serviceKeys[name] = key
		b.add(candidate{
			kind:  platform.EntityKindService,
			key:   key,
			ref:   serviceRef(b.host, s.Kind, name),
			attrs: attrs,
			rank:  serviceRank(s.State),
		})
	}
}

// serviceRank orders services for the per-kind cap. Lower is kept.
func serviceRank(st ServiceState) int {
	switch st {
	case ServiceStateFailed:
		return 0
	case ServiceStateRunning:
		return 1
	case ServiceStateStarting, ServiceStateStopping:
		return 2
	default:
		return 3
	}
}

func (b *builder) addContainers(containers []ContainerFacts) {
	if b.host == "" {
		return
	}
	for i := range containers {
		c := &containers[i]
		id := b.clean(c.ID, maxNameLen)
		if id == sentinelUnknown {
			continue
		}
		key := entityKey(platform.EntityKindContainer, id)

		attrs := []platform.Attr{
			platform.A(AttrContainerID, id),
			platform.A(AttrRuntimeName, c.Runtime.String()),
		}
		attrs = appendIf(attrs, AttrPodUID, b.cleanOptional(c.PodUID, maxNameLen))
		attrs = appendIf(attrs, AttrNamespace, b.cleanOptional(c.Namespace, maxNameLen))
		attrs = appendIf(attrs, AttrPodName, b.cleanOptional(c.PodName, maxNameLen))

		b.containerKeys[c.ID] = key
		b.add(candidate{
			kind:  platform.EntityKindContainer,
			key:   key,
			ref:   containerRef(b.host, id),
			attrs: attrs,
		})
	}
}

func (b *builder) addPods(pods []podFacts) {
	if b.host == "" {
		return
	}
	for i := range pods {
		p := &pods[i]
		uid := b.cleanOptional(p.UID, maxNameLen)
		name := b.cleanOptional(p.Name, maxNameLen)
		ns := b.cleanOptional(p.Namespace, maxNameLen)
		if uid == "" && name == "" {
			continue
		}
		ident := uid
		if ident == "" {
			ident = ns + "/" + name
		}
		key := entityKey(platform.EntityKindKubernetesPod, ident)

		attrs := make([]platform.Attr, 0, 5)
		attrs = appendIf(attrs, AttrPodUID, uid)
		attrs = appendIf(attrs, AttrPodName, name)
		attrs = appendIf(attrs, AttrNamespace, ns)
		attrs = appendIf(attrs, AttrNodeName, b.cleanOptional(p.NodeName, maxNameLen))
		if p.Self {
			attrs = append(attrs, platform.A("self", boolValue(true)))
		}

		if p.UID != "" {
			b.podKeys[p.UID] = key
		}
		b.add(candidate{
			kind:  platform.EntityKindKubernetesPod,
			key:   key,
			ref:   podRef(b.host, ns, name, uid),
			attrs: attrs,
			// The agent's own pod ranks first: it is the one an operator is most
			// often looking for, and it is the only one whose full context the
			// module can see.
			rank: boolRank(!p.Self),
		})
	}
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (b *builder) addInterfaces(ifaces []InterfaceFacts) {
	if b.host == "" {
		return
	}
	for i := range ifaces {
		f := &ifaces[i]
		if f.Virtual && !b.settings.IncludeVirtualIface {
			continue
		}
		name := b.clean(f.Name, maxNameLen)
		if name == sentinelUnknown {
			continue
		}
		key := entityKey(platform.EntityKindNetworkInterface, name)

		addrs := boundAddresses(f.Addresses)
		attrs := []platform.Attr{
			platform.A(AttrInterface, name),
			platform.A(AttrUp, boolValue(f.Up)),
		}
		attrs = appendIf(attrs, AttrMACAddress, b.cleanOptional(f.HardwareAddr, maxNameLen))
		attrs = appendIf(attrs, AttrAddress, joinAddresses(addrs))
		if f.MTU > 0 {
			attrs = append(attrs, platform.A(AttrMTU, strconv.Itoa(f.MTU)))
		}

		b.ifaceKeys[f.Name] = key
		b.add(candidate{
			kind:  platform.EntityKindNetworkInterface,
			key:   key,
			ref:   interfaceRef(b.host, name),
			attrs: attrs,
			// Physical, up interfaces first. A host over its interface cap
			// should shed the down veth pairs, not its uplink.
			rank: interfaceRank(f),
		})
	}
}

func interfaceRank(f *InterfaceFacts) int {
	switch {
	case f.Up && !f.Virtual && !f.Loopback:
		return 0
	case f.Up:
		return 1
	default:
		return 2
	}
}

func (b *builder) addEndpoints(endpoints []EndpointFacts) {
	if b.host == "" {
		return
	}
	for i := range endpoints {
		e := &endpoints[i]
		addr := b.clean(e.Address, maxNameLen)
		if addr == sentinelUnknown {
			continue
		}
		if !b.settings.IncludeLoopback && isLoopbackAddress(addr) {
			continue
		}
		local := endpointLocalKey(e.Protocol, addr, e.Port)
		key := entityKey(platform.EntityKindNetworkEndpoint, local)

		attrs := []platform.Attr{
			platform.A(AttrProtocol, e.Protocol.String()),
			platform.A(AttrAddress, addr),
			platform.A(AttrPort, strconv.Itoa(int(e.Port))),
		}
		if e.HasOwnerPID {
			attrs = append(attrs, platform.A(AttrPID, strconv.Itoa(int(e.OwnerPID))))
		}

		b.endpointKeys[local] = key
		b.add(candidate{
			kind:  platform.EntityKindNetworkEndpoint,
			key:   key,
			ref:   endpointRef(b.host, e.Protocol, addr, e.Port),
			attrs: attrs,
			// Low ports first. A host over its endpoint cap should keep the
			// well-known service ports and shed the ephemeral ones, which is
			// what an operator would choose.
			rank: int(e.Port),
		})
	}
}

// isLoopbackAddress reports whether an address is host-local.
func isLoopbackAddress(addr string) bool {
	return addr == "::1" || len(addr) >= 4 && addr[:4] == "127."
}

func (b *builder) addFilesystems(mounts []FilesystemFacts) {
	if b.host == "" {
		return
	}
	for i := range mounts {
		f := &mounts[i]
		// Pseudo filesystems are filtered HERE rather than in each platform
		// source, so that the flag means the same thing everywhere and one
		// source cannot forget to honour it.
		if !b.settings.IncludePseudoFS && pseudoFilesystems[f.FSType] {
			continue
		}
		mp := b.clean(f.Mountpoint, maxPathLen)
		if mp == sentinelUnknown || !b.settings.admitMount(mp) {
			continue
		}
		key := entityKey(platform.EntityKindFilesystem, mp)

		attrs := []platform.Attr{
			platform.A(AttrMountpoint, mp),
			platform.A(AttrFSType, b.clean(f.FSType, maxNameLen)),
			platform.A(AttrReadOnly, boolValue(f.ReadOnly)),
			platform.A(AttrRemote, boolValue(f.Remote)),
		}
		attrs = appendIf(attrs, AttrDevice, b.cleanOptional(f.Device, maxPathLen))

		b.add(candidate{
			kind:  platform.EntityKindFilesystem,
			key:   key,
			ref:   filesystemRef(b.host, mp),
			attrs: attrs,
			// Shorter mount points first, so a host over its cap keeps "/" and
			// "/var" and sheds the deeply nested per-container overlays.
			rank: len(mp),
		})
	}
}

// addProcesses records process entities according to the configured mode.
//
// The promotion rule is the module's central cardinality decision for this
// domain; see ProcessMode in config.go. Rank is the PID, so a host over its
// process cap keeps the low-numbered long-lived system processes and sheds the
// churn — the same choice the process module makes for the same reason.
func (b *builder) addProcesses(
	procs []ProcessFacts,
	evidence map[PID]cgroupEvidence,
	services []ServiceFacts,
	endpoints []EndpointFacts,
	bootID string,
) {
	if b.host == "" || b.settings.ProcessMode == ProcessModeNone {
		return
	}

	var structural map[PID]struct{}
	if b.settings.ProcessMode == ProcessModeStructural {
		structural = structuralPIDs(procs, evidence, services, endpoints,
			b.settings.IncludeProcesses)
	}

	for i := range procs {
		p := &procs[i]
		if structural != nil {
			if _, ok := structural[p.PID]; !ok {
				continue
			}
		}
		// A process with no start stamp has no instance identity, and a recycled
		// PID would silently inherit its relationships. Omitting it is the
		// lesser harm, and it is the same rule the process module applies.
		if !p.HasStartRaw {
			continue
		}

		name := b.clean(p.Name, maxNameLen)
		key := entityKey(platform.EntityKindProcess,
			strconv.Itoa(int(p.PID)), itoaU(p.StartRaw))

		attrs := []platform.Attr{
			platform.A(AttrName, name),
			platform.A(AttrPID, strconv.Itoa(int(p.PID))),
			platform.A(AttrPPID, strconv.Itoa(int(p.PPID))),
		}
		if p.UID.OK {
			attrs = append(attrs, platform.A(AttrUID, itoaU(p.UID.V)))
		}

		b.procKeys[p.PID] = key
		b.add(candidate{
			kind: platform.EntityKindProcess,
			key:  key,
			// The natural key comes from internal/platform, not from here, so
			// that this module and the process module describe the same process
			// identically. See platform/entity.go.
			ref:   platform.ProcessRef(b.host, bootID, int64(p.PID), p.StartRaw, name),
			attrs: attrs,
			rank:  int(p.PID),
		})
	}
}
