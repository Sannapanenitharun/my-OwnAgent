package discovery

import (
	"sort"
	"strconv"
	"strings"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The entity model.
//
// An entity is one discovered thing: a service, a container, a filesystem. It
// has a LOCAL KEY that identifies it within this host's topology, a bounded set
// of attributes, a fingerprint of those attributes, and — once the platform has
// been asked — an EntityID that the platform assigned.
//
// The local key and the EntityID are different things and the distinction is the
// whole discipline. The local key is how the module recognises the same thing
// across cycles; it is derived here, it never leaves the process, and it is not
// an identifier. The EntityID is the platform's answer to "what is this", it is
// never derived here, and its absence degrades fidelity rather than function.

// entity is one discovered thing, as retained between cycles.
//
// Size is the module's memory model: this struct times the number of tracked
// entities, bounded by max_entities. The fingerprint exists partly to keep it
// small — comparing this cycle's attributes against last cycle's would mean
// retaining last cycle's attribute strings for every entity, where an 8-byte
// hash answers the same question.
type entity struct {
	kind platform.EntityKind
	// key identifies the entity within this host. It is bounded, sanitised and
	// deterministic.
	key string
	// attrs are the entity's current attributes: bounded, sanitised, and sorted
	// by key so that the fingerprint is stable regardless of discovery order.
	attrs []platform.Attr
	// fp is the fingerprint of attrs. A change in fp is what "this entity
	// changed" means.
	fp uint64

	// entityID is the platform-resolved identifier, cached for the entity's
	// life. tried stops the module re-asking every cycle for something the
	// platform has already declined to resolve.
	entityID string
	tried    bool

	// cycle is the last discovery cycle in which this entity was observed.
	cycle uint64
	// firstCycle is when it was first observed, which is what distinguishes a
	// genuinely new entity from one being re-reported by a full resync.
	firstCycle uint64
}

// entityKey builds the local key for an entity of a given kind.
//
// The key is kind-scoped, so a service named "docker" and a container named
// "docker" are two entities rather than one. Components are joined with a
// character that cannot appear in a sanitised component, so that ("a/b", "c")
// and ("a", "b/c") cannot collide — a subtle but real source of merged entities
// in systems that join keys naively.
func entityKey(kind platform.EntityKind, parts ...string) string {
	var b strings.Builder
	b.WriteString(string(kind))
	for _, p := range parts {
		b.WriteByte(keySeparator)
		b.WriteString(p)
	}
	return b.String()
}

// keySeparator is a byte that sanitisation guarantees never appears inside a key
// component: sanitiseValue replaces every control character, and 0x1f is one.
const keySeparator = 0x1f

// fingerprint hashes an attribute set with FNV-1a.
//
// FNV rather than a cryptographic hash because this is a CHANGE DETECTOR, not a
// security boundary. A collision means one changed entity is not re-emitted this
// cycle; the periodic full resync then repairs it. Choosing SHA-256 here would
// cost an allocation and a hash context per entity per cycle to protect against
// a consequence that is already self-healing.
//
// attrs must be sorted before hashing, which sortAttrs guarantees, so that the
// fingerprint depends on the CONTENT and not on the order the sources happened
// to produce it in.
func fingerprint(kind platform.EntityKind, key string, attrs []platform.Attr) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	write := func(s string) {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= prime64
		}
		// A separator byte, so that ("ab","c") and ("a","bc") differ.
		h ^= 0
		h *= prime64
	}
	write(string(kind))
	write(key)
	for _, a := range attrs {
		write(a.Key)
		write(a.Value)
	}
	return h
}

// sortAttrs orders an attribute set by key, then by value.
//
// Sorting is what makes the fingerprint depend on content rather than on the
// order a source produced its facts in. Without it, a source that enumerated
// addresses in a different order each cycle would report every interface as
// changed, every cycle, forever — which is how an incremental discovery system
// degrades into a full one that also lies about what changed.
func sortAttrs(attrs []platform.Attr) {
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].Key != attrs[j].Key {
			return attrs[i].Key < attrs[j].Key
		}
		return attrs[i].Value < attrs[j].Value
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Natural keys.
//
// Each function below states the observable facts that identify one kind of
// entity, and hands them to the platform. None of them hashes anything and none
// returns an identifier.
//
// The process kind is the exception: its builder lives in internal/platform
// because the process module observes processes too, and two modules holding
// separate copies of one key shape is a fork waiting to happen. Every other kind
// here is observed by this module alone, and its builder moves to platform the
// day that stops being true. See platform/entity.go.
// ─────────────────────────────────────────────────────────────────────────────

// serviceRef identifies a managed service by its manager and its manager-assigned
// name. The DISPLAY name is deliberately excluded: it is localised, operators
// change it, and a key that changes when someone edits a description is not a
// key.
func serviceRef(host string, kind ServiceKind, name string) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindService,
		Parent: host,
		Keys: []platform.Attr{
			platform.A("manager", kind.String()),
			platform.A("name", name),
		},
	}
}

// containerRef identifies a container by its runtime ID.
//
// The container ID alone would be globally unique in practice, but the host is
// still the parent: a container is observed FROM this host, and a container that
// migrated would otherwise appear to be in two places at once rather than to
// have moved.
func containerRef(host, id string) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindContainer,
		Parent: host,
		Keys:   []platform.Attr{platform.A("container_id", id)},
	}
}

// interfaceRef identifies a network interface.
//
// Keyed by NAME and not by MAC address. That is the less obvious choice and it
// is the right one: MAC addresses are duplicated on bridged and bonded setups,
// they are absent on tunnels and loopback, and they are randomised by some
// stacks. The name is what the operator, the config and the routing table all
// use.
func interfaceRef(host, name string) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindNetworkInterface,
		Parent: host,
		Keys:   []platform.Attr{platform.A("interface", name)},
	}
}

// endpointRef identifies a listening socket by protocol, bind address and port.
func endpointRef(host string, proto Protocol, addr string, port uint16) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindNetworkEndpoint,
		Parent: host,
		Keys: []platform.Attr{
			platform.A("protocol", proto.String()),
			platform.A("address", addr),
			platform.A("port", strconv.Itoa(int(port))),
		},
	}
}

// filesystemRef identifies a mounted filesystem by its mount point.
//
// The mount point, not the device. A device may be mounted twice, a device node
// may be renumbered across reboots, and network filesystems have no device node
// worth the name — whereas the mount point is where the data actually appears
// and is what every consumer of the fact means by "the filesystem".
func filesystemRef(host, mountpoint string) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindFilesystem,
		Parent: host,
		Keys:   []platform.Attr{platform.A("mountpoint", mountpoint)},
	}
}

// runtimeRef identifies the host's execution environment. There is exactly one
// per host, so the host is the entire key.
func runtimeRef(host string) platform.EntityRef {
	return platform.EntityRef{
		Kind:   platform.EntityKindRuntime,
		Parent: host,
		Keys:   []platform.Attr{platform.A("scope", "host")},
	}
}

// cloudRef identifies the provider's own notion of this machine.
//
// When the firmware exposes an instance ID that is the key, because it is the
// provider's identifier and will match their records. When it does not, the key
// falls back to the provider plus the host — which correctly means "the cloud
// instance this host is", without pretending to know the provider's name for it.
func cloudRef(host string, provider CloudProvider, instanceID string) platform.EntityRef {
	keys := []platform.Attr{platform.A("provider", provider.String())}
	if instanceID != "" {
		keys = append(keys, platform.A("instance_id", instanceID))
	} else {
		keys = append(keys, platform.A("scope", "host"))
	}
	return platform.EntityRef{
		Kind:   platform.EntityKindCloudInstance,
		Parent: host,
		Keys:   keys,
	}
}

// podRef identifies a Kubernetes pod.
//
// The UID is the key WHEN THERE IS ONE, and namespace/name are then attributes
// rather than key components. That ordering is deliberate and it is the opposite
// of what reads naturally:
//
//   - A pod UID is the cluster's own identity for the pod and is never reused. A
//     namespace/name pair IS reused — a Deployment rollout produces a new pod
//     with a name derived from the same template — so keying on the name would
//     merge every generation of a pod into one entity with an impossible
//     lifetime.
//   - The two are learned from different places. Containers discovered through
//     cgroup evidence yield a UID and no name; the agent's own downward-API
//     context yields all three. Keying on the UID means both paths describe the
//     same pod rather than two.
//
// The parent is the HOST, not a cluster entity: this module observes pods from
// the node it runs on, and the cluster is not something it can see.
func podRef(host, namespace, name, uid string) platform.EntityRef {
	if uid != "" {
		return platform.EntityRef{
			Kind:   platform.EntityKindKubernetesPod,
			Parent: host,
			Keys:   []platform.Attr{platform.A("uid", uid)},
		}
	}
	return platform.EntityRef{
		Kind:   platform.EntityKindKubernetesPod,
		Parent: host,
		Keys: []platform.Attr{
			platform.A("namespace", namespace),
			platform.A("pod", name),
		},
	}
}
