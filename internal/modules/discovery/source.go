// Package discovery is the agent's environment-awareness module: what exists on
// this host, and how those things are related.
//
// It answers two questions and deliberately not a third. It answers "what is
// here" and "what is connected to what". It does not answer "how is it
// performing" — that is the collectors' job, and a discovery module that also
// measured would be two modules sharing a release cadence.
//
// Five properties carry the design, and each exists because of a specific way
// discovery systems fail in production:
//
//   - RELATIONSHIPS ARE FUNCTIONAL, SO TOPOLOGY IS LINEAR. The naive fear about
//     topology is quadratic blow-up: N entities admit N² relationships. Every
//     relationship this module emits is functional — a process has at most one
//     parent, at most one service, at most one container; an endpoint has at
//     most one owner. The relationship count is therefore bounded by
//     entities × relationship-types, which is LINEAR in entity count. That is a
//     structural property, asserted by tests, not a cap someone tuned. See
//     relate.go, which also records what would break it.
//
//   - EVIDENCE, NOT INFERENCE. A relationship is emitted only when a specific
//     local mechanism proves it, and every relationship carries the name of that
//     mechanism. A cgroup path proves a process belongs to a systemd unit. A
//     socket inode proves an endpoint belongs to a process. A shared port number
//     proves nothing, and so produces nothing. A topology that is 60% correct is
//     worse than one that is 40% complete, because nobody can tell which 60%.
//
//   - DISCOVERY IS INCREMENTAL. Entities are fingerprinted, and a cycle emits
//     only what appeared, changed or vanished. A stable host converges to
//     emitting nothing. A periodic full resync bounds how long a missed event
//     can leave a consumer stale — change-only streams that never resync are how
//     inventories silently rot.
//
//   - THE MODULE NEVER MINTS AN ENTITY ID. It observes natural keys and asks the
//     platform what they denote, exactly as the process module does. Twelve
//     entity kinds make this rule more load-bearing, not less: a collector that
//     invented identifiers for ten kinds would fork the entity graph ten ways.
//
//   - NOTHING RUNS. No subprocesses, no shell, no docker socket, no Kubernetes
//     API server, no cloud SDK, no metadata HTTP fetch. Every fact in this
//     module comes from a file the agent may read or a documented read-only
//     system call. See the security notes in README.md, and the prohibitions
//     asserted in internal/architecture.
//
// The module contains no OS-specific code; one build-tagged file per platform
// supplies the sources. Concurrency: sources are called from a single discovery
// goroutine, one at a time, and need not be safe for concurrent use.
package discovery

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported reports that a source cannot provide facts in this
// environment.
var ErrUnsupported = errors.New("discovery: unsupported")

// U64 is an optionally-known unsigned value. A zero that means "not available"
// is indistinguishable from a genuine zero.
//
// This duplicates the type in the host and process modules by design: modules
// may not import each other, and a four-line value type is a far smaller cost
// than three collectors sharing a release cadence. See internal/architecture.
type U64 struct {
	V  uint64
	OK bool
}

// KnownU64 returns a known value.
func KnownU64(v uint64) U64 { return U64{V: v, OK: true} }

// PID is an operating system process identifier. As in the process module it is
// a transient handle and never an identity: see entity.go.
type PID int32

// Bounds applied where UNTRUSTED bytes enter the module.
//
// Almost everything discovery reads is chosen by something other than the
// agent — a process names itself, a container runtime writes the cgroup path, an
// operator names a mount point, a service author picks a display name. Each of
// these becomes an entity attribute, and several become natural-key components
// that the platform may persist forever.
//
// The caps live HERE, at the reader boundary, rather than at the emitter, so
// that no later stage has to be trusted to bound them and no unbounded string
// is ever held in the topology table. The emitter bounds again; that is belt and
// braces, not redundancy, because it is the last gate before bytes leave.
const (
	// maxNameLen bounds a single identifying string: a service name, an
	// executable name, an interface name, a container ID.
	maxNameLen = 128
	// maxPathLen bounds a filesystem path: a mount point, a device node. Longer
	// than a name because paths are legitimately long, short enough that a
	// pathological mount table cannot become a memory event.
	maxPathLen = 256
	// maxAddressesPerInterface bounds how many addresses one interface may
	// contribute. An interface with a thousand aliases is real (load balancers
	// do this) and must not become a thousand attributes.
	maxAddressesPerInterface = 8
	// maxCgroupLen bounds the raw cgroup path read per process. It is evidence,
	// parsed and discarded, never emitted verbatim.
	maxCgroupLen = 512
)

// ─────────────────────────────────────────────────────────────────────────────
// Facts. One struct per domain, each carrying IDENTITY and STRUCTURE only.
//
// There is not a single counter, rate or utilisation figure in this file, and
// that absence is the module boundary: the moment discovery reports how much
// memory something uses, it has become a collector with a different release
// cadence and an unbounded metric surface.
// ─────────────────────────────────────────────────────────────────────────────

// HostFacts is what the machine is, as opposed to how it is doing.
//
// Note what is NOT here: /etc/machine-id and the DMI product UUID. Both would
// identify the host precisely, and both are exactly the wrong thing for this
// module to collect — systemd documents machine-id as confidential and not to
// be exposed, the DMI UUID needs root, and host identity is the platform's to
// assign in any case. The module reports what the host IS and lets the platform
// decide who it is.
type HostFacts struct {
	Hostname string
	// OS is the kernel family: "linux", "windows", "darwin".
	OS string
	// Distribution and Version are the userland's own name for itself:
	// "ubuntu"/"22.04", "windows"/"10.0.26100".
	Distribution string
	Version      string

	KernelVersion string
	Architecture  string

	BootTime    time.Time
	HasBootTime bool

	// BootID identifies THIS boot of the host.
	//
	// It is here, on the host facts, for a specific cross-module reason. The
	// process entity's natural key includes a boot identifier, and this module
	// and the process module must produce the SAME key for the same process or
	// the platform mints two entities for it. Both therefore derive the boot
	// identifier the same way, from the same kernel source, and the shared key
	// builder in internal/platform consumes it.
	//
	// It is not emitted as an attribute: it is an identifier component, and a
	// boot ID is precise enough to be worth not scattering.
	BootID string

	// TimeZone is the host's configured zone name. It is discovery data because
	// a fleet with mixed time zones is a correlation problem waiting to happen.
	TimeZone string
}

// ProcessFacts is the discovery view of a process: identity and the evidence
// needed to relate it to other things.
//
// It is deliberately much thinner than the process module's Info. Discovery does
// not want CPU, memory, threads or I/O — it wants to know that this process
// exists, what started it, and which service, container or endpoint it belongs
// to. Reading the two through the same kernel interface is not duplication; they
// are different questions asked of the same file.
type ProcessFacts struct {
	PID  PID
	PPID PID
	Name string

	// StartRaw is the platform's native start stamp, kept raw for exactly the
	// reason the process module keeps it raw: it is the discriminator that stops
	// a recycled PID inheriting another process's identity.
	StartRaw    uint64
	HasStartRaw bool

	UID U64

	// CgroupPath is the raw control-group path, the single richest piece of
	// local relationship evidence on Linux: it names the systemd unit, the
	// container ID and often the Kubernetes pod UID, all without a socket, a
	// daemon or a privilege. It is parsed by the relationship engine and is
	// NEVER emitted verbatim — a cgroup path can contain arbitrary text chosen
	// by whoever created the container.
	CgroupPath string
}

// ServiceKind is how a service is managed. Closed set; bounds an attribute.
type ServiceKind int

const (
	ServiceKindUnknown ServiceKind = iota
	// ServiceKindSystemd is a systemd unit.
	ServiceKindSystemd
	// ServiceKindWindows is a Windows Service Control Manager service.
	ServiceKindWindows
	// ServiceKindLaunchd is a macOS launchd job.
	ServiceKindLaunchd
)

func (k ServiceKind) String() string {
	switch k {
	case ServiceKindSystemd:
		return "systemd"
	case ServiceKindWindows:
		return "windows_service"
	case ServiceKindLaunchd:
		return "launchd"
	default:
		return "unknown"
	}
}

// ServiceState is a service's run state, normalised. Closed set.
type ServiceState int

const (
	ServiceStateUnknown ServiceState = iota
	ServiceStateRunning
	ServiceStateStopped
	// ServiceStateStarting and ServiceStateStopping are transient. They are kept
	// distinct from running and stopped because a service that is permanently
	// "starting" is a specific, common and diagnosable failure.
	ServiceStateStarting
	ServiceStateStopping
	// ServiceStateFailed is a service the manager considers failed.
	ServiceStateFailed
)

// AllServiceStates is every state, in a stable order.
var AllServiceStates = []ServiceState{
	ServiceStateUnknown, ServiceStateRunning, ServiceStateStopped,
	ServiceStateStarting, ServiceStateStopping, ServiceStateFailed,
}

func (s ServiceState) String() string {
	switch s {
	case ServiceStateRunning:
		return "running"
	case ServiceStateStopped:
		return "stopped"
	case ServiceStateStarting:
		return "starting"
	case ServiceStateStopping:
		return "stopping"
	case ServiceStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// ServiceFacts is one managed service.
type ServiceFacts struct {
	// Name is the manager's own identifier — the unit name, the SCM service
	// name. It is the natural key, so it must be the stable machine-readable
	// one and not the display name.
	Name        string
	Command     string
	DisplayName string
	Kind        ServiceKind
	State       ServiceState

	// MainPID is the service's primary process where the manager reports one.
	// It is the evidence for the service→process relationship.
	MainPID    PID
	HasMainPID bool

	// Enabled reports whether the service starts at boot. A service that is
	// running but not enabled is a common and important finding.
	Enabled    bool
	HasEnabled bool
}

// ContainerRuntime identifies the runtime that created a container. Closed set.
type ContainerRuntime int

const (
	ContainerRuntimeUnknown ContainerRuntime = iota
	ContainerRuntimeDocker
	ContainerRuntimeContainerd
	ContainerRuntimeCRIO
	ContainerRuntimePodman
	// ContainerRuntimeLXC covers LXC and LXD.
	ContainerRuntimeLXC
)

func (r ContainerRuntime) String() string {
	switch r {
	case ContainerRuntimeDocker:
		return "docker"
	case ContainerRuntimeContainerd:
		return "containerd"
	case ContainerRuntimeCRIO:
		return "cri-o"
	case ContainerRuntimePodman:
		return "podman"
	case ContainerRuntimeLXC:
		return "lxc"
	default:
		return "unknown"
	}
}

// ContainerFacts is one container instance observed on this host.
//
// Everything here is derived from cgroup membership, which is why the module
// needs no container runtime socket. That matters more than it sounds: the
// Docker socket is root-equivalent, granting the agent write access to the whole
// host, and an observability agent that holds it has become the most valuable
// target on the machine. Reading cgroups is unprivileged and read-only.
type ContainerFacts struct {
	// ID is the runtime's container ID, as it appears in the cgroup path.
	ID      string
	Runtime ContainerRuntime

	// Kubernetes context, when the cgroup path carries it. Empty otherwise, and
	// never guessed.
	PodUID    string
	PodName   string
	Namespace string

	// Runtime detail, filled in only when the runtime API is reachable and the
	// operator has opted into reading it. A cgroup path carries an ID and
	// nothing else, so these stay empty on an unenriched host.
	Name        string
	Command     string
	Image       string
	State       string
	Status      string
	Ports       string
	CreatedUnix int64
}

// InterfaceFacts is one network interface.
//
// Privacy note: HardwareAddr and Addresses identify the machine on its networks,
// and both are collected because an infrastructure inventory without them cannot
// be correlated with anything else — a cloud ENI record, a switch port, a
// firewall rule. They are host-level facts about the agent's own machine, not
// observations of third parties, and the address list is capped so that an
// interface with a thousand aliases cannot become a thousand attributes.
type InterfaceFacts struct {
	Name  string
	Index int
	// HardwareAddr is the MAC in canonical lower-case colon form, or empty for
	// interfaces that have none.
	HardwareAddr string
	// Addresses are the configured addresses in CIDR form, bounded by
	// maxAddressesPerInterface and sorted for determinism.
	Addresses []string
	MTU       int

	Up       bool
	Loopback bool
	// Virtual marks interfaces created by software — bridges, veth pairs, tun
	// devices. On a container host these outnumber the physical interfaces by
	// two orders of magnitude, which is why they can be filtered out.
	Virtual bool
}

// Protocol is a transport protocol. Closed set; bounds an attribute.
type Protocol int

const (
	ProtocolUnknown Protocol = iota
	ProtocolTCP
	ProtocolUDP
	ProtocolTCP6
	ProtocolUDP6
)

// AllProtocols is every protocol, in a stable order.
var AllProtocols = []Protocol{
	ProtocolUnknown, ProtocolTCP, ProtocolUDP, ProtocolTCP6, ProtocolUDP6,
}

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolTCP6:
		return "tcp6"
	case ProtocolUDP6:
		return "udp6"
	default:
		return "unknown"
	}
}

// EndpointFacts is one LISTENING socket.
//
// Listeners only, and that boundary is deliberate. A listener is a stable fact
// about what this host offers: there are tens of them, they change rarely, and
// each is a genuine entity. An established connection is a flow between two
// hosts: there can be a hundred thousand, they change every second, the remote
// address is a third party's identity, and the pair (local, remote) is exactly
// the non-functional relationship that would make topology quadratic. Connection
// discovery is a Network Module problem with a different design, and is out of
// scope here rather than half-done here.
type EndpointFacts struct {
	Protocol Protocol
	// Address is the local bind address, normalised. The unspecified address is
	// reported as "0.0.0.0" or "::" rather than being resolved to a real one.
	Address string
	Port    uint16

	// OwnerPID is the owning process where the platform reports it directly
	// (Windows) or where socket-inode correlation established it (Linux).
	OwnerPID    PID
	HasOwnerPID bool

	// Inode is the Linux socket inode, retained only as correlation evidence
	// within a cycle. It is never emitted.
	Inode uint64
}

// FilesystemFacts is one mounted filesystem, as an entity rather than as usage.
type FilesystemFacts struct {
	Mountpoint string
	Device     string
	FSType     string

	ReadOnly bool
	// Remote marks network filesystems (NFS, CIFS, and friends). They are worth
	// distinguishing because a remote mount is a dependency on another host,
	// which is a topology fact rather than a storage one.
	Remote bool
}

// CloudProvider identifies a cloud or virtualisation platform. Closed set.
type CloudProvider int

const (
	CloudProviderUnknown CloudProvider = iota
	CloudProviderAWS
	CloudProviderGCP
	CloudProviderAzure
	CloudProviderOracle
	CloudProviderAlibaba
	CloudProviderOpenStack
	CloudProviderVMware
	CloudProviderKVM
	CloudProviderHyperV
	CloudProviderXen
	CloudProviderVirtualBox
	// CloudProviderBareMetal means the firmware evidence positively indicates
	// physical hardware, as distinct from Unknown, which means no evidence.
	CloudProviderBareMetal
)

// AllCloudProviders is every provider, in a stable order.
var AllCloudProviders = []CloudProvider{
	CloudProviderUnknown, CloudProviderAWS, CloudProviderGCP, CloudProviderAzure,
	CloudProviderOracle, CloudProviderAlibaba, CloudProviderOpenStack,
	CloudProviderVMware, CloudProviderKVM, CloudProviderHyperV, CloudProviderXen,
	CloudProviderVirtualBox, CloudProviderBareMetal,
}

func (p CloudProvider) String() string {
	switch p {
	case CloudProviderAWS:
		return "aws"
	case CloudProviderGCP:
		return "gcp"
	case CloudProviderAzure:
		return "azure"
	case CloudProviderOracle:
		return "oracle"
	case CloudProviderAlibaba:
		return "alibaba"
	case CloudProviderOpenStack:
		return "openstack"
	case CloudProviderVMware:
		return "vmware"
	case CloudProviderKVM:
		return "kvm"
	case CloudProviderHyperV:
		return "hyperv"
	case CloudProviderXen:
		return "xen"
	case CloudProviderVirtualBox:
		return "virtualbox"
	case CloudProviderBareMetal:
		return "bare_metal"
	default:
		return "unknown"
	}
}

// CloudFacts is what the platform underneath this host is.
//
// It is derived from LOCAL FIRMWARE EVIDENCE ONLY — the DMI/SMBIOS strings the
// hypervisor writes, which every provider sets and which any user may read. The
// module deliberately performs NO network call to a metadata service.
//
// That is a security decision, not a scoping shortcut. The link-local metadata
// endpoint at 169.254.169.254 is the canonical SSRF target: on IMDSv1 it serves
// IAM credentials to anything that can issue a GET, and an observability agent
// that speaks to it is a credential-fetching primitive running as root on every
// host in the fleet. Firmware strings identify the provider — which is the
// question worth asking — with none of that surface. What they cannot always
// supply is the instance ID, and the module reports that as unknown rather than
// reaching for the network to get it. See README.md.
type CloudFacts struct {
	Provider CloudProvider

	// InstanceID is the provider's own identifier where firmware exposes it.
	// AWS writes it to the DMI board asset tag; most providers do not expose it
	// locally at all, and it stays empty rather than being fetched.
	InstanceID string

	// Vendor and Product are the raw firmware strings the classification was
	// derived from, retained so an operator can see WHY the module concluded
	// what it did — and so an unrecognised platform reports something useful
	// instead of "unknown".
	Vendor  string
	Product string
}

// KubernetesFacts is the pod context of the AGENT ITSELF.
//
// Scope note: this is local self-context, not cluster discovery. The module
// reads the agent's own environment and its own cgroup; it does not contact the
// API server, does not use a kubeconfig, and does not read the service account
// TOKEN that sits in the same directory as the namespace file it does read. A
// Kubernetes Module that watches cluster resources is a different component with
// a different threat model, and stubbing it here would be worse than not having
// it.
type KubernetesFacts struct {
	InCluster bool
	Namespace string
	PodName   string
	PodUID    string
	NodeName  string
}

// RuntimeFacts is the execution environment the host is running IN.
type RuntimeFacts struct {
	// InContainer reports whether the agent itself is containerised.
	InContainer bool
	ContainerID string
	Runtime     ContainerRuntime
}

// ─────────────────────────────────────────────────────────────────────────────
// Sources. Narrow, one method each, split by DOMAIN and by COST.
//
// A single DiscoverySource interface would force every platform to implement
// every domain, and the only way to satisfy it where a domain is genuinely
// unavailable would be to return an empty slice — which reads downstream as
// "there are no services on this host" rather than "this platform cannot tell
// you about services". A nil source says the second thing.
// ─────────────────────────────────────────────────────────────────────────────

// HostSource reads host identity facts.
type HostSource interface {
	DiscoverHost(ctx context.Context) (HostFacts, error)
}

// ProcessOptions parameterises process discovery.
type ProcessOptions struct {
	// WantCgroups asks the source to populate ProcessFacts.CgroupPath.
	//
	// It is opt-in because on Linux it costs one extra file read per process. At
	// ten thousand processes that is ten thousand reads per cycle for evidence
	// that only matters when service or container discovery is enabled — so the
	// module asks for it only when something will use it, and the cost is
	// visible rather than buried.
	WantCgroups bool
	// WantUser asks the source to populate ProcessFacts.UID.
	WantUser bool
}

// ProcessSource enumerates processes for discovery purposes.
type ProcessSource interface {
	DiscoverProcesses(ctx context.Context, opts ProcessOptions) (ProcessListing, error)
}

// ProcessListing is one process enumeration.
//
// The three outcome counters mean three different things and only one of them is
// a fault, exactly as in the process module. Collapsing them is how a healthy,
// busy host gets reported as broken.
type ProcessListing struct {
	Processes []ProcessFacts
	// Vanished counts processes that exited mid-enumeration. Churn, not error.
	Vanished int
	// Denied counts processes the agent may not inspect. A privilege boundary.
	Denied int
	// Unreadable counts everything else. The only one that is a fault.
	Unreadable int
}

// ServiceSource enumerates managed services.
type ServiceSource interface {
	DiscoverServices(ctx context.Context) ([]ServiceFacts, error)
}

// ContainerSource enumerates containers from local evidence.
//
// It takes the process facts the module has ALREADY gathered, rather than
// enumerating for itself. That is unusual for a source interface and it is
// deliberate: on Linux, containers are proved by the cgroup paths of processes,
// so a self-contained container source would walk /proc a second time in the
// same cycle to read files the module is already holding. Putting the dependency
// in the signature makes it explicit and ordered, where sharing it through
// hidden state on the source object would make the module's call order a silent
// correctness requirement.
type ContainerSource interface {
	DiscoverContainers(ctx context.Context, procs []ProcessFacts) ([]ContainerFacts, error)
}

// InterfaceSource enumerates network interfaces.
type InterfaceSource interface {
	DiscoverInterfaces(ctx context.Context) ([]InterfaceFacts, error)
}

// EndpointSource enumerates listening sockets.
type EndpointSource interface {
	DiscoverEndpoints(ctx context.Context, opts EndpointOptions) ([]EndpointFacts, error)
}

// EndpointOptions parameterises endpoint discovery.
type EndpointOptions struct {
	// Correlate asks the source to establish which process owns each listener.
	//
	// On Windows this is free: the OS reports the owning PID in the same table.
	// On Linux it is NOT free — the kernel gives a socket inode, and mapping it
	// to a process means scanning /proc/PID/fd across the host. That is O(total
	// open descriptors), which on a large host is the single most expensive
	// thing this module could do, so it is opt-in and separately bounded.
	Correlate bool
	// MaxScans bounds how many processes may be scanned for descriptors when
	// correlating. Zero means the source's own default bound.
	MaxScans int
}

// FilesystemSource enumerates mounted filesystems.
type FilesystemSource interface {
	DiscoverFilesystems(ctx context.Context) ([]FilesystemFacts, error)
}

// RuntimeSource reads the agent's own execution environment.
type RuntimeSource interface {
	DiscoverRuntime(ctx context.Context) (RuntimeFacts, error)
}

// CloudSource reads cloud/virtualisation platform evidence.
type CloudSource interface {
	DiscoverCloud(ctx context.Context) (CloudFacts, error)
}

// KubernetesSource reads the agent's own pod context.
//
// This is the EXTENSION SEAM the phase requires: Kubernetes support is an
// optional source that is present only where the environment actually provides
// the evidence, so nothing about Kubernetes is mandatory, no client library is
// linked, and a host that has never heard of Kubernetes reports the source as
// unavailable with a reason.
type KubernetesSource interface {
	DiscoverKubernetes(ctx context.Context) (KubernetesFacts, error)
}

// Domain is one area of discovery. The set is closed, which bounds the `domain`
// telemetry attribute and makes the capability report a fixed size.
type Domain int

const (
	DomainHost Domain = iota
	DomainProcess
	DomainService
	DomainContainer
	DomainInterface
	DomainEndpoint
	DomainFilesystem
	DomainRuntime
	DomainCloud
	DomainKubernetes
)

// AllDomains is every domain, in a stable order.
var AllDomains = []Domain{
	DomainHost, DomainProcess, DomainService, DomainContainer, DomainInterface,
	DomainEndpoint, DomainFilesystem, DomainRuntime, DomainCloud, DomainKubernetes,
}

func (d Domain) String() string {
	switch d {
	case DomainHost:
		return "host"
	case DomainProcess:
		return "process"
	case DomainService:
		return "service"
	case DomainContainer:
		return "container"
	case DomainInterface:
		return "interface"
	case DomainEndpoint:
		return "endpoint"
	case DomainFilesystem:
		return "filesystem"
	case DomainRuntime:
		return "runtime"
	case DomainCloud:
		return "cloud"
	case DomainKubernetes:
		return "kubernetes"
	default:
		return "unknown"
	}
}

func domainByName(name string) (Domain, bool) {
	for _, d := range AllDomains {
		if d.String() == name {
			return d, true
		}
	}
	return 0, false
}

// Unsupported records why a domain is unavailable, so the module can emit one
// precise diagnostic instead of a generic "not available".
type Unsupported struct {
	Domain Domain
	Reason string
}

// Set is the platform's source implementations. A nil field means the platform
// cannot provide that domain; Unsupported carries the reason.
type Set struct {
	Host       HostSource
	Process    ProcessSource
	Service    ServiceSource
	Container  ContainerSource
	Interface  InterfaceSource
	Endpoint   EndpointSource
	Filesystem FilesystemSource
	Runtime    RuntimeSource
	Cloud      CloudSource
	Kubernetes KubernetesSource

	Unsupported []Unsupported
}

// Has reports whether a domain has a source.
func (s Set) Has(d Domain) bool {
	switch d {
	case DomainHost:
		return s.Host != nil
	case DomainProcess:
		return s.Process != nil
	case DomainService:
		return s.Service != nil
	case DomainContainer:
		return s.Container != nil
	case DomainInterface:
		return s.Interface != nil
	case DomainEndpoint:
		return s.Endpoint != nil
	case DomainFilesystem:
		return s.Filesystem != nil
	case DomainRuntime:
		return s.Runtime != nil
	case DomainCloud:
		return s.Cloud != nil
	case DomainKubernetes:
		return s.Kubernetes != nil
	default:
		return false
	}
}

// UnsupportedReason returns the recorded reason for an absent domain.
func (s Set) UnsupportedReason(d Domain) string {
	for _, u := range s.Unsupported {
		if u.Domain == d {
			return u.Reason
		}
	}
	if s.Has(d) {
		return ""
	}
	return "not implemented on this platform"
}

// Available returns the domains that have sources, in a stable order.
func (s Set) Available() []Domain {
	var out []Domain
	for _, d := range AllDomains {
		if s.Has(d) {
			out = append(out, d)
		}
	}
	return out
}

// NewSet returns the source set for the platform this binary was built for.
// It is supplied by exactly one build-tagged file.
func NewSet() Set { return platformSet() }
