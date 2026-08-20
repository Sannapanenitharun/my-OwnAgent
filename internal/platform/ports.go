// Package platform defines the ports through which the observability agent
// reaches the enterprise platform (Capability Runtime, Telemetry Plane,
// IAM/Identity, and time).
//
// These are PORTS, not a second platform. The agent owns no runtime, no
// telemetry pipeline, no transport and no identity authority; it depends on
// narrow interfaces that a platform adapter satisfies. See ADR-0001.
//
// Stability: the interfaces in this package are PROVISIONAL. They were derived
// from the agent's Stage 1 requirements, not from the frozen platform
// contracts, which were not available at implementation time. When the real
// platform contracts are available, the expectation is that only
// internal/platform/* changes; no module, the supervisor, or the agent shell
// should need to move.
package platform

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrUnsupported reports that a port implementation cannot provide a value on
// this platform or in this deployment. Callers must surface it as an explicit
// diagnostic and degrade; they must never substitute a fabricated value.
var ErrUnsupported = errors.New("platform: unsupported")

// ErrUnresolved reports that an identifier could not be resolved. Per the data
// quality rules, callers must emit an unresolved diagnostic rather than invent
// an identifier.
var ErrUnresolved = errors.New("platform: unresolved")

// ErrDenied reports that an authorization check failed. Authorization is
// fail-closed: any error from Authorize, including transport failures, denies
// the operation.
var ErrDenied = errors.New("platform: permission denied")

// Permission is an opaque capability permission string evaluated by the
// platform IAM. The agent never interprets or expands permissions locally.
type Permission string

// CapabilityDescriptor describes a unit of functionality the agent registers
// with the platform Capability Runtime.
type CapabilityDescriptor struct {
	// ID uniquely identifies the capability within the agent, e.g. "host".
	ID string
	// Version is the capability implementation version.
	Version string
	// Permissions are the permissions the capability requires to operate.
	Permissions []Permission
}

// Lease is the handle returned when a capability is admitted by the Capability
// Runtime. Releasing a lease deregisters the capability.
type Lease interface {
	// Release deregisters the capability. It is safe to call more than once.
	Release(ctx context.Context) error
}

// CapabilityRuntime is the port to the platform Capability Runtime. It owns
// capability admission and permission grants.
//
// It deliberately does NOT own per-process supervision (restart, crash-loop
// protection, health aggregation of OS-level collectors); that is an agent-host
// concern and lives in internal/supervisor. See ADR-0002 for the rationale.
type CapabilityRuntime interface {
	// Register admits a capability. A non-nil error means the capability must
	// not start.
	Register(ctx context.Context, desc CapabilityDescriptor) (Lease, error)

	// Authorize checks a single permission for an already-registered
	// capability. Implementations MUST fail closed.
	Authorize(ctx context.Context, capabilityID string, perm Permission) error
}

// Attr is a single telemetry attribute. Attribute values are deliberately
// restricted to bounded-cardinality scalars.
type Attr struct {
	Key   string
	Value string
}

// A returns an Attr. It exists to keep call sites terse.
func A(key, value string) Attr { return Attr{Key: key, Value: value} }

// Counter is a monotonically increasing instrument.
type Counter interface {
	Add(delta int64, attrs ...Attr)
}

// Gauge is a point-in-time instrument.
type Gauge interface {
	Set(value float64, attrs ...Attr)
}

// Histogram records a distribution of values.
type Histogram interface {
	Observe(value float64, attrs ...Attr)
}

// EventSeverity classifies a telemetry event.
type EventSeverity int

const (
	SeverityDebug EventSeverity = iota
	SeverityInfo
	SeverityWarn
	SeverityError
)

func (s EventSeverity) String() string {
	switch s {
	case SeverityDebug:
		return "debug"
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	default:
		return "unknown"
	}
}

// Event is a discrete, structured telemetry record.
//
// Event carries no free-form payload by design: everything emitted through this
// port is subject to secret scrubbing at the Telemetry Plane boundary, and
// bounded structured attributes are far cheaper to scrub and to bound for
// cardinality than arbitrary text.
type Event struct {
	Name      string
	Severity  EventSeverity
	Timestamp time.Time
	Attrs     []Attr
}

// LogRecord is a collected log line (or journal/event-log entry).
//
// Unlike Event, LogRecord carries a body: that is the signal. Bodies MUST be
// truncated and redacted before they reach this port. The port itself still
// bounds what it retains so a noisy source cannot fill the agent.
type LogRecord struct {
	Timestamp time.Time
	Severity  EventSeverity
	Body      string
	Attrs     []Attr
}

// TracePayload is one OTLP request received from a local application.
//
// The agent does not invent spans. It forwards what an instrumented process
// sent, optionally wrapping host resource attributes at the adapter. ContentType
// is the request's Content-Type so the adapter can distinguish protobuf and JSON.
// Signal is "traces" (default), "logs" or "metrics".
type TracePayload struct {
	ContentType string
	Body        []byte
	Signal      string
}

// Telemetry is the port to the platform Telemetry Plane. The agent's own
// self-observability flows through this port; the agent does not build a
// separate monitoring system for itself.
type Telemetry interface {
	Counter(name string) Counter
	Gauge(name string) Gauge
	Histogram(name string) Histogram
	Emit(ev Event)
	EmitLog(rec LogRecord)
	IngestTraces(payload TracePayload)
}

// Shutdowner is an optional Telemetry capability: flush and release export
// resources. Adapters that do not implement it have nothing to tear down.
type Shutdowner interface {
	Shutdown(ctx context.Context) error
}

// ShutdownTelemetry shuts down tel if it can. It is safe to call with any
// Telemetry, including those that only terminate in memory.
func ShutdownTelemetry(ctx context.Context, tel Telemetry) error {
	if s, ok := tel.(Shutdowner); ok {
		return s.Shutdown(ctx)
	}
	return nil
}

// Identity is the port to platform IAM/Identity/Tenancy.
//
// Every accessor may fail. A failure means the identifier is unresolved and the
// caller must emit an unresolved diagnostic; callers must never synthesize an
// identifier locally.
type Identity interface {
	// AgentID is the stable identity of this agent installation.
	AgentID(ctx context.Context) (string, error)
	// TenantID is the tenant this agent reports into.
	TenantID(ctx context.Context) (string, error)
	// HostID is the deterministic entity identifier of the host, as assigned
	// by the platform Discovery Runtime / Digital Twin.
	HostID(ctx context.Context) (string, error)
}

// EntityKind classifies an entity the agent observes. The set is CLOSED and
// small, because it is part of the vocabulary shared with the platform's entity
// taxonomy rather than something a collector invents.
//
// Closed is the operative word. A collector that could mint a new kind would be
// extending the platform's taxonomy unilaterally, and two collectors that each
// invented "svc" and "service" would produce an entity graph nobody can query.
// Adding a kind is therefore an edit to this file — additive, reviewable, and
// visible to whoever owns the taxonomy — rather than a string literal in a
// module. See ADR-0006.
type EntityKind string

const (
	// EntityKindHost is the machine the agent runs on.
	EntityKindHost EntityKind = "host"
	// EntityKindProcess is a single process INSTANCE — not a PID. A PID is
	// reused; a process instance is not.
	EntityKindProcess EntityKind = "process"

	// The kinds below were added for the discovery module (Stage 4). They are
	// purely additive: nothing that existed before this point changes meaning,
	// and an adapter that has never heard of them is not broken — it fails to
	// resolve them, which is the contract's existing degradation path.

	// EntityKindService is a unit of managed, supervised software on the host:
	// a systemd unit, a Windows service. It is NOT a network service and not a
	// logical application; it is the thing the host's init system starts.
	EntityKindService EntityKind = "service"
	// EntityKindApplication is a GROUPING of processes that evidence shows
	// belong together. It exists separately from Service because a host may run
	// an application that no init system manages.
	EntityKindApplication EntityKind = "application"
	// EntityKindContainer is one container instance on this host.
	EntityKindContainer EntityKind = "container"
	// EntityKindNetworkInterface is one network interface of the host.
	EntityKindNetworkInterface EntityKind = "network_interface"
	// EntityKindNetworkEndpoint is one bound listening socket: an address, a
	// port and a protocol. It is a LISTENER, not a connection — a connection is
	// a flow between two endpoints and has entirely different cardinality
	// properties.
	EntityKindNetworkEndpoint EntityKind = "network_endpoint"
	// EntityKindFilesystem is one mounted filesystem.
	EntityKindFilesystem EntityKind = "filesystem"
	// EntityKindRuntime is the execution environment the host itself is in:
	// bare metal, a hypervisor guest, a container, a Kubernetes pod.
	EntityKindRuntime EntityKind = "runtime"
	// EntityKindCloudInstance is the cloud or virtualisation provider's own
	// notion of this machine.
	EntityKindCloudInstance EntityKind = "cloud_instance"
	// EntityKindKubernetesPod is the pod this agent, or an observed container,
	// belongs to.
	EntityKindKubernetesPod EntityKind = "kubernetes_pod"
	// EntityKindDatabase is a database instance running on this host, detected
	// from direct local evidence.
	EntityKindDatabase EntityKind = "database"
)

// AllEntityKinds is every kind, in a stable order. It exists so that tests can
// assert the taxonomy is closed, and so that a collector reporting per-kind
// counts emits a fixed, bounded set of series.
var AllEntityKinds = []EntityKind{
	EntityKindHost, EntityKindProcess, EntityKindService, EntityKindApplication,
	EntityKindContainer, EntityKindNetworkInterface, EntityKindNetworkEndpoint,
	EntityKindFilesystem, EntityKindRuntime, EntityKindCloudInstance,
	EntityKindKubernetesPod, EntityKindDatabase,
}

// EntityRef is a NATURAL KEY for an entity: the stable, observable properties
// that identify one real thing, expressed so that the platform can map them
// onto its own identifier.
//
// It is deliberately not an identifier. A collector observes facts (this PID,
// started at this instant, on this host) and asks the platform what entity they
// denote. The answer is the platform's to give, and a collector that computed it
// locally would fork the entity graph the first time two components hashed the
// same facts differently.
type EntityRef struct {
	// Kind is the entity taxonomy entry.
	Kind EntityKind
	// Parent is the already-resolved EntityID of the containing entity, if any
	// — a process hangs off its host. Empty when the entity stands alone.
	Parent string
	// Keys is the natural key, in a stable order chosen by the collector. Every
	// value must be bounded and non-secret: these travel to the platform and
	// may be persisted against the entity.
	Keys []Attr
}

// EntityResolver is an OPTIONAL capability of an Identity adapter: mapping an
// observed natural key onto a platform EntityID.
//
// It is optional rather than part of Identity so that this is a purely additive
// extension — every existing adapter keeps compiling and keeps working. Callers
// discover it with a type assertion, which ResolveEntity below does once so that
// no collector repeats it.
//
// An adapter that does not implement it is not broken: the caller emits an
// unresolved diagnostic and continues with host-scoped telemetry. That is the
// same contract Identity already has, and it is why an absent resolver degrades
// fidelity rather than function.
type EntityResolver interface {
	ResolveEntity(ctx context.Context, ref EntityRef) (string, error)
}

// ResolveEntity resolves a natural key through id, if id can resolve entities.
//
// It returns ErrUnsupported when the adapter has no resolver, which callers must
// treat exactly like ErrUnresolved: emit a diagnostic, bind nothing, and never
// substitute a locally computed identifier.
func ResolveEntity(ctx context.Context, id Identity, ref EntityRef) (string, error) {
	r, ok := id.(EntityResolver)
	if !ok {
		return "", fmt.Errorf("%w: identity adapter cannot resolve entities", ErrUnsupported)
	}
	return r.ResolveEntity(ctx, ref)
}

// Ticker abstracts time.Ticker so that time can be controlled in tests.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Clock abstracts wall-clock time and timers.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
}

// Ports bundles every platform dependency the agent needs. Passing this single
// value keeps constructor signatures stable as ports are added.
type Ports struct {
	Runtime   CapabilityRuntime
	Telemetry Telemetry
	Identity  Identity
	Clock     Clock
}

// Validate reports whether every required port is populated. A nil port is a
// programming error, not a runtime condition, so the agent refuses to start
// rather than nil-checking at every call site.
func (p Ports) Validate() error {
	var missing []string
	if p.Runtime == nil {
		missing = append(missing, "Runtime")
	}
	if p.Telemetry == nil {
		missing = append(missing, "Telemetry")
	}
	if p.Identity == nil {
		missing = append(missing, "Identity")
	}
	if p.Clock == nil {
		missing = append(missing, "Clock")
	}
	if len(missing) > 0 {
		return &MissingPortsError{Missing: missing}
	}
	return nil
}

// MissingPortsError reports unpopulated platform ports.
type MissingPortsError struct {
	Missing []string
}

func (e *MissingPortsError) Error() string {
	return "platform: missing required ports: " + joinStrings(e.Missing, ", ")
}

func joinStrings(in []string, sep string) string {
	switch len(in) {
	case 0:
		return ""
	case 1:
		return in[0]
	}
	n := len(sep) * (len(in) - 1)
	for _, s := range in {
		n += len(s)
	}
	b := make([]byte, 0, n)
	b = append(b, in[0]...)
	for _, s := range in[1:] {
		b = append(b, sep...)
		b = append(b, s...)
	}
	return string(b)
}
