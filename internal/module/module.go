// Package module defines the single lifecycle contract every part of the
// observability agent implements.
//
// There is exactly one module contract. Collectors (host, process, logs, ebpf,
// network, security, profiler), discovery, and processing components
// (otel-engine, secret-scrubber) all satisfy it, which is what makes the agent
// one product rather than a bundle of daemons sharing a binary.
//
// The required surface is small — Manifest, Start, Stop, Health — and the rest
// of the contract (pause/resume, configure, diagnostics, statistics) is
// expressed as optional interfaces with defined default behaviour. This is
// deliberate: a mandatory twelve-method interface would be satisfied by twelve
// empty methods per module, which looks like conformance while providing none.
// An optional interface is either implemented and meaningful, or absent and
// answerable ("this module cannot be paused"), and the supervisor can tell the
// difference.
package module

import (
	"context"
	"log/slog"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/platform"
)

// ID uniquely identifies a module within the agent.
type ID string

func (id ID) String() string { return string(id) }

// Category classifies a module's role in the agent.
type Category int

const (
	// CategoryCollector produces observations from the host.
	CategoryCollector Category = iota
	// CategoryDiscovery discovers entities and relationships.
	CategoryDiscovery
	// CategoryProcessing transforms telemetry in the pipeline.
	CategoryProcessing
	// CategoryLifecycle manages the agent itself.
	CategoryLifecycle
)

func (c Category) String() string {
	switch c {
	case CategoryCollector:
		return "collector"
	case CategoryDiscovery:
		return "discovery"
	case CategoryProcessing:
		return "processing"
	case CategoryLifecycle:
		return "lifecycle"
	default:
		return "unknown"
	}
}

// Priority orders modules for resource governance.
//
// The field is carried in the manifest from Stage 1 so that manifests do not
// have to change when the resource governor lands in Stage 13. It is NOT
// enforced yet; see docs/READINESS.md, which records this explicitly rather
// than letting it read as a working feature.
type Priority int

const (
	// PriorityCritical must keep running under any pressure.
	PriorityCritical Priority = iota
	// PriorityHigh is shed only after all lower priorities.
	PriorityHigh
	// PriorityNormal is the default.
	PriorityNormal
	// PriorityLow is shed first under resource pressure.
	PriorityLow
)

func (p Priority) String() string {
	switch p {
	case PriorityCritical:
		return "critical"
	case PriorityHigh:
		return "high"
	case PriorityNormal:
		return "normal"
	case PriorityLow:
		return "low"
	default:
		return "unknown"
	}
}

// Capability is a named unit of functionality a module may or may not be able
// to provide in the current environment.
//
// Availability is reported, never assumed. An eBPF module on Windows reports
// its capabilities as unavailable with a reason; it does not report success
// with empty data, and it does not fail the agent.
type Capability struct {
	Name      string
	Available bool
	// Reason explains unavailability. Required when Available is false.
	Reason string
}

// Manifest is a module's static declaration. It is fixed for the life of the
// process and must not depend on configuration or runtime state.
type Manifest struct {
	ID           ID
	Version      string
	Category     Category
	Description  string
	Dependencies []ID
	// Permissions are the platform permissions the module requires. The
	// supervisor registers them with the Capability Runtime before start and
	// refuses to start the module if any is denied.
	Permissions []platform.Permission
	Priority    Priority
}

// Host is the set of services the supervisor provides to a module.
//
// A module receives exactly this and nothing more. It has no reference to the
// supervisor, to other modules, or to platform internals, which is what keeps
// module-to-module coupling impossible rather than merely discouraged.
type Host struct {
	// ID is the receiving module's own ID.
	ID ID
	// Logger is scoped to the module.
	Logger *slog.Logger
	// Telemetry is the platform Telemetry Plane port. All module telemetry
	// leaves through it; modules do not export anything themselves.
	Telemetry platform.Telemetry
	// Clock is the time source. Modules must not call time.Now directly, so
	// that collection intervals are testable.
	Clock platform.Clock
	// Identity resolves agent, tenant and host identifiers. A failure means
	// unresolved: modules must not invent identifiers.
	Identity platform.Identity
	// Diagnostics is scoped to the module; the source field is stamped
	// automatically and cannot be forged.
	Diagnostics diagnostics.Sink
	// Authorize checks a permission for this module against platform IAM. It
	// fails closed.
	Authorize func(ctx context.Context, perm platform.Permission) error
	// ReportFailure tells the supervisor that the module has failed
	// unrecoverably after a successful Start.
	//
	// Start returns promptly and the module's real work runs on goroutines it
	// owns, so a failure in that work is invisible to the supervisor unless
	// the module says so. Without this callback, a module whose collection
	// loop died would sit in StateRunning forever, silently collecting
	// nothing — the worst failure mode an observability agent can have.
	//
	// It is safe to call from any goroutine and is non-blocking. Repeated
	// calls before the supervisor acts are coalesced.
	ReportFailure func(err error)
	// Config is the module's fragment at start time. Later changes arrive
	// through the Configurable interface, not by mutating this value.
	Config config.ModuleConfig
}

// Module is the required contract. Every module implements it.
type Module interface {
	// Manifest returns the module's static declaration. It must be
	// side-effect free and safe to call at any time, including before Start.
	Manifest() Manifest

	// Start begins collection or processing. It must return promptly: any
	// ongoing work belongs on goroutines the module owns and stops in Stop.
	// Start must not block for the module's lifetime.
	//
	// Returning ErrUnsupported means the module cannot operate in this
	// environment. That is not a failure: the supervisor marks the module
	// unsupported, records a diagnostic, degrades agent health and does not
	// retry.
	Start(ctx context.Context, host Host) error

	// Stop halts the module and releases its resources. It must be idempotent
	// and must respect ctx deadlines. Stop is called even if Start failed, so
	// it must tolerate being called on a module that never fully started.
	Stop(ctx context.Context) error

	// Health reports current health. It must be cheap, non-blocking, and must
	// never perform collection work: the supervisor calls it on a timer and a
	// slow probe is indistinguishable from a hung module.
	Health(ctx context.Context) health.Report
}

// Pausable is implemented by modules that can suspend work without releasing
// resources. The resource governor uses it to shed load; the supervisor uses it
// during configuration reloads.
//
// A module that does not implement Pausable is reported as not pausable rather
// than silently ignored.
type Pausable interface {
	Pause(ctx context.Context) error
	Resume(ctx context.Context) error
}

// Configurable is implemented by modules whose configuration can change at
// runtime. It is a three-phase transaction, and the phases mean exactly this:
//
//	PrepareConfig — validate and stage. MUST NOT change live behaviour. May
//	                allocate and open resources. Returning an error aborts the
//	                whole agent reload, not just this module.
//	CommitConfig  — atomically switch to the staged configuration. Must not
//	                fail for reasons that could have been detected in prepare.
//	RollbackConfig— discard the staged configuration and release anything
//	                prepare allocated. Must be safe with nothing staged.
//
// This is what makes "invalid configuration must not partially apply" a
// property of the system rather than an aspiration.
type Configurable interface {
	PrepareConfig(ctx context.Context, cfg config.ModuleConfig) error
	CommitConfig(ctx context.Context) error
	RollbackConfig(ctx context.Context) error
}

// Diagnosable is implemented by modules that can describe their current
// constraints on demand, beyond the diagnostics they push to their sink.
type Diagnosable interface {
	Diagnostics(ctx context.Context) []diagnostics.Record
}

// Statistics is a bounded set of module counters and gauges.
//
// Keys must be a fixed, small set chosen by the module. This is a diagnostic
// surface, not a metrics pipeline: telemetry goes through Host.Telemetry.
type Statistics struct {
	Counters map[string]int64
	Gauges   map[string]float64
}

// StatisticsReporter is implemented by modules exposing operational counters.
type StatisticsReporter interface {
	Statistics(ctx context.Context) Statistics
}

// CapabilityReporter is implemented by modules that expose which of their
// capabilities are available in the current environment.
type CapabilityReporter interface {
	Capabilities(ctx context.Context) []Capability
}
