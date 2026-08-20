// Package process is the agent's process observability module.
//
// The hard problem here is NOT reading process information. It is doing so on a
// host with fifty thousand processes that are constantly starting and stopping,
// without the agent becoming the incident. Four properties carry that weight:
//
//   - IDENTITY IS AN INSTANCE, NOT A PID. PIDs are reused within minutes on a
//     busy host. Every piece of per-process state is keyed by (boot, pid, start)
//     so that a recycled PID is recognised as a different process rather than
//     silently inheriting the previous one's counter baselines.
//
//   - CARDINALITY IS BOUNDED BY DISTINCT EXECUTABLES, NOT BY PROCESS COUNT.
//     Metrics roll up by executable name and carry no PID. Ten thousand
//     processes on a typical host are a few dozen distinct executables, so the
//     series count is flat in the thing that actually grows.
//
//   - CHEAP READS COME FIRST. One enumeration read per process yields identity
//     and basic statistics. The expensive per-process reads — I/O counters, open
//     file descriptors, executable path, command line — happen only for the
//     bounded set that survived filtering and selection.
//
//   - CHURN IS NORMAL, NOT AN ERROR. A process that exits between enumeration
//     and inspection is the expected case, counted as churn and never as a read
//     failure. An agent that treated it as an error would report a busy host as
//     permanently unhealthy.
//
// The module contains no OS-specific code; one build-tagged file per platform
// supplies the readers. Concurrency: readers are called from a single collection
// goroutine, one at a time, and need not be safe for concurrent use.
package process

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported reports that a reader cannot provide a value in this
// environment.
var ErrUnsupported = errors.New("process: unsupported")

// U64 is an optionally-known unsigned value. A zero that means "not available"
// is indistinguishable from a genuine zero, and a plausible wrong number is
// worse than no number.
//
// This duplicates the host module's type by design: modules may not import each
// other, and a four-line value type is a far smaller cost than two collectors
// sharing a release cadence. See internal/architecture.
type U64 struct {
	V  uint64
	OK bool
}

// KnownU64 returns a known value.
func KnownU64(v uint64) U64 { return U64{V: v, OK: true} }

// PID is an operating system process identifier.
//
// It is a transient handle, not an identity: see InstanceKey. Nothing in this
// module keys durable state on a PID alone, and no PID ever becomes a metric
// label.
type PID int32

// State is a process's run state, normalised across platforms. The set is
// closed and small, which is what keeps the `state` telemetry attribute bounded.
type State int

const (
	// StateUnknown means the platform did not report a state. It is emitted as
	// "unknown" rather than being mapped onto a plausible value.
	StateUnknown State = iota
	StateRunning
	StateSleeping
	// StateDiskSleep is uninterruptible sleep — a process blocked in the
	// kernel. It is distinguished from ordinary sleep because a rising count is
	// one of the clearest signals of a storage problem.
	StateDiskSleep
	StateStopped
	StateZombie
	StateIdle
)

// AllStates is every state, in a stable order.
var AllStates = []State{
	StateUnknown, StateRunning, StateSleeping, StateDiskSleep,
	StateStopped, StateZombie, StateIdle,
}

func (s State) String() string {
	switch s {
	case StateRunning:
		return "running"
	case StateSleeping:
		return "sleeping"
	case StateDiskSleep:
		return "disk_sleep"
	case StateStopped:
		return "stopped"
	case StateZombie:
		return "zombie"
	case StateIdle:
		return "idle"
	default:
		return "unknown"
	}
}

// Info is the result of the CHEAP per-process read.
//
// Everything here is obtainable in one operation per process on Linux
// (/proc/PID/stat), and in one operation for ALL processes on Windows
// (a toolhelp snapshot) and Darwin (one sysctl). That is what makes it safe to
// gather for every process on the host before any filtering has happened.
//
// Every optional field is optional because some platform genuinely cannot
// supply it, not because it might be inconvenient to read.
type Info struct {
	PID  PID
	PPID PID

	// Name is the executable name as the kernel reports it. It is TRUNCATED on
	// Unix — 15 characters on Linux, 16 on Darwin — because that is what the
	// kernel stores. The full path is available only through the optional
	// PathReader, and only for selected processes, so Name is what the
	// `executable` attribute is built from and its truncation is a documented
	// property rather than a surprise.
	Name  string
	State State

	// StartRaw is the platform's native, exact process start stamp: jiffies
	// since boot on Linux, a FILETIME on Windows, microseconds on Darwin. It is
	// the instance key's discriminator, and it is kept raw because converting to
	// wall-clock time introduces rounding that would let two consecutive
	// instances of a recycled PID compare equal.
	StartRaw    uint64
	HasStartRaw bool

	// StartTime is the absolute start instant, for telemetry. It may be unknown
	// even when StartRaw is known, if the platform cannot supply boot time.
	StartTime    time.Time
	HasStartTime bool

	// CPUUserNanos and CPUSystemNanos are cumulative CPU time in NANOSECONDS.
	// Readers convert from their native unit — jiffies, 100ns FILETIME ticks —
	// because the unit is only knowable where the value is read, and a
	// divisor threaded through the generic code is a unit bug waiting to
	// happen.
	CPUUserNanos   U64
	CPUSystemNanos U64

	RSSBytes     U64
	VirtualBytes U64
	Threads      U64

	// UID is the numeric owning user. No name lookup is performed: resolving it
	// would mean reading the password database (or querying a directory service)
	// once per process, which is both a cost and an information-disclosure
	// surface the module does not need.
	UID U64
}

// CPUNanos returns total cumulative CPU time, known only if both halves are.
func (i Info) CPUNanos() U64 {
	if !i.CPUUserNanos.OK || !i.CPUSystemNanos.OK {
		return U64{}
	}
	return KnownU64(i.CPUUserNanos.V + i.CPUSystemNanos.V)
}

// IOCounters are a process's cumulative I/O counters.
type IOCounters struct {
	ReadBytes  U64
	WriteBytes U64
	ReadOps    U64
	WriteOps   U64
}

// BootIdentity identifies one boot of the host.
//
// It matters because StartRaw on Linux is measured from boot: without a boot
// discriminator, a process started 500 jiffies after boot and another started
// 500 jiffies after the NEXT boot would share an instance key. Agents that
// restart across a reboot and reuse persisted state get this wrong.
type BootIdentity struct {
	// ID is a stable per-boot identifier where the platform has one.
	ID string
	// Time is the boot instant, used to convert StartRaw into wall-clock time.
	Time    time.Time
	HasTime bool
}

// Feature is one unit of process observability. The set is closed, which is what
// bounds the `feature` telemetry attribute and makes the capability report a
// fixed size.
type Feature int

const (
	// FeatureEnumeration is the ability to list processes at all. Without it
	// the module has nothing to do and reports unsupported.
	FeatureEnumeration Feature = iota
	FeatureCPU
	FeatureMemory
	FeatureThreads
	FeatureState
	FeatureIO
	FeatureOpenFiles
	FeatureExecutablePath
	FeatureCommandLine
	FeatureUser
)

// AllFeatures is every feature, in a stable order.
var AllFeatures = []Feature{
	FeatureEnumeration, FeatureCPU, FeatureMemory, FeatureThreads, FeatureState,
	FeatureIO, FeatureOpenFiles, FeatureExecutablePath, FeatureCommandLine,
	FeatureUser,
}

func (f Feature) String() string {
	switch f {
	case FeatureEnumeration:
		return "enumeration"
	case FeatureCPU:
		return "cpu"
	case FeatureMemory:
		return "memory"
	case FeatureThreads:
		return "threads"
	case FeatureState:
		return "state"
	case FeatureIO:
		return "io"
	case FeatureOpenFiles:
		return "open_files"
	case FeatureExecutablePath:
		return "executable_path"
	case FeatureCommandLine:
		return "command_line"
	case FeatureUser:
		return "user"
	default:
		return "unknown"
	}
}

func featureByName(name string) (Feature, bool) {
	for _, f := range AllFeatures {
		if f.String() == name {
			return f, true
		}
	}
	return 0, false
}

// The reader interfaces are narrow and separated by COST as well as by concern.
//
// Lister is the one cheap bulk operation. Everything else is a per-process call
// that the module makes only for the bounded selected set, so the interface
// split is what makes "cheap filter before expensive read" structural rather
// than a rule someone has to remember.

// ListOptions parameterises an enumeration.
type ListOptions struct {
	// Accept is consulted with each PID BEFORE any per-process work, so a
	// platform that reads a file or opens a handle per process can skip it
	// entirely for PIDs the module has already excluded. A nil Accept admits
	// everything.
	Accept func(PID) bool

	// WantUser asks the reader to populate Info.UID.
	//
	// It is a separate flag rather than something always done because on Linux
	// it costs an extra stat(2) per process. At fifty thousand processes that is
	// fifty thousand syscalls per cycle for a field most deployments never
	// filter on, so the cost is opt-in and visible.
	WantUser bool
}

func (o ListOptions) accept(pid PID) bool {
	return o.Accept == nil || o.Accept(pid)
}

// Lister enumerates processes and reads their cheap identity and statistics.
//
// A process that disappears between enumeration and inspection must be OMITTED
// from the result, not reported as an error: that race is the normal case on a
// busy host, and its count is reported separately through Vanished.
type Lister interface {
	ListProcesses(ctx context.Context, opts ListOptions) (Listing, error)
}

// Listing is one enumeration.
//
// The three counters are separated because they mean three different things and
// only one of them is a fault. Collapsing them into a single "errors" number is
// how a healthy, busy host ends up reported as broken.
type Listing struct {
	Processes []Info
	// Vanished counts PIDs that were enumerated but had exited before their
	// details could be read. This is CHURN. It is expected, it is not a failure,
	// and it never affects health.
	Vanished int
	// Denied counts processes the agent is not permitted to inspect. This is a
	// PRIVILEGE BOUNDARY — on Windows, an unelevated agent cannot open another
	// user's processes, and on Linux /proc/PID/io is owner-only. It is expected
	// and, by default, does not affect health either.
	Denied int
	// Unreadable counts PIDs that failed for any other reason. This is the only
	// one of the three that indicates something is actually wrong, and it is the
	// only one that feeds the health thresholds.
	Unreadable int
}

// IOReader reads a process's cumulative I/O counters.
type IOReader interface {
	ReadIO(ctx context.Context, pid PID) (IOCounters, error)
}

// FileReader reads how many file descriptors or handles a process holds.
type FileReader interface {
	ReadOpenFiles(ctx context.Context, pid PID) (U64, error)
}

// PathReader reads a process's executable path.
type PathReader interface {
	ReadExecutablePath(ctx context.Context, pid PID) (string, error)
}

// Bounds on collected command lines.
//
// argv is entirely under the observed process's control — it can be rewritten at
// runtime and can be megabytes long. These caps are applied in the READER, at
// the point the untrusted bytes enter the agent, so that no later stage has to
// be trusted to bound them.
const (
	maxCommandArgs  = 32
	maxCommandBytes = 4096
)

// CommandReader reads a process's command line.
//
// Command lines routinely contain credentials passed as arguments. Collection is
// OFF by default, the result never becomes a metric label, and it leaves the
// module only through the Telemetry Plane's event path where central scrubbing
// applies. See the security notes in README.md.
type CommandReader interface {
	ReadCommandLine(ctx context.Context, pid PID) ([]string, error)
}

// BootReader reads the host's boot identity.
type BootReader interface {
	ReadBootIdentity(ctx context.Context) (BootIdentity, error)
}

// Unsupported records why a feature is unavailable, so the module can emit one
// precise diagnostic instead of a generic "not available".
type Unsupported struct {
	Feature Feature
	Reason  string
}

// Set is the platform's reader implementations. A nil reader means the platform
// cannot provide that feature; Unsupported carries the reason.
type Set struct {
	Lister  Lister
	IO      IOReader
	Files   FileReader
	Path    PathReader
	Command CommandReader
	Boot    BootReader

	// Inline declares which fields of Info this platform actually populates.
	// CPU, memory, threads, state and user arrive with the enumeration rather
	// than through a reader of their own, so their availability cannot be
	// inferred from a nil check and has to be stated.
	Inline map[Feature]bool

	Unsupported []Unsupported
}

// Has reports whether a feature is available.
func (s Set) Has(f Feature) bool {
	switch f {
	case FeatureEnumeration:
		return s.Lister != nil
	case FeatureIO:
		return s.IO != nil
	case FeatureOpenFiles:
		return s.Files != nil
	case FeatureExecutablePath:
		return s.Path != nil
	case FeatureCommandLine:
		return s.Command != nil
	case FeatureCPU, FeatureMemory, FeatureThreads, FeatureState, FeatureUser:
		return s.Inline[f]
	default:
		return false
	}
}

// UnsupportedReason returns the recorded reason for an absent feature.
func (s Set) UnsupportedReason(f Feature) string {
	for _, u := range s.Unsupported {
		if u.Feature == f {
			return u.Reason
		}
	}
	if s.Has(f) {
		return ""
	}
	return "not implemented on this platform"
}

// Available returns the features that are available, in a stable order.
func (s Set) Available() []Feature {
	var out []Feature
	for _, f := range AllFeatures {
		if s.Has(f) {
			out = append(out, f)
		}
	}
	return out
}

// NewSet returns the reader set for the platform this binary was built for.
// It is supplied by exactly one build-tagged file.
func NewSet() Set { return platformSet() }
