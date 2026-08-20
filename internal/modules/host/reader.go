// Package host is the agent's host observability module: CPU, memory, disk,
// filesystem, network interfaces, OS, kernel, architecture, load, uptime and
// host identity.
//
// It is the reference implementation every later collector should follow. The
// pattern it establishes:
//
//   - The module contains no OS-specific code. It talks to narrow reader
//     interfaces; one build-tagged file per platform supplies them.
//   - A source that a platform cannot provide is ABSENT, not empty. A nil
//     reader and a recorded reason produce an unsupported diagnostic and
//     degraded health. Nothing is ever fabricated.
//   - Individual values are optional too, via U64/F64. Darwin can report total
//     memory but not used memory without cgo, so it reports total and leaves
//     used unknown rather than reporting zero.
//   - One goroutine. One deadline-bounded call at a time. Bounded series counts
//     with deterministic selection.
//
// Concurrency: readers are called from a single collection goroutine, one at a
// time, and need not be safe for concurrent use.
package host

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported reports that a reader cannot provide a value in this
// environment. It is deliberately the module contract's unsupported error, so
// that a reader returning it from Start propagates to the supervisor's
// unsupported handling unchanged.
var ErrUnsupported = errors.New("host: unsupported")

// U64 is an optionally-known unsigned value.
//
// This type exists because the alternative — returning 0 for "not available" —
// is indistinguishable from a genuine zero, and an observability agent that
// reports a plausible wrong number is worse than one that reports nothing.
type U64 struct {
	V  uint64
	OK bool
}

// KnownU64 returns a known value.
func KnownU64(v uint64) U64 { return U64{V: v, OK: true} }

// F64 is an optionally-known floating point value.
type F64 struct {
	V  float64
	OK bool
}

// KnownF64 returns a known value.
func KnownF64(v float64) F64 { return F64{V: v, OK: true} }

// Source identifies one collection source. The set is closed and small, which
// is what keeps the `source` telemetry attribute bounded.
type Source int

const (
	SourceCPU Source = iota
	SourceMemory
	SourceDisk
	SourceFilesystem
	SourceNetwork
	SourceOS
	SourceLoad
)

// AllSources is every source, in a stable order.
var AllSources = []Source{
	SourceCPU, SourceMemory, SourceDisk, SourceFilesystem,
	SourceNetwork, SourceOS, SourceLoad,
}

func (s Source) String() string {
	switch s {
	case SourceCPU:
		return "cpu"
	case SourceMemory:
		return "memory"
	case SourceDisk:
		return "disk"
	case SourceFilesystem:
		return "filesystem"
	case SourceNetwork:
		return "network"
	case SourceOS:
		return "os"
	case SourceLoad:
		return "load"
	default:
		return "unknown"
	}
}

// CPUTimes are cumulative CPU time counters in arbitrary but consistent units.
//
// The units do not matter because utilisation is computed as a ratio of deltas;
// requiring readers to normalise to seconds would force each platform to
// discover its own clock tick for no benefit.
type CPUTimes struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

// Total returns the sum of all counters.
//
// Guest time is deliberately excluded: the kernel already includes it in User,
// so adding it again would inflate the denominator and understate utilisation
// on every virtualised host — which is most of them.
func (t CPUTimes) Total() uint64 {
	return t.User + t.Nice + t.System + t.Idle + t.IOWait + t.IRQ + t.SoftIRQ + t.Steal
}

// Busy returns non-idle time. IOWait counts as busy: a host blocked on storage
// is not available for work, and treating it as idle hides the most common
// cause of a slow host.
func (t CPUTimes) Busy() uint64 { return t.Total() - t.Idle }

// CPUStats is one CPU sample.
type CPUStats struct {
	LogicalCount  U64
	PhysicalCount U64
	// Total is aggregate CPU time. Unknown on platforms without a
	// cgo-free way to read it.
	Total    CPUTimes
	HasTotal bool
	// PerCore is populated only when per-core collection is enabled. Index is
	// the core number.
	PerCore []CPUTimes
}

// MemoryStats is one memory sample. Every field is optional because platforms
// differ sharply in what they expose without elevated privileges or cgo.
type MemoryStats struct {
	Total     U64
	Available U64
	Free      U64
	Used      U64
	Buffers   U64
	Cached    U64
	SwapTotal U64
	SwapFree  U64
	SwapUsed  U64
}

// DiskStats is one block device's cumulative I/O counters.
type DiskStats struct {
	Device     string
	ReadOps    U64
	WriteOps   U64
	ReadBytes  U64
	WriteBytes U64
	IOTime     U64 // milliseconds spent doing I/O
}

// FilesystemStats is one mounted filesystem.
type FilesystemStats struct {
	Mountpoint string
	Device     string
	FSType     string
	TotalBytes U64
	FreeBytes  U64
	AvailBytes U64
	UsedBytes  U64
	TotalInode U64
	FreeInode  U64
	UsedInode  U64
	ReadOnly   bool
}

// InterfaceStats is one network interface's cumulative counters.
type InterfaceStats struct {
	Name       string
	RxBytes    U64
	TxBytes    U64
	RxPackets  U64
	TxPackets  U64
	RxErrors   U64
	TxErrors   U64
	RxDropped  U64
	TxDropped  U64
	Up         bool
	KnownState bool
}

// OSInfo is host metadata. It changes rarely, so it is collected at a long
// interval rather than on every cycle.
type OSInfo struct {
	OS              string
	Platform        string
	PlatformVersion string
	KernelVersion   string
	Architecture    string
	Hostname        string
	BootTime        time.Time
	HasBootTime     bool
}

// LoadStats is the run-queue load average.
type LoadStats struct {
	Load1  F64
	Load5  F64
	Load15 F64
}

// The reader interfaces are deliberately one-method and one-source. A single
// large HostReader would force every platform to implement every source, and
// the only way to satisfy it on a platform that cannot provide a source would
// be to return a zero value — which is precisely the fabrication this design
// exists to prevent. With separate interfaces, "cannot" is expressed by not
// providing the reader at all.

// CPUReader reads CPU counts and cumulative CPU time.
type CPUReader interface {
	ReadCPU(ctx context.Context, perCore bool) (CPUStats, error)
}

// MemoryReader reads physical and swap memory.
type MemoryReader interface {
	ReadMemory(ctx context.Context) (MemoryStats, error)
}

// DiskReader reads block device I/O counters.
type DiskReader interface {
	ReadDisks(ctx context.Context) ([]DiskStats, error)
}

// FilesystemReader reads mounted filesystem usage.
type FilesystemReader interface {
	ReadFilesystems(ctx context.Context) ([]FilesystemStats, error)
}

// NetworkReader reads network interface counters.
type NetworkReader interface {
	ReadInterfaces(ctx context.Context) ([]InterfaceStats, error)
}

// OSReader reads host metadata.
type OSReader interface {
	ReadOS(ctx context.Context) (OSInfo, error)
}

// LoadReader reads the load average.
type LoadReader interface {
	ReadLoad(ctx context.Context) (LoadStats, error)
}

// Unsupported records why a source is unavailable, so the module can emit one
// precise diagnostic instead of a generic "not available".
type Unsupported struct {
	Source Source
	Reason string
}

// Set is the platform's reader implementations. A nil field means the platform
// cannot provide that source; Unsupported carries the reason.
type Set struct {
	CPU         CPUReader
	Memory      MemoryReader
	Disk        DiskReader
	Filesystem  FilesystemReader
	Network     NetworkReader
	OS          OSReader
	Load        LoadReader
	Unsupported []Unsupported
}

// Has reports whether a source has a reader.
func (s Set) Has(src Source) bool {
	switch src {
	case SourceCPU:
		return s.CPU != nil
	case SourceMemory:
		return s.Memory != nil
	case SourceDisk:
		return s.Disk != nil
	case SourceFilesystem:
		return s.Filesystem != nil
	case SourceNetwork:
		return s.Network != nil
	case SourceOS:
		return s.OS != nil
	case SourceLoad:
		return s.Load != nil
	default:
		return false
	}
}

// UnsupportedReason returns the recorded reason for an absent source.
func (s Set) UnsupportedReason(src Source) string {
	for _, u := range s.Unsupported {
		if u.Source == src {
			return u.Reason
		}
	}
	if s.Has(src) {
		return ""
	}
	return "not implemented on this platform"
}

// Available returns the sources that have readers, in a stable order.
func (s Set) Available() []Source {
	var out []Source
	for _, src := range AllSources {
		if s.Has(src) {
			out = append(out, src)
		}
	}
	return out
}

// NewSet returns the reader set for the platform this binary was built for.
// It is supplied by exactly one build-tagged file.
func NewSet() Set { return platformSet() }
