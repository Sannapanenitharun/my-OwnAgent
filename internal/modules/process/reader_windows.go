//go:build windows

package process

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Windows collection goes through documented Win32 APIs and needs no elevation.
//
// The shape of the Windows baseline is dictated by two hard limits, and both are
// reported honestly rather than worked around:
//
//   - COMMAND LINES ARE NOT COLLECTED. Reading another process's command line on
//     Windows means locating its PEB with NtQueryInformationProcess and then
//     calling ReadProcessMemory on it. That is inspecting process memory, which
//     this module is forbidden from doing — a prohibition worth more than the
//     field. The feature is reported unsupported.
//
//   - THERE IS NO PER-PROCESS RUN STATE. Windows schedules threads, not
//     processes; there is no equivalent of Linux's R/S/D/Z. Synthesising one
//     from thread states would be a different measurement wearing a familiar
//     name, so the feature is reported unsupported and the by-state metric is
//     simply absent.
//
// An unelevated agent also cannot open processes belonging to other users. That
// is a privilege boundary, counted as Denied, and it does not degrade health:
// requiring the agent to run as SYSTEM to avoid an "unhealthy" reading would be
// trading a real security property for a cosmetic one.

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateToolhelp32Snapshot   = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW             = modkernel32.NewProc("Process32NextW")
	procOpenProcess                = modkernel32.NewProc("OpenProcess")
	procGetProcessTimes            = modkernel32.NewProc("GetProcessTimes")
	procGetProcessHandleCount      = modkernel32.NewProc("GetProcessHandleCount")
	procGetProcessIoCounters       = modkernel32.NewProc("GetProcessIoCounters")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessMemoryInfo       = modkernel32.NewProc("K32GetProcessMemoryInfo")
	procGetTickCount64             = modkernel32.NewProc("GetTickCount64")
)

const (
	th32csSnapProcess = 0x00000002

	// PROCESS_QUERY_LIMITED_INFORMATION is the least privilege that answers
	// every question this module asks. PROCESS_QUERY_INFORMATION would also
	// work and would additionally permit reading process memory, which is
	// exactly why it is not requested.
	processQueryLimitedInformation = 0x1000

	errorAccessDenied     = 5
	errorInvalidParameter = 87
	errorNoMoreFiles      = 18
	errorPartialCopy      = 299

	// FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC.
	filetimeUnitNanos = 100
	// Offset in 100ns units between the FILETIME epoch and the Unix epoch.
	filetimeToUnix = 116444736000000000
)

var invalidHandle = ^uintptr(0)

// processEntry32 mirrors PROCESSENTRY32W. The layout is load-bearing: a
// mismatch yields plausible garbage rather than an error, so it is verified at
// run time against the size Windows expects by TestProcessEntry32Layout.
type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// ioCounters mirrors IO_COUNTERS.
type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type filetime struct {
	Low  uint32
	High uint32
}

func (f filetime) uint64() uint64 { return uint64(f.High)<<32 | uint64(f.Low) }

type windowsReader struct{}

func platformSet() Set {
	r := &windowsReader{}
	return Set{
		Lister:  r,
		IO:      r,
		Files:   r,
		Path:    r,
		Boot:    r,
		Command: nil,
		Inline: map[Feature]bool{
			FeatureCPU:     true,
			FeatureMemory:  true,
			FeatureThreads: true,
		},
		Unsupported: []Unsupported{
			{Feature: FeatureState, Reason: "Windows schedules threads rather than processes and exposes no per-process run state"},
			{Feature: FeatureCommandLine, Reason: "reading another process's command line on Windows requires inspecting its memory, which this agent never does"},
			{Feature: FeatureUser, Reason: "process ownership on Windows is a token SID rather than a numeric UID; it is not part of the unelevated baseline"},
		},
	}
}

// classifyWin maps a Win32 error onto the three per-process outcomes.
func classifyWin(errno syscall.Errno) (vanished, denied bool) {
	switch errno {
	case errorInvalidParameter:
		// OpenProcess reports this for a PID that no longer exists — the
		// process exited between the snapshot and the open. Normal churn.
		return true, false
	case errorAccessDenied:
		return false, true
	case errorPartialCopy:
		// A process exiting while it is being queried.
		return true, false
	}
	return false, false
}

func (r *windowsReader) ListProcesses(ctx context.Context, opts ListOptions) (Listing, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == invalidHandle {
		return Listing{}, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return Listing{}, fmt.Errorf("Process32FirstW: %w", err)
	}

	out := Listing{Processes: make([]Info, 0, 256)}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		pid := PID(entry.ProcessID)
		if opts.accept(pid) {
			// The snapshot alone supplies identity and thread count for EVERY
			// process, including those the agent may not open. That is what
			// keeps process.count and the parent/child view complete even
			// though CPU and memory are not always obtainable.
			info := Info{
				PID:     pid,
				PPID:    PID(entry.ParentProcessID),
				Name:    syscall.UTF16ToString(entry.ExeFile[:]),
				State:   StateUnknown,
				Threads: KnownU64(uint64(entry.Threads)),
			}
			switch vanished, denied := r.enrich(&info); {
			case vanished:
				out.Vanished++
			case denied:
				out.Denied++
				out.Processes = append(out.Processes, info)
			default:
				out.Processes = append(out.Processes, info)
			}
		}

		ret, _, err = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == errorNoMoreFiles {
				break
			}
			break
		}
	}
	return out, nil
}

// enrich adds CPU time, memory and start time, all of which need a handle.
//
// A process that cannot be opened keeps its snapshot-derived identity: it is
// reported, counted, and simply has no CPU or memory figures. Dropping it would
// understate the host's process count, and inventing zeros would be worse.
func (r *windowsReader) enrich(info *Info) (vanished, denied bool) {
	h, err := openProcess(info.PID)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return classifyWin(errno)
		}
		return false, false
	}
	defer syscall.CloseHandle(h)

	var creation, exit, kernel, user filetime
	if ret, _, _ := procGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	); ret != 0 {
		// Windows start stamps are ABSOLUTE, unlike Linux's boot-relative
		// jiffies, so the raw FILETIME is already a globally unique
		// discriminator and needs no boot identity to disambiguate it.
		info.StartRaw = creation.uint64()
		info.HasStartRaw = info.StartRaw != 0
		if info.HasStartRaw {
			info.StartTime = filetimeToTime(info.StartRaw)
			info.HasStartTime = true
		}
		info.CPUUserNanos = KnownU64(user.uint64() * filetimeUnitNanos)
		info.CPUSystemNanos = KnownU64(kernel.uint64() * filetimeUnitNanos)
	}

	var mem processMemoryCounters
	mem.CB = uint32(unsafe.Sizeof(mem))
	if ret, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.CB),
	); ret != 0 {
		// WorkingSetSize is the closest Windows analogue of RSS: resident
		// physical pages. PagefileUsage is private committed bytes, which is the
		// nearest thing to "virtual" that is actually comparable between
		// processes — total virtual size on Windows is dominated by reserved
		// address space and is close to meaningless.
		info.RSSBytes = KnownU64(uint64(mem.WorkingSetSize))
		info.VirtualBytes = KnownU64(uint64(mem.PagefileUsage))
	}
	return false, false
}

func openProcess(pid PID) (syscall.Handle, error) {
	h, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

func filetimeToTime(ft uint64) time.Time {
	if ft < filetimeToUnix {
		return time.Time{}
	}
	n := int64(ft-filetimeToUnix) * filetimeUnitNanos
	return time.Unix(0, n).UTC()
}

func (r *windowsReader) ReadIO(_ context.Context, pid PID) (IOCounters, error) {
	h, err := openProcess(pid)
	if err != nil {
		return IOCounters{}, err
	}
	defer syscall.CloseHandle(h)

	var c ioCounters
	ret, _, err := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
	if ret == 0 {
		return IOCounters{}, fmt.Errorf("GetProcessIoCounters: %w", err)
	}
	return IOCounters{
		ReadBytes:  KnownU64(c.ReadTransferCount),
		WriteBytes: KnownU64(c.WriteTransferCount),
		ReadOps:    KnownU64(c.ReadOperationCount),
		WriteOps:   KnownU64(c.WriteOperationCount),
	}, nil
}

// ReadOpenFiles returns the process's HANDLE count.
//
// Windows handles are not file descriptors: the count includes events, mutexes,
// threads and registry keys as well as files. It is reported under the same
// metric because it answers the same operational question — "is this process
// leaking kernel objects?" — and the difference is documented rather than
// hidden.
func (r *windowsReader) ReadOpenFiles(_ context.Context, pid PID) (U64, error) {
	h, err := openProcess(pid)
	if err != nil {
		return U64{}, err
	}
	defer syscall.CloseHandle(h)

	var n uint32
	ret, _, err := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&n)))
	if ret == 0 {
		return U64{}, fmt.Errorf("GetProcessHandleCount: %w", err)
	}
	return KnownU64(uint64(n)), nil
}

func (r *windowsReader) ReadExecutablePath(_ context.Context, pid PID) (string, error) {
	h, err := openProcess(pid)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageNameW.Call(
		uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "", fmt.Errorf("QueryFullProcessImageNameW: %w", err)
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

// WindowsBootNamespace is the boot component of a Windows process instance key.
//
// It is a CONSTANT, and that is a correction to what this reader originally did.
//
// The boot identifier exists to disambiguate start stamps that are measured FROM
// boot, as Linux jiffies are: without it, a process started 500 jiffies after
// one boot and another started 500 jiffies after the next would share a key.
// Windows start stamps are absolute FILETIMEs, so they carry no such ambiguity
// and need no boot discriminator at all.
//
// The original implementation derived one anyway, from time.Now() minus
// GetTickCount64. That is not stable. The tick count has roughly 15 ms
// resolution and the wall clock drifts under NTP, so the derived boot instant
// moves by tens of milliseconds between reads — and every time it crossed a
// second boundary, the truncation produced a DIFFERENT identifier for the same
// boot. The consequence was that restarting the agent re-keyed every process
// entity on the host, and running two modules that both resolve processes could
// key them differently within one run.
//
// A constant is correct precisely because the start stamp is already absolute.
// See docs/adr/0006 and platform.ProcessRef.
const WindowsBootNamespace = "windows-absolute-start"

func (r *windowsReader) ReadBootIdentity(context.Context) (BootIdentity, error) {
	out := BootIdentity{ID: WindowsBootNamespace}
	// The boot TIME is still reported, because it is useful telemetry. It is
	// simply not used as an identity component, for the reason above.
	if ms, _, _ := procGetTickCount64.Call(); ms > 0 {
		out.Time = time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second)
		out.HasTime = true
	}
	return out, nil
}

var (
	_ Lister     = (*windowsReader)(nil)
	_ IOReader   = (*windowsReader)(nil)
	_ FileReader = (*windowsReader)(nil)
	_ PathReader = (*windowsReader)(nil)
	_ BootReader = (*windowsReader)(nil)
)
