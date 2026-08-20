//go:build darwin

package process

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/obsagent/observability-agent/internal/platform/darwinsysctl"
)

// Darwin enumerates processes with one sysctl and decodes the result carefully.
//
// The Darwin baseline is DELIBERATELY NARROW, and the reason is worth stating
// plainly because it is a judgement call rather than an oversight.
//
// KERN_PROC_ALL returns an array of `struct kinfo_proc`, which is two structs
// glued together: `extern_proc` followed by `eproc`. Only the first has a
// layout that can be derived confidently from published headers and reproduced
// without cgo — it is 296 bytes of simple, long-stable fields. `eproc` embeds
// `struct vmspace` and `struct ucred`, whose sizes have changed across releases,
// and which is where the parent PID and the owning UID live.
//
// A decoder with one wrong offset in `eproc` does not fail. It returns numbers:
// a parent PID that is really part of a pointer, a UID that is really a group
// count. That is exactly the class of defect this agent must not ship, and it is
// not verifiable from a machine that cannot run macOS. So PPID and user identity
// are reported UNSUPPORTED on Darwin rather than guessed.
//
// Per-process CPU and memory need proc_pidinfo from libproc, which needs cgo,
// and the agent ships CGO_ENABLED=0. The p_pctcpu and p_uticks fields of
// extern_proc are not maintained by modern XNU and are typically zero, so they
// are not read: a metric that reports zero CPU for every process is worse than
// an absent one.
//
// Command lines and executable paths both come from KERN_PROCARGS2, which
// returns the process's ENVIRONMENT in the same buffer as its arguments. This
// module does not read process environments, so neither is supported here.
//
// What Darwin does give, honestly and cheaply: process enumeration, executable
// name, run state, start time, and therefore the aggregate counts, the state
// distribution and the full process lifecycle event stream.
//
// Verification status: this file is verified by COMPILATION for darwin/amd64 and
// darwin/arm64. It has not been executed on Apple hardware. The size guard below
// exists precisely because of that.

const (
	ctlKern     = 1
	kernProc    = 14
	kernProcAll = 0

	// sizeofKinfoProc is sizeof(struct kinfo_proc) on 64-bit Darwin. It is used
	// as a GATE, not as an assumption: a buffer that is not a whole number of
	// records means this kernel's layout differs from the one this decoder was
	// written against, and the reader reports unsupported instead of decoding
	// whatever happens to be there.
	sizeofKinfoProc = 648
	// sizeofExternProc is the prefix of kinfo_proc that this decoder reads.
	sizeofExternProc = 296

	// Field offsets within extern_proc, derived field by field from
	// <sys/proc.h> under LP64. XNU fills __p_starttime through the union at
	// offset 0 when answering sysctl, which is the whole reason the union
	// exists.
	offStartSec  = 0 // struct timeval { int64 tv_sec; int32 tv_usec; }
	offStartUsec = 8
	offStat      = 36 // char p_stat
	offPID       = 40 // pid_t p_pid
	offComm      = 243
	lenComm      = 17 // MAXCOMLEN + 1
)

type darwinReader struct{}

func platformSet() Set {
	r := &darwinReader{}
	return Set{
		Lister: r,
		Boot:   r,
		Inline: map[Feature]bool{
			FeatureState: true,
		},
		Unsupported: []Unsupported{
			{Feature: FeatureCPU, Reason: "per-process CPU time on macOS requires proc_pidinfo from libproc, which needs cgo; the agent is built without cgo"},
			{Feature: FeatureMemory, Reason: "per-process memory on macOS requires proc_pidinfo from libproc, which needs cgo; the agent is built without cgo"},
			{Feature: FeatureThreads, Reason: "per-process thread counts on macOS require proc_pidinfo from libproc, which needs cgo"},
			{Feature: FeatureIO, Reason: "per-process I/O counters on macOS require proc_pidinfo from libproc, which needs cgo"},
			{Feature: FeatureOpenFiles, Reason: "per-process descriptor counts on macOS require proc_pidinfo from libproc, which needs cgo"},
			{Feature: FeatureExecutablePath, Reason: "executable paths on macOS come from KERN_PROCARGS2, which returns the process environment in the same buffer; this agent does not read process environments"},
			{Feature: FeatureCommandLine, Reason: "command lines on macOS come from KERN_PROCARGS2, which returns the process environment in the same buffer; this agent does not read process environments"},
			{Feature: FeatureUser, Reason: "the owning UID lives in the eproc half of kinfo_proc, whose layout is not stable enough to decode without cgo; a guessed offset would report a plausible wrong user"},
		},
	}
}

func (r *darwinReader) ListProcesses(ctx context.Context, opts ListOptions) (Listing, error) {
	// Prefer the 3-element MIB used by Apple and libproc wrappers
	// (CTL_KERN, KERN_PROC, KERN_PROC_ALL). Some kernels also accept a trailing
	// 0; try that only if the standard form fails.
	buf, err := sysctlKinfoProcAll()
	if err != nil {
		return Listing{}, err
	}
	if len(buf) == 0 {
		return Listing{}, nil
	}
	if len(buf)%sizeofKinfoProc != 0 {
		return Listing{}, fmt.Errorf(
			"%w: kern.proc.all returned %d bytes, not a multiple of the expected %d-byte record",
			ErrUnsupported, len(buf), sizeofKinfoProc)
	}

	n := len(buf) / sizeofKinfoProc
	out := Listing{Processes: make([]Info, 0, n)}
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		rec := buf[i*sizeofKinfoProc : i*sizeofKinfoProc+sizeofExternProc]
		info, ok := decodeExternProc(rec)
		if !ok {
			out.Unreadable++
			continue
		}
		if !opts.accept(info.PID) {
			continue
		}
		out.Processes = append(out.Processes, info)
	}
	return out, nil
}

func sysctlKinfoProcAll() ([]byte, error) {
	mibs := [][]int32{
		{ctlKern, kernProc, kernProcAll},
		{ctlKern, kernProc, kernProcAll, 0},
	}
	var last error
	for _, mib := range mibs {
		b, err := sysctlBytes(mib)
		if err != nil {
			last = err
			continue
		}
		if len(b) == 0 || len(b)%sizeofKinfoProc == 0 {
			return b, nil
		}
		last = fmt.Errorf("%w: kern.proc.all returned %d bytes (not a multiple of %d)",
			ErrUnsupported, len(b), sizeofKinfoProc)
	}
	if last == nil {
		last = fmt.Errorf("%w: kern.proc.all unavailable", ErrUnsupported)
	}
	return nil, last
}

func sysctlBytes(mib []int32) ([]byte, error) {
	var need uintptr
	if _, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)), 0,
		uintptr(unsafe.Pointer(&need)), 0, 0); errno != 0 {
		return nil, fmt.Errorf("sysctl kern.proc.all (size): %w", errno)
	}
	if need == 0 {
		return nil, nil
	}
	need += need / 8
	buf := make([]byte, need)
	size := need
	if _, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, 0); errno != 0 {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", errno)
	}
	if size > need {
		size = need
	}
	return buf[:size], nil
}

// decodeExternProc reads the fields this module needs out of one extern_proc.
func decodeExternProc(rec []byte) (Info, bool) {
	if len(rec) < sizeofExternProc {
		return Info{}, false
	}
	pid := int32(le32(rec[offPID:]))
	// PID 0 is the Darwin kernel_task entry in kinfo_proc; it is not a
	// user-space process and fails the agent's "positive PID" invariant.
	if pid <= 0 {
		return Info{}, false
	}

	info := Info{
		PID:   PID(pid),
		State: stateFromDarwin(rec[offStat]),
		Name:  cstring(rec[offComm : offComm+lenComm]),
	}

	sec := int64(le64(rec[offStartSec:]))
	usec := int32(le32(rec[offStartUsec:]))
	if sec > 0 {
		// Microseconds since the epoch: absolute, exact, and unique enough to
		// discriminate two processes that reuse a PID.
		info.StartRaw = uint64(sec)*1e6 + uint64(uint32(usec))
		info.HasStartRaw = true
		info.StartTime = time.Unix(sec, int64(usec)*1000)
		info.HasStartTime = true
	}
	return info, true
}

// Darwin runs only on little-endian architectures, but the decode is written
// explicitly rather than by casting a byte slice to a struct pointer: an
// unaligned struct cast is undefined behaviour that happens to work, and being
// explicit is what makes the offsets above auditable against the header.
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// stateFromDarwin maps p_stat from <sys/proc.h>: SIDL 1, SRUN 2, SSLEEP 3,
// SSTOP 4, SZOMB 5.
func stateFromDarwin(c byte) State {
	switch c {
	case 1:
		return StateIdle
	case 2:
		return StateRunning
	case 3:
		return StateSleeping
	case 4:
		return StateStopped
	case 5:
		return StateZombie
	default:
		return StateUnknown
	}
}

func (r *darwinReader) ReadBootIdentity(context.Context) (BootIdentity, error) {
	// kern.boottime returns struct timeval{ int64 sec; int32 usec; }.
	b, err := darwinsysctl.Bytes("kern.boottime", 8)
	if err != nil {
		return BootIdentity{}, err
	}
	sec := int64(le64(b))
	if sec <= 0 {
		return BootIdentity{}, fmt.Errorf("sysctl kern.boottime: implausible boot time")
	}
	t := time.Unix(sec, 0)
	return BootIdentity{ID: "boot-" + fmt.Sprint(sec), Time: t, HasTime: true}, nil
}

var (
	_ Lister     = (*darwinReader)(nil)
	_ BootReader = (*darwinReader)(nil)
)
