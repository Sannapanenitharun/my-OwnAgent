//go:build darwin

package host

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Darwin collection uses sysctl and getfsstat from the standard library.
//
// What is deliberately ABSENT, and why: CPU time, memory pressure and disk I/O
// on macOS live behind Mach APIs (host_statistics, host_processor_info,
// IOKit). Reaching them requires cgo. The agent ships CGO_ENABLED=0 so that one
// binary runs on any macOS without a toolchain and without dynamic-linker
// surprises, so those sources report unsupported.
//
// The alternative — deriving "used memory" from total minus a number that does
// not mean free — would produce a figure that looks right and is wrong. An
// absent metric prompts an operator to ask why; a wrong one does not.
//
// Verification status: this file is verified by COMPILATION for darwin/amd64
// and darwin/arm64. It has not been executed on macOS hardware. That is stated
// plainly in docs/READINESS.md rather than implied to be tested.

// mntRDONLY is MNT_RDONLY from <sys/mount.h>. The standard library does not
// export it for darwin.
const mntRDONLY = 0x00000001

type darwinReader struct{}

func platformSet() Set {
	r := &darwinReader{}
	return Set{
		CPU:        r,
		Memory:     r,
		Filesystem: r,
		OS:         r,
		Load:       r,
		Disk:       nil,
		Network:    nil,
		Unsupported: []Unsupported{
			{Source: SourceDisk, Reason: "macOS disk I/O counters require IOKit, which needs cgo; the agent is built without cgo"},
			{Source: SourceNetwork, Reason: "macOS interface counters require the routing-socket interface, which is not available without cgo in this build"},
		},
	}
}

// ReadCPU reports CPU counts. Cumulative CPU time is not available without
// cgo, so HasTotal stays false and the module emits no utilisation rather than
// a fabricated one.
func (r *darwinReader) ReadCPU(context.Context, bool) (CPUStats, error) {
	var stats CPUStats
	if n, err := syscall.SysctlUint32("hw.logicalcpu"); err == nil && n > 0 {
		stats.LogicalCount = KnownU64(uint64(n))
	} else if n := runtime.NumCPU(); n > 0 {
		stats.LogicalCount = KnownU64(uint64(n))
	}
	if n, err := syscall.SysctlUint32("hw.physicalcpu"); err == nil && n > 0 {
		stats.PhysicalCount = KnownU64(uint64(n))
	}
	if !stats.LogicalCount.OK {
		return CPUStats{}, fmt.Errorf("no CPU information available via sysctl")
	}
	return stats, nil
}

// ReadMemory reports total physical memory. Available and used require Mach
// vm_statistics64 and stay unknown.
func (r *darwinReader) ReadMemory(context.Context) (MemoryStats, error) {
	// The standard library provides SysctlUint32 but not a 64-bit form, and
	// hw.memsize exceeds 32 bits on any machine worth monitoring, so the raw
	// bytes are decoded here.
	raw, err := syscall.Sysctl("hw.memsize")
	if err != nil {
		return MemoryStats{}, fmt.Errorf("sysctl hw.memsize: %w", err)
	}
	b := []byte(raw)
	if len(b) < 8 {
		return MemoryStats{}, fmt.Errorf("sysctl hw.memsize: short read (%d bytes)", len(b))
	}
	total := *(*uint64)(unsafe.Pointer(&b[0]))
	out := MemoryStats{Total: KnownU64(total)}

	// vm.swapusage returns struct xsw_usage{ xsu_total, xsu_avail, xsu_used
	// uint64; xsu_pagesize uint32; ... }. Only the first three are read.
	if raw, err := syscall.Sysctl("vm.swapusage"); err == nil && len(raw) >= 24 {
		b := []byte(raw)
		swapTotal := *(*uint64)(unsafe.Pointer(&b[0]))
		swapAvail := *(*uint64)(unsafe.Pointer(&b[8]))
		swapUsed := *(*uint64)(unsafe.Pointer(&b[16]))
		out.SwapTotal = KnownU64(swapTotal)
		out.SwapFree = KnownU64(swapAvail)
		out.SwapUsed = KnownU64(swapUsed)
	}
	return out, nil
}

// ReadLoad reads vm.loadavg, which returns struct loadavg {
//
//	fixpt_t ldavg[3]; // 3×uint32 = 12 bytes
//	long    fscale;   // 8 bytes at offset 16 on LP64 (4 bytes padding)
//
// }. Values are fixed-point and must be divided by fscale.
func (r *darwinReader) ReadLoad(context.Context) (LoadStats, error) {
	raw, err := syscall.Sysctl("vm.loadavg")
	if err != nil {
		return LoadStats{}, fmt.Errorf("sysctl vm.loadavg: %w", err)
	}
	b := []byte(raw)
	if len(b) < 24 {
		return LoadStats{}, fmt.Errorf("sysctl vm.loadavg: short read (%d bytes)", len(b))
	}
	ld0 := *(*uint32)(unsafe.Pointer(&b[0]))
	ld1 := *(*uint32)(unsafe.Pointer(&b[4]))
	ld2 := *(*uint32)(unsafe.Pointer(&b[8]))
	scale := float64(*(*int64)(unsafe.Pointer(&b[16])))
	if scale == 0 {
		return LoadStats{}, fmt.Errorf("sysctl vm.loadavg: zero scale")
	}
	return LoadStats{
		Load1:  KnownF64(float64(ld0) / scale),
		Load5:  KnownF64(float64(ld1) / scale),
		Load15: KnownF64(float64(ld2) / scale),
	}, nil
}

func (r *darwinReader) ReadOS(context.Context) (OSInfo, error) {
	info := OSInfo{OS: "darwin", Architecture: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if v, err := syscall.Sysctl("kern.ostype"); err == nil {
		info.Platform = v
	}
	if v, err := syscall.Sysctl("kern.osrelease"); err == nil {
		info.KernelVersion = v
	}
	if v, err := syscall.Sysctl("kern.osproductversion"); err == nil && v != "" {
		info.PlatformVersion = v
	} else if v, err := syscall.Sysctl("kern.osversion"); err == nil {
		info.PlatformVersion = v
	}

	// kern.boottime returns struct timeval{ int64 sec; int32 usec; }.
	if raw, err := syscall.Sysctl("kern.boottime"); err == nil && len(raw) >= 8 {
		b := []byte(raw)
		sec := *(*int64)(unsafe.Pointer(&b[0]))
		if sec > 0 {
			info.BootTime = time.Unix(sec, 0)
			info.HasBootTime = true
		}
	}

	if info.Hostname == "" && info.KernelVersion == "" {
		return OSInfo{}, fmt.Errorf("no host metadata available via sysctl")
	}
	return info, nil
}

func (r *darwinReader) ReadFilesystems(ctx context.Context) ([]FilesystemStats, error) {
	// MNT_NOWAIT (2) returns cached values instead of asking each filesystem
	// to update its statistics. On a host with an unresponsive network mount,
	// the waiting form can block indefinitely — which would hang the whole
	// collection loop.
	const mntNoWait = 2

	n, err := syscall.Getfsstat(nil, mntNoWait)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]syscall.Statfs_t, n)
	n, err = syscall.Getfsstat(buf, mntNoWait)
	if err != nil {
		return nil, fmt.Errorf("getfsstat: %w", err)
	}
	if n > len(buf) {
		n = len(buf)
	}

	out := make([]FilesystemStats, 0, n)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		st := &buf[i]
		fs := FilesystemStats{
			Mountpoint: cstring(st.Mntonname[:]),
			Device:     cstring(st.Mntfromname[:]),
			FSType:     cstring(st.Fstypename[:]),
			ReadOnly:   st.Flags&mntRDONLY != 0,
		}
		bsize := uint64(st.Bsize)
		if bsize == 0 && st.Iosize > 0 {
			bsize = uint64(st.Iosize)
		}
		if bsize > 0 {
			fs.TotalBytes = KnownU64(st.Blocks * bsize)
			fs.FreeBytes = KnownU64(st.Bfree * bsize)
			avail := st.Bavail * bsize
			// Snapshot / reserve accounting can report Bavail > Blocks; that is
			// not usable as a capacity gauge, so leave Available unknown.
			if st.Blocks > 0 && avail <= st.Blocks*bsize {
				fs.AvailBytes = KnownU64(avail)
			}
			if st.Blocks >= st.Bfree {
				fs.UsedBytes = KnownU64((st.Blocks - st.Bfree) * bsize)
			}
		}
		if st.Files > 0 {
			fs.TotalInode = KnownU64(st.Files)
			fs.FreeInode = KnownU64(st.Ffree)
			if st.Files >= st.Ffree {
				fs.UsedInode = KnownU64(st.Files - st.Ffree)
			}
		}
		out = append(out, fs)
	}
	return out, nil
}

// cstring converts a NUL-terminated fixed-size C char array to a Go string.
func cstring(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
