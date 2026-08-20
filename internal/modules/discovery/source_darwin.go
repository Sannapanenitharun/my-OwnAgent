//go:build darwin

package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Darwin discovery is DELIBERATELY NARROW, and the narrowness is a judgement
// call rather than an oversight. What it can prove, it reports; what it would
// have to guess at, it declares unsupported with a reason.
//
// The four domains that are absent, and why each is absent rather than
// approximated:
//
//	services      launchd has no readable interface. The answer lives behind
//	              launchctl (a subprocess, which is prohibited) or the private
//	              ServiceManagement framework (which needs cgo). Parsing the
//	              plists under /Library/LaunchDaemons would report what is
//	              INSTALLED, not what is running, and presenting that as a
//	              service inventory would be a different measurement wearing the
//	              same name.
//	containers    Docker on macOS runs inside a Linux VM. The containers are real
//	              but they are not on this host, and reporting them as though
//	              they were would attach them to the wrong machine in the
//	              topology.
//	endpoints     listener-to-process attribution needs proc_pidfdinfo from
//	              libproc, which needs cgo. The raw net.inet sysctls expose
//	              structures whose layout is not published stably enough to
//	              decode confidently, and a wrong offset there yields a plausible
//	              wrong port rather than an error.
//	cloud         the firmware equivalent of DMI is IORegistry, reachable through
//	              ioreg (a subprocess) or IOKit (cgo).
//
// Verification status: this file is verified by COMPILATION for darwin/amd64 and
// darwin/arm64. It has not been executed on Apple hardware. The record-size gate
// in DiscoverProcesses exists precisely because of that.

const (
	ctlKern     = 1
	kernProc    = 14
	kernProcAll = 0

	// sizeofKinfoProc is sizeof(struct kinfo_proc) on 64-bit Darwin. It is used
	// as a GATE, not as an assumption: a buffer that is not a whole number of
	// records means this kernel's layout differs from the one this decoder was
	// written against, and the source reports unsupported rather than decoding
	// whatever happens to be there.
	sizeofKinfoProc  = 648
	sizeofExternProc = 296

	// Field offsets within extern_proc, derived field by field from
	// <sys/proc.h> under LP64. XNU fills __p_starttime through the union at
	// offset 0 when answering sysctl, which is the whole reason the union exists.
	offStartSec  = 0 // struct timeval { int64 tv_sec; int32 tv_usec; }
	offStartUsec = 8
	offPID       = 40 // pid_t p_pid
	offComm      = 243
	lenComm      = 17 // MAXCOMLEN + 1
)

type darwinSource struct{}

func platformSet() Set {
	s := &darwinSource{}
	return Set{
		Host:       s,
		Process:    s,
		Interface:  s,
		Filesystem: s,
		Runtime:    s,
		Unsupported: []Unsupported{
			{Domain: DomainService, Reason: "launchd exposes no interface that can be read without executing launchctl or linking a private framework; parsing the launch plists would report installed jobs rather than running services"},
			{Domain: DomainContainer, Reason: "containers on macOS run inside a Linux virtual machine and are not processes of this host; reporting them here would attach them to the wrong machine"},
			{Domain: DomainEndpoint, Reason: "listening socket enumeration on macOS requires proc_pidfdinfo from libproc, which needs cgo; the agent is built without cgo"},
			{Domain: DomainCloud, Reason: "platform identification on macOS requires IOKit or the ioreg tool; the agent links no frameworks and executes nothing"},
			{Domain: DomainKubernetes, Reason: "Kubernetes pod evidence on this agent is derived from control groups, which macOS does not provide"},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Host
// ─────────────────────────────────────────────────────────────────────────────

func (s *darwinSource) DiscoverHost(context.Context) (HostFacts, error) {
	out := HostFacts{
		OS:           "darwin",
		Distribution: "macos",
		Architecture: runtime.GOARCH,
	}
	out.Hostname, _ = os.Hostname()
	out.KernelVersion, _ = syscall.Sysctl("kern.osrelease")
	// kern.osproductversion is the marketing version ("14.5"), which is what an
	// operator means by "what macOS is this". It is absent on older kernels, so
	// its absence leaves the field empty rather than falling back to the Darwin
	// kernel version under a label that says product.
	out.Version, _ = syscall.Sysctl("kern.osproductversion")

	if t, ok := darwinBootTime(); ok {
		out.BootTime = t
		out.HasBootTime = true
		// Identical derivation to the process module's Darwin reader, because
		// both modules key process entities on this value and a difference would
		// mint two entities for every process. See platform/entity.go.
		out.BootID = "boot-" + fmt.Sprint(t.Unix())
	}

	out.TimeZone, _ = time.Now().Zone()
	return out, nil
}

// darwinBootTime reads kern.boottime, which returns struct timeval.
func darwinBootTime() (time.Time, bool) {
	raw, err := syscall.Sysctl("kern.boottime")
	if err != nil {
		return time.Time{}, false
	}
	b := []byte(raw)
	if len(b) < 8 {
		return time.Time{}, false
	}
	sec := int64(le64(b))
	if sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// ─────────────────────────────────────────────────────────────────────────────
// Processes
// ─────────────────────────────────────────────────────────────────────────────

// DiscoverProcesses enumerates processes with one sysctl.
//
// Only the extern_proc half of kinfo_proc is decoded. The eproc half — which is
// where the PARENT PID lives — embeds struct vmspace and struct ucred, whose
// sizes have changed across releases. A decoder with one wrong offset there does
// not fail; it returns a parent PID that is really part of a pointer. So the
// parent process relationship is simply not built on macOS, rather than built on
// a guess.
func (s *darwinSource) DiscoverProcesses(ctx context.Context, _ ProcessOptions) (ProcessListing, error) {
	mib := [3]int32{ctlKern, kernProc, kernProcAll}

	// Two-call protocol: ask for the size, then read. The process table can grow
	// between the calls, so the buffer is padded and a short read is accepted
	// rather than retried in a loop that a forking host could keep alive
	// indefinitely.
	var need uintptr
	if _, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), 3, 0,
		uintptr(unsafe.Pointer(&need)), 0, 0); errno != 0 {
		return ProcessListing{}, fmt.Errorf("sysctl kern.proc.all (size): %w", errno)
	}
	if need == 0 {
		return ProcessListing{}, nil
	}
	need += need / 8

	buf := make([]byte, need)
	size := need
	if _, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), 3,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, 0); errno != 0 {
		return ProcessListing{}, fmt.Errorf("sysctl kern.proc.all: %w", errno)
	}
	if size > need {
		size = need
	}
	if size%sizeofKinfoProc != 0 {
		// The gate. This kernel's kinfo_proc is not the one this decoder was
		// written against, so nothing is decoded.
		return ProcessListing{}, fmt.Errorf(
			"%w: kern.proc.all returned %d bytes, not a multiple of the expected %d-byte record",
			ErrUnsupported, size, sizeofKinfoProc)
	}

	n := int(size) / sizeofKinfoProc
	out := ProcessListing{Processes: make([]ProcessFacts, 0, n)}
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		rec := buf[i*sizeofKinfoProc : i*sizeofKinfoProc+sizeofExternProc]
		facts, ok := decodeExternProc(rec)
		if !ok {
			out.Unreadable++
			continue
		}
		out.Processes = append(out.Processes, facts)
	}
	return out, nil
}

func decodeExternProc(rec []byte) (ProcessFacts, bool) {
	if len(rec) < sizeofExternProc {
		return ProcessFacts{}, false
	}
	pid := int32(le32(rec[offPID:]))
	if pid < 0 {
		return ProcessFacts{}, false
	}

	facts := ProcessFacts{
		PID:  PID(pid),
		Name: cstring(rec[offComm : offComm+lenComm]),
	}

	sec := int64(le64(rec[offStartSec:]))
	usec := int32(le32(rec[offStartUsec:]))
	if sec > 0 {
		// Microseconds since the epoch: absolute, exact, and unique enough to
		// discriminate two processes that reuse a PID.
		facts.StartRaw = uint64(sec)*1_000_000 + uint64(uint32(usec))
		facts.HasStartRaw = true
	}
	return facts, true
}

func le32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	_ = b[7]
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

// cstring reads a NUL-terminated string from a fixed-width field.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Network interfaces
// ─────────────────────────────────────────────────────────────────────────────

// darwinVirtualPrefixes name interfaces created by software on macOS.
var darwinVirtualPrefixes = []string{
	"lo", "gif", "stf", "utun", "awdl", "llw", "bridge", "p2p", "ap",
	"vmenet", "anpi", "XHC",
}

func (s *darwinSource) DiscoverInterfaces(context.Context) ([]InterfaceFacts, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating interfaces: %w", err)
	}
	out := make([]InterfaceFacts, 0, len(ifaces))
	for _, iface := range ifaces {
		f := InterfaceFacts{
			Name:         iface.Name,
			Index:        iface.Index,
			HardwareAddr: iface.HardwareAddr.String(),
			MTU:          iface.MTU,
			Up:           iface.Flags&net.FlagUp != 0,
			Loopback:     iface.Flags&net.FlagLoopback != 0,
		}
		for _, p := range darwinVirtualPrefixes {
			if strings.HasPrefix(iface.Name, p) {
				f.Virtual = true
				break
			}
		}
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				f.Addresses = append(f.Addresses, a.String())
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystems
// ─────────────────────────────────────────────────────────────────────────────

func (s *darwinSource) DiscoverFilesystems(context.Context) ([]FilesystemFacts, error) {
	// MNT_NOWAIT: return cached statistics rather than asking every filesystem
	// to refresh. A hung NFS mount would otherwise block the whole cycle, which
	// is the classic way a monitoring agent becomes the outage.
	const mntNoWait = 2

	n, err := syscall.Getfsstat(nil, mntNoWait)
	if err != nil {
		return nil, fmt.Errorf("getfsstat (count): %w", err)
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

	const mntReadOnly = 0x00000001
	const mntLocal = 0x00001000

	out := make([]FilesystemFacts, 0, n)
	for i := 0; i < n; i++ {
		fs := &buf[i]
		out = append(out, FilesystemFacts{
			Mountpoint: int8ToString(fs.Mntonname[:]),
			Device:     int8ToString(fs.Mntfromname[:]),
			FSType:     int8ToString(fs.Fstypename[:]),
			ReadOnly:   fs.Flags&mntReadOnly != 0,
			Remote:     fs.Flags&mntLocal == 0,
		})
	}
	return out, nil
}

// int8ToString converts a fixed-width C char array. Darwin's syscall package
// types these as [N]int8, so the bytes need converting rather than casting.
func int8ToString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime
// ─────────────────────────────────────────────────────────────────────────────

func (s *darwinSource) DiscoverRuntime(context.Context) (RuntimeFacts, error) {
	// The agent is not containerised on macOS in any sense this module can
	// observe: a container on macOS runs inside a Linux VM, and an agent inside
	// that VM reports itself through the Linux source.
	return RuntimeFacts{}, nil
}

var (
	_ HostSource       = (*darwinSource)(nil)
	_ ProcessSource    = (*darwinSource)(nil)
	_ InterfaceSource  = (*darwinSource)(nil)
	_ FilesystemSource = (*darwinSource)(nil)
	_ RuntimeSource    = (*darwinSource)(nil)
)
