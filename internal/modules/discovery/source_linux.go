//go:build linux

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Linux discovery reads files. That is the whole design.
//
// Everything this file learns comes from procfs, sysfs, or a documented
// read-only system call. There is no cgo, no elevated privilege, and in
// particular NONE of the following, each of which is the obvious shortcut and
// each of which is refused for a stated reason:
//
//	/var/run/docker.sock          root-equivalent. Anything that can write to
//	                              it can start a privileged container and own
//	                              the host. An agent holding it is the most
//	                              valuable target on the machine. Container
//	                              inventory comes from cgroup paths instead,
//	                              which is unprivileged and gives the same answer.
//	D-Bus / systemctl             service inventory via a subprocess or a bus
//	                              connection. Both are heavier than reading
//	                              cgroup paths and /run/systemd, and executing
//	                              anything is prohibited outright.
//	the Kubernetes API server     cluster discovery needs credentials, network
//	                              egress and a client library. Local pod context
//	                              comes from the downward API instead.
//	169.254.169.254               the cloud metadata service. On IMDSv1 it
//	                              serves IAM credentials to anything that can
//	                              issue a GET, and an agent that speaks to it is
//	                              a credential-fetching primitive on every host
//	                              in the fleet. Provider identity comes from DMI.
//	/proc/PID/environ             the richest source of credentials on a host.
//	/etc/machine-id               documented by systemd as confidential; host
//	                              identity is the platform's to assign anyway.
//	/var/run/secrets/.../token    the service account token. The NAMESPACE file
//	                              beside it is read, because it is the documented
//	                              non-secret way to learn one's own namespace.
//	                              The token is not, and the distinction is
//	                              enforced by a test in internal/architecture.

var (
	procRoot = "/proc"
	sysRoot  = "/sys"
	// dmiRoot holds the firmware strings used for platform classification. Every
	// file read from it is world-readable; product_uuid, which is not, is
	// deliberately never read.
	dmiRoot = "/sys/class/dmi/id"
	// serviceAccountRoot is the projected service account volume. ONLY the
	// namespace file is ever read from it.
	serviceAccountRoot = "/var/run/secrets/kubernetes.io/serviceaccount"
)

// enumChunk bounds how many directory names are pulled from /proc at a time.
// Reading all of them at once would allocate proportionally to the process
// count, which is the unbounded behaviour the module exists to avoid.
const enumChunk = 4096

// maxSmallFile bounds a read of any of the small text files below. A procfs or
// sysfs file that is unexpectedly enormous is a reason to stop reading, not to
// allocate.
const maxSmallFile = 1 << 20

type linuxSource struct {
	// buf is reused across per-process reads within a cycle. Sources are called
	// from the single discovery goroutine, one at a time, so a shared scratch
	// buffer is safe and removes an allocation per process.
	buf []byte
}

func platformSet() Set {
	s := &linuxSource{buf: make([]byte, 4096)}
	set := Set{
		Host:       s,
		Process:    s,
		Interface:  s,
		Endpoint:   s,
		Filesystem: s,
		Runtime:    s,
		Cloud:      s,
		Kubernetes: s,
		// Containers are derived from the cgroup paths of processes the module
		// has already read. See derive.go for why that needs no runtime socket.
		Container: cgroupContainers{},
	}

	// systemd is not universally present — minimal container images, Alpine with
	// OpenRC, embedded systems. Its absence is detected once, at construction,
	// because it cannot change while the agent runs, and it produces an explicit
	// unavailable domain rather than an empty service list that would read as
	// "this host runs no services".
	if hasSystemd() {
		set.Service = s
	} else {
		set.Unsupported = append(set.Unsupported, Unsupported{
			Domain: DomainService,
			Reason: "no systemd instance was found at /run/systemd/system; service discovery on Linux is systemd-only, because the alternative init systems have no interface that can be read without executing a program",
		})
	}
	return set
}

// hasSystemd reports whether systemd is the running init system.
//
// The documented check is the existence of /run/systemd/system, which systemd
// itself specifies as the way for a program to detect that it is booted under
// systemd. It is not merely "is systemd installed" — that would be true on hosts
// booted with something else.
func hasSystemd() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

// readSmallFile reads a bounded file into a reusable buffer.
//
// Raw syscalls rather than os.ReadFile for one reason that matters at scale:
// os.Open allocates an *os.File with a finalizer, and procfs files report a size
// of zero so ReadFile runs a grow loop. At ten thousand processes per cycle
// those costs are the difference between a cycle that allocates kilobytes and
// one that allocates tens of megabytes.
func (s *linuxSource) readSmallFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	n := 0
	for {
		if n == len(s.buf) {
			if len(s.buf) >= maxSmallFile {
				return nil, fmt.Errorf("%s exceeded %d bytes", path, maxSmallFile)
			}
			s.buf = append(s.buf, make([]byte, len(s.buf))...)
		}
		got, err := syscall.Read(fd, s.buf[n:])
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if got == 0 {
			break
		}
		n += got
	}
	return s.buf[:n], nil
}

// readTrimmed reads a small file with a fresh allocation and trims it. It is for
// the handful of one-shot files — DMI strings, os-release — where reuse buys
// nothing and the value is retained.
func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxSmallFile {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// classify maps an errno onto the three outcomes a per-process read can have.
// Getting this right is what keeps normal churn out of the error counters.
func classify(err error) (vanished, denied bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT, syscall.ESRCH:
			return true, false
		case syscall.EACCES, syscall.EPERM:
			return false, true
		}
	}
	if os.IsNotExist(err) {
		return true, false
	}
	if os.IsPermission(err) {
		return false, true
	}
	return false, false
}

// ─────────────────────────────────────────────────────────────────────────────
// Host
// ─────────────────────────────────────────────────────────────────────────────

func (s *linuxSource) DiscoverHost(context.Context) (HostFacts, error) {
	var out HostFacts
	out.OS = "linux"
	out.Hostname, _ = os.Hostname()
	// GOARCH, not uname. The kernel's machine string varies by distribution
	// ("x86_64", "amd64", "aarch64") for one architecture, and a fleet inventory
	// that spells the same thing three ways cannot be grouped by it.
	out.Architecture = runtime.GOARCH
	out.KernelVersion = readTrimmed(procRoot + "/sys/kernel/osrelease")

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		id, version, pretty := parseOSRelease(data)
		out.Distribution = id
		out.Version = version
		if out.Distribution == "" {
			out.Distribution = pretty
		}
	}

	// The boot identifier. boot_id is a random UUID regenerated on every boot,
	// which is exactly the discriminator a boot-relative start stamp needs — and
	// unlike boot time it cannot drift when NTP steps the clock shortly after
	// start-up. This derivation is deliberately IDENTICAL to the process
	// module's, because both modules key process entities on it and a difference
	// would mint two entities for every process. See platform/entity.go.
	out.BootID = readTrimmed(procRoot + "/sys/kernel/random/boot_id")
	if data, err := os.ReadFile(procRoot + "/stat"); err == nil {
		if t, ok := bootTimeFrom(data); ok {
			out.BootTime = t
			out.HasBootTime = true
			if out.BootID == "" {
				out.BootID = "btime-" + strconv.FormatInt(t.Unix(), 10)
			}
		}
	}

	// The zone NAME, from the symlink target, not the abbreviation. "CEST" is
	// ambiguous across continents; "Europe/Berlin" is not.
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			out.TimeZone = target[i+len("zoneinfo/"):]
		}
	}
	if out.TimeZone == "" {
		out.TimeZone, _ = time.Now().Zone()
	}
	return out, nil
}

// bootTimeFrom extracts the btime line from /proc/stat.
func bootTimeFrom(data []byte) (time.Time, bool) {
	for _, line := range splitLines(data) {
		if len(line) < 6 || string(line[:6]) != "btime " {
			continue
		}
		v, err := parseUint(trimSpace(line[6:]))
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(int64(v), 0), true
	}
	return time.Time{}, false
}

// ─────────────────────────────────────────────────────────────────────────────
// Processes
// ─────────────────────────────────────────────────────────────────────────────

func (s *linuxSource) DiscoverProcesses(ctx context.Context, opts ProcessOptions) (ProcessListing, error) {
	dir, err := os.Open(procRoot)
	if err != nil {
		return ProcessListing{}, fmt.Errorf("opening %s: %w", procRoot, err)
	}
	defer dir.Close()

	var out ProcessListing
	// Grown from a modest hint rather than sized from the directory: a host that
	// briefly forks a hundred thousand processes must not be able to make the
	// agent allocate proportionally in one step.
	out.Processes = make([]ProcessFacts, 0, 256)

	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		names, err := dir.Readdirnames(enumChunk)
		if err != nil && len(names) == 0 {
			break
		}
		for _, name := range names {
			pid, ok := numericPID(name)
			if !ok {
				continue
			}
			facts, err := s.readProcess(pid, opts)
			if err != nil {
				switch vanished, denied := classify(err); {
				case vanished:
					out.Vanished++
				case denied:
					out.Denied++
				default:
					out.Unreadable++
				}
				continue
			}
			out.Processes = append(out.Processes, facts)
		}
		if len(names) < enumChunk {
			break
		}
	}
	return out, nil
}

// numericPID reports whether a /proc entry names a process. procfs also contains
// non-numeric entries (self, net, meminfo) which must be skipped without being
// treated as malformed.
func numericPID(name string) (PID, bool) {
	if len(name) == 0 || name[0] < '1' || name[0] > '9' {
		return 0, false
	}
	v, err := strconv.ParseUint(name, 10, 31)
	if err != nil {
		return 0, false
	}
	return PID(v), true
}

func (s *linuxSource) readProcess(pid PID, opts ProcessOptions) (ProcessFacts, error) {
	base := procRoot + "/" + strconv.Itoa(int(pid))

	data, err := s.readSmallFile(base + "/stat")
	if err != nil {
		return ProcessFacts{}, err
	}
	facts, err := parseProcStat(data)
	if err != nil {
		return ProcessFacts{}, err
	}
	// The PID in the file is authoritative. If it disagrees with the directory
	// name, the entry was recycled underneath the read, so it is treated as
	// churn rather than trusted.
	if facts.PID != pid {
		return ProcessFacts{}, syscall.ESRCH
	}

	if opts.WantCgroups {
		if cg, err := s.readSmallFile(base + "/cgroup"); err == nil {
			facts.CgroupPath = parseCgroupFile(cg)
		}
	}
	if opts.WantUser {
		// The owner of the /proc/PID directory is the process's real UID. One
		// stat(2) is far cheaper than parsing /proc/PID/status, which is a
		// fifty-line text file read for one number.
		var st syscall.Stat_t
		if err := syscall.Stat(base, &st); err == nil {
			facts.UID = KnownU64(uint64(st.Uid))
		}
	}
	return facts, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Services — systemd, without D-Bus and without executing anything
// ─────────────────────────────────────────────────────────────────────────────

// DiscoverServices enumerates systemd units from the cgroup hierarchy.
//
// THE APPROACH IS THE INTERESTING PART. The obvious way to list units is to talk
// to systemd — over D-Bus, or by running systemctl. Both are refused: executing
// a program is prohibited outright, and a bus connection is a dependency, a
// permission surface and a source of hangs on exactly the unhealthy hosts where
// an agent most needs to keep working.
//
// systemd already publishes the answer in a file tree. Every unit that has
// running processes owns a cgroup directory under the unified hierarchy, so
// walking /sys/fs/cgroup/system.slice yields the RUNNING units with no
// interface at all — and the cgroup.procs file in each directory names its
// processes, which is the same evidence the process cgroup paths give, arrived
// at from the other end.
//
// WHAT THIS CANNOT SEE, stated plainly rather than papered over: units that are
// installed but not running have no cgroup, so this reports the running service
// inventory rather than the installed one, and the Enabled field is therefore
// never populated. A host's full unit list needs systemd's own interface, and
// the module reports what it can prove instead of guessing at the rest.
func (s *linuxSource) DiscoverServices(ctx context.Context) ([]ServiceFacts, error) {
	roots := []string{
		sysRoot + "/fs/cgroup/system.slice",
		// cgroup v1 with the systemd-named hierarchy.
		sysRoot + "/fs/cgroup/systemd/system.slice",
	}
	var out []ServiceFacts
	seen := make(map[string]struct{}, 64)

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || !strings.HasSuffix(name, ".service") {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}

			svc := ServiceFacts{
				Name:  name,
				Kind:  ServiceKindSystemd,
				State: ServiceStateRunning,
			}
			if pid, ok := s.mainPIDOf(root + "/" + name); ok {
				svc.MainPID = pid
				svc.HasMainPID = true
			} else {
				// A unit directory with no processes is a unit that has exited
				// but whose cgroup has not been reaped. Reporting it as running
				// would be wrong; "unknown" is what is actually known.
				svc.State = ServiceStateUnknown
			}
			out = append(out, svc)
		}
		if len(out) > 0 {
			break
		}
	}
	return out, nil
}

// mainPIDOf returns the lowest PID in a unit's cgroup.
//
// The LOWEST, which is a heuristic-free choice: a unit's main process is started
// before the workers it forks, so it holds the lowest PID of the group except
// across a PID-space wrap. systemd's own MainPID would be authoritative but is
// only available over D-Bus. The relationship built from this carries
// Evidence=cgroup_unit rather than service_manager, so a consumer can tell which
// of the two proved it.
func (s *linuxSource) mainPIDOf(dir string) (PID, bool) {
	if pid, ok := s.lowestPIDIn(dir); ok {
		return pid, true
	}
	// A unit that DELEGATES its cgroup keeps no processes in the directory
	// systemd named after it; they live in children the unit creates itself.
	// systemd-udevd is the ordinary example -- its workers sit in
	// system.slice/systemd-udevd.service/udev -- and reading only the parent
	// reported a running daemon as "unknown" with no PID. Container managers
	// delegate the same way, and on a busy host that would be every one of
	// them.
	return s.lowestPIDBelow(dir, 0)
}

// cgroupWalk bounds the search below a delegated unit. A container manager's
// cgroup subtree has one directory per container and can nest, so an unbounded
// walk here would scale with the workload -- in the collection path, on the
// hosts least able to afford it. The main process is at the top of that subtree
// in every real delegation, so depth is what matters and it is small.
const (
	maxCgroupDepth = 3
	maxCgroupDirs  = 64
)

// lowestPIDIn returns the lowest PID directly in one cgroup.
func (s *linuxSource) lowestPIDIn(dir string) (PID, bool) {
	data, err := s.readSmallFile(dir + "/cgroup.procs")
	if err != nil {
		return 0, false
	}
	var best PID
	for _, line := range splitLines(data) {
		v, err := parseUint(trimSpace(line))
		if err != nil {
			continue
		}
		pid := PID(v)
		if best == 0 || pid < best {
			best = pid
		}
	}
	return best, best != 0
}

// lowestPIDBelow searches a delegated unit's child cgroups breadth-first, so a
// process one level down is preferred over one buried three levels deeper.
func (s *linuxSource) lowestPIDBelow(dir string, depth int) (PID, bool) {
	if depth >= maxCgroupDepth {
		return 0, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	children := make([]string, 0, 8)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if len(children) >= maxCgroupDirs {
			break
		}
		children = append(children, dir+"/"+e.Name())
	}
	for _, child := range children {
		if pid, ok := s.lowestPIDIn(child); ok {
			return pid, true
		}
	}
	for _, child := range children {
		if pid, ok := s.lowestPIDBelow(child, depth+1); ok {
			return pid, true
		}
	}
	return 0, false
}

// ─────────────────────────────────────────────────────────────────────────────
// Network interfaces
// ─────────────────────────────────────────────────────────────────────────────

// virtualInterfacePrefixes name interfaces created by software. On a container
// host these outnumber the physical ones by two orders of magnitude.
var virtualInterfacePrefixes = []string{
	"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "tunl",
	"lxcbr", "kube-", "vxlan", "nodelocaldns", "dummy", "ifb", "gre",
}

func (s *linuxSource) DiscoverInterfaces(context.Context) ([]InterfaceFacts, error) {
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
			Virtual:      isVirtualInterface(iface.Name),
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

// isVirtualInterface classifies by NAME PREFIX plus the sysfs device link.
//
// The sysfs check is the reliable one: a real interface has a `device` symlink
// pointing at its hardware, and a software interface does not. The prefix list
// is the fallback for kernels and namespaces where sysfs is not mounted, which
// is common inside containers — precisely where the veth flood happens.
func isVirtualInterface(name string) bool {
	if _, err := os.Stat(sysRoot + "/class/net/" + name + "/device"); err == nil {
		return false
	}
	if name == "lo" {
		return true
	}
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	// No device link and no known prefix. Treating it as virtual is the safer
	// default: the cost of a wrong "virtual" is one hidden interface behind a
	// documented flag, while the cost of a wrong "physical" is a thousand veth
	// entities on a container host.
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Listening endpoints
// ─────────────────────────────────────────────────────────────────────────────

var procNetFiles = []struct {
	name  string
	proto Protocol
}{
	{"tcp", ProtocolTCP},
	{"tcp6", ProtocolTCP6},
	{"udp", ProtocolUDP},
	{"udp6", ProtocolUDP6},
}

func (s *linuxSource) DiscoverEndpoints(ctx context.Context, opts EndpointOptions) ([]EndpointFacts, error) {
	var out []EndpointFacts
	for _, f := range procNetFiles {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		data, err := s.readSmallFile(procRoot + "/net/" + f.name)
		if err != nil {
			// A missing tcp6 on a host with IPv6 disabled is normal, and a
			// hardening profile may restrict /proc/net entirely. Neither is a
			// reason to fail the other three.
			continue
		}
		out = append(out, parseProcNet(data, f.proto)...)
	}
	if !opts.Correlate || len(out) == 0 {
		return out, nil
	}
	s.correlateOwners(ctx, out, opts.MaxScans)
	return out, nil
}

// correlateOwners maps socket inodes to the processes holding them.
//
// THIS IS THE MOST EXPENSIVE THING THE MODULE DOES, and the cost model is worth
// stating because it is the reason the operation is optional and separately
// bounded. The kernel gives /proc/net a socket INODE and nothing else; the only
// way to find the owner is to read every process's file-descriptor directory and
// look for a symlink to socket:[inode]. That is O(total open descriptors on the
// host) — hundreds of thousands on a busy server — not O(listeners).
//
// Three things keep it affordable:
//
//   - The wanted inodes are collected into a set FIRST, so each descriptor is
//     tested with one map lookup rather than compared against every listener.
//   - The scan stops as soon as every listener has an owner. On a normal host
//     that happens after a few dozen processes, because listeners belong to
//     long-lived low-PID services.
//   - It is hard-bounded by MaxScans regardless.
//
// Partial results are correct results here: an endpoint with no owner is
// reported without one, which is exactly what an endpoint whose owner the agent
// may not inspect looks like.
func (s *linuxSource) correlateOwners(ctx context.Context, endpoints []EndpointFacts, maxScans int) {
	wanted := make(map[uint64]int, len(endpoints))
	for i := range endpoints {
		if endpoints[i].Inode != 0 {
			wanted[endpoints[i].Inode] = i
		}
	}
	if len(wanted) == 0 {
		return
	}
	if maxScans <= 0 {
		maxScans = 1024
	}

	dir, err := os.Open(procRoot)
	if err != nil {
		return
	}
	defer dir.Close()

	scanned := 0
	for len(wanted) > 0 && scanned < maxScans {
		if ctx.Err() != nil {
			return
		}
		names, err := dir.Readdirnames(enumChunk)
		if err != nil && len(names) == 0 {
			return
		}
		for _, name := range names {
			if len(wanted) == 0 || scanned >= maxScans {
				return
			}
			pid, ok := numericPID(name)
			if !ok {
				continue
			}
			scanned++
			s.scanDescriptors(pid, wanted, endpoints)
		}
		if len(names) < enumChunk {
			return
		}
	}
}

// socketLinkPrefix is what a socket file descriptor's symlink target starts
// with: "socket:[12345]".
const socketLinkPrefix = "socket:["

func (s *linuxSource) scanDescriptors(pid PID, wanted map[uint64]int, endpoints []EndpointFacts) {
	base := procRoot + "/" + strconv.Itoa(int(pid)) + "/fd"
	dir, err := os.Open(base)
	if err != nil {
		// Denied is the common case for another user's process, and is a
		// privilege boundary rather than a fault.
		return
	}
	defer dir.Close()

	var linkBuf [64]byte
	for {
		names, err := dir.Readdirnames(enumChunk)
		if err != nil && len(names) == 0 {
			return
		}
		for _, fd := range names {
			n, err := syscall.Readlink(base+"/"+fd, linkBuf[:])
			if err != nil || n <= len(socketLinkPrefix) {
				continue
			}
			target := linkBuf[:n]
			if string(target[:len(socketLinkPrefix)]) != socketLinkPrefix {
				continue
			}
			inode, err := parseUint(target[len(socketLinkPrefix) : n-1])
			if err != nil {
				continue
			}
			idx, want := wanted[inode]
			if !want {
				continue
			}
			endpoints[idx].OwnerPID = pid
			endpoints[idx].HasOwnerPID = true
			delete(wanted, inode)
			if len(wanted) == 0 {
				return
			}
		}
		if len(names) < enumChunk {
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystems
// ─────────────────────────────────────────────────────────────────────────────

func (s *linuxSource) DiscoverFilesystems(context.Context) ([]FilesystemFacts, error) {
	// mountinfo rather than /etc/mtab or /proc/mounts: mtab is a userland file
	// that can be stale or a symlink an attacker controls, and mountinfo is the
	// only one that reports the MOUNT's read-only flag separately from the
	// superblock's.
	data, err := s.readSmallFile(procRoot + "/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("reading mountinfo: %w", err)
	}
	// Pseudo filesystems are filtered in the module rather than here, so that
	// the flag is honoured on every platform identically.
	return parseMountinfo(data, true), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime, cloud and Kubernetes context
// ─────────────────────────────────────────────────────────────────────────────

func (s *linuxSource) DiscoverRuntime(context.Context) (RuntimeFacts, error) {
	var out RuntimeFacts

	// The agent's own cgroup names its own container, if it is in one. Reading
	// one's own cgroup is not an inspection of another process.
	if data, err := s.readSmallFile(procRoot + "/self/cgroup"); err == nil {
		ev := parseCgroupPath(parseCgroupFile(data))
		if ev.ContainerID != "" {
			out.InContainer = true
			out.ContainerID = ev.ContainerID
			out.Runtime = ev.Runtime
		}
	}
	if !out.InContainer {
		// The container-runtime marker file, which Docker and most OCI runtimes
		// write into the image root. It proves containerisation even when the
		// cgroup path does not — a container started with a host cgroup
		// namespace sees the HOST's paths and would otherwise look like bare
		// metal.
		if _, err := os.Stat("/.dockerenv"); err == nil {
			out.InContainer = true
			out.Runtime = ContainerRuntimeDocker
		}
	}
	return out, nil
}

func (s *linuxSource) DiscoverCloud(context.Context) (CloudFacts, error) {
	vendor := readTrimmed(dmiRoot + "/sys_vendor")
	product := readTrimmed(dmiRoot + "/product_name")
	// The chassis asset tag distinguishes Azure from generic Hyper-V, which
	// otherwise present identical vendor and product strings.
	assetTag := readTrimmed(dmiRoot + "/chassis_asset_tag")

	if vendor == "" && product == "" {
		// No DMI at all: common in containers and on ARM boards without SMBIOS.
		// Unknown is the honest answer, and it is different from bare metal.
		return CloudFacts{Provider: CloudProviderUnknown}, nil
	}

	out := CloudFacts{
		Provider: classifyPlatform(vendor, product, assetTag),
		Vendor:   vendor,
		Product:  product,
	}
	if out.Provider == CloudProviderAWS {
		// AWS writes the instance ID into the board asset tag on Nitro
		// instances. It is the one case where the provider's own identifier is
		// available WITHOUT a metadata-service request.
		out.InstanceID = awsInstanceIDFrom(readTrimmed(dmiRoot + "/board_asset_tag"))
	}
	return out, nil
}

// DiscoverKubernetes reads the agent's OWN pod context.
//
// Three sources, all local, none of them the API server:
//
//	KUBERNETES_SERVICE_HOST   injected into every pod; proves cluster membership
//	the downward API          namespace, pod name, pod UID and node name, but
//	                          ONLY if the deployment asked for them
//	the namespace file        the documented fallback for the namespace
//
// The namespace file lives in the projected service account volume, alongside
// the TOKEN. The token is a bearer credential for the API server and is never
// read; the namespace is documented as the non-secret way for a pod to learn its
// own namespace. That distinction is enforced by a test in internal/architecture
// rather than left to this comment.
func (s *linuxSource) DiscoverKubernetes(context.Context) (KubernetesFacts, error) {
	var out KubernetesFacts
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return out, nil
	}
	out.InCluster = true

	// Reading the agent's OWN environment is not reading another process's.
	out.PodName = os.Getenv("POD_NAME")
	out.PodUID = os.Getenv("POD_UID")
	out.NodeName = os.Getenv("NODE_NAME")
	out.Namespace = os.Getenv("POD_NAMESPACE")
	if out.Namespace == "" {
		out.Namespace = readTrimmed(serviceAccountRoot + "/namespace")
	}
	if out.PodName == "" {
		// The hostname of a pod is its name unless a subdomain was configured.
		// It is a fallback, not the primary source, and it is why POD_NAME is
		// read first.
		out.PodName, _ = os.Hostname()
	}
	return out, nil
}

var (
	_ HostSource       = (*linuxSource)(nil)
	_ ProcessSource    = (*linuxSource)(nil)
	_ ServiceSource    = (*linuxSource)(nil)
	_ InterfaceSource  = (*linuxSource)(nil)
	_ EndpointSource   = (*linuxSource)(nil)
	_ FilesystemSource = (*linuxSource)(nil)
	_ RuntimeSource    = (*linuxSource)(nil)
	_ CloudSource      = (*linuxSource)(nil)
	_ KubernetesSource = (*linuxSource)(nil)
	_ ContainerSource  = cgroupContainers{}
)
