//go:build linux

package host

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Linux reads everything from procfs, sysfs and statfs. No cgo, no shelling
// out, no third-party library — and no privileged access: every path below is
// world-readable on a default install, which is what keeps the module usable
// under least privilege.

// procRoot is the procfs mount point. It is a variable so tests can point the
// reader at a fixture tree; production never changes it.
var (
	procRoot = "/proc"
	sysRoot  = "/sys"
	etcRoot  = "/etc"
)

// stRDONLY is ST_RDONLY from <sys/statvfs.h>. The standard library exposes
// MS_RDONLY (a mount(2) flag) but not the statfs f_flags bit, and the two are
// different namespaces that happen to share this value. Defining it here with
// the reason is better than reaching for the mount flag and being subtly wrong
// on some future architecture.
const stRDONLY = 0x0001

type linuxReader struct{}

func platformSet() Set {
	r := &linuxReader{}
	return Set{
		CPU:        r,
		Memory:     r,
		Disk:       r,
		Filesystem: r,
		Network:    r,
		OS:         r,
		Load:       r,
	}
}

func (r *linuxReader) ReadCPU(_ context.Context, perCore bool) (CPUStats, error) {
	data, err := os.ReadFile(procRoot + "/stat")
	if err != nil {
		return CPUStats{}, fmt.Errorf("reading %s/stat: %w", procRoot, err)
	}
	stats, err := parseProcStat(data, perCore)
	if err != nil {
		return CPUStats{}, err
	}
	// Physical core count comes from topology; it is genuinely absent on some
	// kernels and in some containers, so it stays unknown rather than being
	// approximated from the logical count.
	if n, ok := readPhysicalCores(); ok {
		stats.PhysicalCount = KnownU64(n)
	}
	return stats, nil
}

// readPhysicalCores counts distinct (package, core) pairs in sysfs.
func readPhysicalCores() (uint64, bool) {
	entries, err := os.ReadDir(sysRoot + "/devices/system/cpu")
	if err != nil {
		return 0, false
	}
	seen := make(map[string]struct{})
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") || len(name) == 3 {
			continue
		}
		if name[3] < '0' || name[3] > '9' {
			continue
		}
		base := sysRoot + "/devices/system/cpu/" + name + "/topology/"
		pkg, err1 := os.ReadFile(base + "physical_package_id")
		core, err2 := os.ReadFile(base + "core_id")
		if err1 != nil || err2 != nil {
			continue
		}
		seen[strings.TrimSpace(string(pkg))+":"+strings.TrimSpace(string(core))] = struct{}{}
	}
	if len(seen) == 0 {
		return 0, false
	}
	return uint64(len(seen)), true
}

func (r *linuxReader) ReadMemory(context.Context) (MemoryStats, error) {
	data, err := os.ReadFile(procRoot + "/meminfo")
	if err != nil {
		return MemoryStats{}, fmt.Errorf("reading %s/meminfo: %w", procRoot, err)
	}
	return parseMeminfo(data)
}

func (r *linuxReader) ReadDisks(context.Context) ([]DiskStats, error) {
	data, err := os.ReadFile(procRoot + "/diskstats")
	if err != nil {
		return nil, fmt.Errorf("reading %s/diskstats: %w", procRoot, err)
	}
	return parseDiskstats(data)
}

func (r *linuxReader) ReadInterfaces(context.Context) ([]InterfaceStats, error) {
	data, err := os.ReadFile(procRoot + "/net/dev")
	if err != nil {
		return nil, fmt.Errorf("reading %s/net/dev: %w", procRoot, err)
	}
	stats, err := parseNetDev(data)
	if err != nil {
		return nil, err
	}
	// One netlink dump for link state, rather than one sysfs read per
	// interface. Link state is a bonus: failing to get it leaves the flag
	// unknown and does not fail the whole source.
	if ifaces, err := net.Interfaces(); err == nil {
		up := make(map[string]bool, len(ifaces))
		for _, ifc := range ifaces {
			up[ifc.Name] = ifc.Flags&net.FlagUp != 0
		}
		for i := range stats {
			if v, ok := up[stats[i].Name]; ok {
				stats[i].Up = v
				stats[i].KnownState = true
			}
		}
	}
	return stats, nil
}

func (r *linuxReader) ReadLoad(context.Context) (LoadStats, error) {
	data, err := os.ReadFile(procRoot + "/loadavg")
	if err != nil {
		return LoadStats{}, fmt.Errorf("reading %s/loadavg: %w", procRoot, err)
	}
	return parseLoadavg(data)
}

func (r *linuxReader) ReadOS(context.Context) (OSInfo, error) {
	info := OSInfo{
		OS: "linux",
		// GOARCH is the architecture this binary was built for, which is the
		// architecture it is executing as. It is not necessarily the hardware's
		// widest mode — a 32-bit build on a 64-bit host reports 32-bit — and
		// that is the honest answer for an agent describing its own view.
		Architecture: runtime.GOARCH,
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if data, err := os.ReadFile(procRoot + "/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(etcRoot + "/os-release"); err == nil {
		info.Platform, info.PlatformVersion = parseOSRelease(data)
	}
	if data, err := os.ReadFile(procRoot + "/uptime"); err == nil {
		if up, perr := parseUptime(data); perr == nil {
			info.BootTime = time.Now().Add(-up)
			info.HasBootTime = true
		}
	}
	if info.KernelVersion == "" && info.Hostname == "" {
		return OSInfo{}, fmt.Errorf("no host metadata available under %s", procRoot)
	}
	return info, nil
}

func (r *linuxReader) ReadFilesystems(ctx context.Context) ([]FilesystemStats, error) {
	data, err := os.ReadFile(procRoot + "/self/mounts")
	if err != nil {
		return nil, fmt.Errorf("reading %s/self/mounts: %w", procRoot, err)
	}
	mounts, err := parseMounts(data)
	if err != nil {
		return nil, err
	}

	out := make([]FilesystemStats, 0, len(mounts))
	for _, m := range mounts {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		fs := FilesystemStats{
			Mountpoint: m.Mountpoint,
			Device:     m.Device,
			FSType:     m.FSType,
			ReadOnly:   m.ReadOnly,
		}
		var st syscall.Statfs_t
		if serr := syscall.Statfs(m.Mountpoint, &st); serr != nil {
			// A mount we cannot stat is reported with its metadata and no
			// usage figures rather than dropped, so an operator can see that
			// the agent knows about it but could not measure it.
			out = append(out, fs)
			continue
		}
		bsize := uint64(st.Bsize)
		if bsize == 0 {
			out = append(out, fs)
			continue
		}
		fs.TotalBytes = KnownU64(st.Blocks * bsize)
		fs.FreeBytes = KnownU64(st.Bfree * bsize)
		fs.AvailBytes = KnownU64(st.Bavail * bsize)
		if st.Blocks >= st.Bfree {
			fs.UsedBytes = KnownU64((st.Blocks - st.Bfree) * bsize)
		}
		if st.Files > 0 {
			fs.TotalInode = KnownU64(st.Files)
			fs.FreeInode = KnownU64(st.Ffree)
			if st.Files >= st.Ffree {
				fs.UsedInode = KnownU64(st.Files - st.Ffree)
			}
		}
		if st.Flags&stRDONLY != 0 {
			fs.ReadOnly = true
		}
		out = append(out, fs)
	}
	return out, nil
}
