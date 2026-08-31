//go:build linux

package container

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type sample struct {
	ShortID     string
	Runtime     string
	MemoryBytes int64
	CPUUtil     float64 // -1 when unknown
	// Net is cumulative interface traffic in the container's own network
	// namespace. Not OK where the container shares the host's namespace, or
	// where no process in it could be read.
	Net netCounters
}

func supported() bool { return true }

var lastCPU = map[string]cpuSnap{}

type cpuSnap struct {
	usec int64
	at   time.Time
}

func readSamples(max int) ([]sample, error) {
	ids := map[string]string{} // shortID -> runtime
	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		id, rt := parseCgroupDir(base, path)
		if id == "" {
			return nil
		}
		if len(id) > 12 {
			id = id[:12]
		}
		ids[id] = rt
		if len(ids) >= max {
			return filepath.SkipAll
		}
		return nil
	})

	out := make([]sample, 0, len(ids))
	now := time.Now()
	for id, rt := range ids {
		dir := findCgroupDir(id)
		if dir == "" {
			continue
		}
		mem := readIntFile(filepath.Join(dir, "memory.current"))
		if mem < 0 {
			mem = readIntFile(filepath.Join(dir, "memory.usage_in_bytes"))
		}
		cpu := -1.0
		if usec := readCPUUsage(dir); usec >= 0 {
			prev, ok := lastCPU[id]
			if ok && now.After(prev.at) {
				dt := now.Sub(prev.at).Seconds()
				if dt > 0 && usec >= prev.usec {
					// Approximate utilization vs one CPU (0–1+ under multi-core).
					cpu = float64(usec-prev.usec) / 1e6 / dt
				}
			}
			lastCPU[id] = cpuSnap{usec: usec, at: now}
		}
		out = append(out, sample{
			ShortID:     id,
			Runtime:     rt,
			MemoryBytes: max64(0, mem),
			CPUUtil:     cpu,
			Net:         readContainerNet(dir),
		})
	}
	return out, nil
}

func parseCgroupDir(base, full string) (id, runtime string) {
	// docker-<64hex>.scope
	if strings.HasPrefix(base, "docker-") && strings.HasSuffix(base, ".scope") {
		id = strings.TrimSuffix(strings.TrimPrefix(base, "docker-"), ".scope")
		return id, "docker"
	}
	// cri-containerd-<id>.scope
	if strings.HasPrefix(base, "cri-containerd-") && strings.HasSuffix(base, ".scope") {
		id = strings.TrimSuffix(strings.TrimPrefix(base, "cri-containerd-"), ".scope")
		return id, "containerd"
	}
	// .../docker/<id>
	if strings.Contains(full, string(filepath.Separator)+"docker"+string(filepath.Separator)) && len(base) >= 12 {
		if isHex(base) {
			return base, "docker"
		}
	}
	// podman-<id>.scope
	if strings.HasPrefix(base, "libpod-") && strings.HasSuffix(base, ".scope") {
		id = strings.TrimSuffix(strings.TrimPrefix(base, "libpod-"), ".scope")
		return id, "podman"
	}
	return "", ""
}

func findCgroupDir(shortID string) string {
	var found string
	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Contains(filepath.Base(path), shortID) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func readCPUUsage(dir string) int64 {
	// cgroup v2
	if v := readKeyFile(filepath.Join(dir, "cpu.stat"), "usage_usec"); v >= 0 {
		return v
	}
	// cgroup v1
	return readIntFile(filepath.Join(dir, "cpuacct.usage")) / 1000 // ns → µs approx
}

func readIntFile(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func readKeyFile(path, key string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, key) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return -1
		}
		return n
	}
	return -1
}

func isHex(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// readContainerNet reads the container's own interface counters.
//
// It needs one pid inside the container, which the cgroup already lists. Any
// of them will do: every process in a container shares its network namespace,
// so they all render the same /proc/<pid>/net/dev.
func readContainerNet(cgroupDir string) netCounters {
	hostNS := readLink("/proc/self/ns/net")
	for _, pid := range cgroupPIDs(cgroupDir, maxPIDProbes) {
		// A container on host networking shares the host's namespace. Its
		// counters are the machine's, and reporting them per container would
		// restate host.network.* under a container id.
		if ns := readLink("/proc/" + pid + "/ns/net"); ns != "" && ns == hostNS {
			return netCounters{}
		}
		b, err := os.ReadFile("/proc/" + pid + "/net/dev")
		if err != nil {
			// The process exited between listing and reading, or procfs is
			// restricted for it. Try the next one rather than giving up: on a
			// busy container the first pid is often the one that just died.
			continue
		}
		if n := parseNetDev(string(b)); n.OK {
			return n
		}
	}
	return netCounters{}
}

// maxPIDProbes bounds the retry above. A container whose every process is
// unreadable is not going to become readable on the twentieth attempt, and
// this runs once per container per cycle.
const maxPIDProbes = 4

// cgroupPIDs lists processes in a cgroup, newest first is not needed -- any
// member will do -- so it stops as soon as it has enough to try.
func cgroupPIDs(dir string, limit int) []string {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		// cgroup v1 splits the same information across controllers.
		b, err = os.ReadFile(filepath.Join(dir, "tasks"))
		if err != nil {
			return nil
		}
	}
	out := make([]string, 0, limit)
	for _, line := range strings.Split(string(b), "\n") {
		pid := strings.TrimSpace(line)
		if pid == "" {
			continue
		}
		out = append(out, pid)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func readLink(path string) string {
	s, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return s
}
