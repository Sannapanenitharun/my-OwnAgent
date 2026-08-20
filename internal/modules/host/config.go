package host

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// Settings is the host module's configuration.
//
// It is decoded from config.ModuleConfig.Settings, which the Stage 1 contract
// defines as map[string]string. A nested structure would read better, but the
// configuration contract is frozen and a flat namespaced key space
// ("interval.cpu", "filesystem.exclude") is expressive enough for everything
// this module needs. That finding is recorded in docs/READINESS.md along with
// the smallest compatible extension, should a later module need real nesting.
//
// Unknown keys are REJECTED, matching the agent-level configuration behaviour:
// a misspelled tuning key that is silently ignored is how an operator concludes
// they have reduced an agent's cost when they have not.
type Settings struct {
	Intervals map[Source]time.Duration

	// CollectionTimeout bounds a single source's read. It exists because a
	// statfs against a wedged network mount does not return, and one wedged
	// mount must not stop CPU and memory collection.
	CollectionTimeout time.Duration

	CPUPerCore bool
	MaxCPUs    int

	FilesystemExclude     []string
	FilesystemTypeExclude []string
	MaxFilesystems        int

	NetworkExclude     []string
	MaxInterfaces      int
	DiskExclude        []string
	MaxDisks           int
	DisabledMetrics    map[string]bool
	DisabledSources    map[Source]bool
	ReportInodeMetrics bool
}

// Default collection intervals.
//
// They are deliberately unequal. Collecting everything at the fastest useful
// rate is the single largest avoidable cost in an observability agent, and most
// of what a host reports does not change on a ten-second timescale: a
// filesystem does not fill up in ten seconds, and an OS version does not change
// at all between reboots.
func defaultIntervals() map[Source]time.Duration {
	return map[Source]time.Duration{
		SourceCPU:        10 * time.Second,
		SourceMemory:     10 * time.Second,
		SourceNetwork:    10 * time.Second,
		SourceLoad:       10 * time.Second,
		SourceDisk:       30 * time.Second,
		SourceFilesystem: 60 * time.Second,
		SourceOS:         5 * time.Minute,
	}
}

// defaultFilesystemTypeExclude lists pseudo-filesystems that exist on every
// Linux host and describe kernel bookkeeping rather than storage. Reporting
// them is pure cardinality: a container host easily has hundreds of overlay and
// tmpfs mounts, none of which an operator would alert on.
func defaultFilesystemTypeExclude() []string {
	return []string{
		"autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs",
		"devfs", "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue",
		"nsfs", "nullfs", "overlay", "proc", "pstore", "ramfs", "rpc_pipefs", "securityfs",
		"selinuxfs", "squashfs", "sysfs", "tracefs",
	}
}

// defaultFilesystemExclude lists mountpoint prefixes that are never storage an
// operator manages.
func defaultFilesystemExclude() []string {
	return []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker/", "/var/lib/kubelet/"}
}

// defaultNetworkExclude is platform-specific because the noise is.
//
// On Linux the noise is container and virtual-bridge interfaces, which scale
// with the number of running containers — an unbounded label source. On Windows
// it is tunnel pseudo-interfaces. These are substring matches, so "veth"
// catches vethGH8A2B1.
func defaultNetworkExclude() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "lxc", "tap", "tun"}
	case "windows":
		return []string{"Teredo", "IP-HTTPS", "6to4", "Kernel Debugger", "Loopback Pseudo-Interface"}
	default:
		return nil
	}
}

// defaultDiskExclude lists virtual block devices whose counters describe the
// kernel rather than hardware.
func defaultDiskExclude() []string {
	return []string{"loop", "ram", "dm-", "zram", "md"}
}

// DefaultSettings returns the built-in configuration.
func DefaultSettings() Settings {
	return Settings{
		Intervals:             defaultIntervals(),
		CollectionTimeout:     5 * time.Second,
		CPUPerCore:            false,
		MaxCPUs:               256,
		FilesystemExclude:     defaultFilesystemExclude(),
		FilesystemTypeExclude: defaultFilesystemTypeExclude(),
		MaxFilesystems:        64,
		NetworkExclude:        defaultNetworkExclude(),
		MaxInterfaces:         32,
		DiskExclude:           defaultDiskExclude(),
		MaxDisks:              32,
		DisabledMetrics:       map[string]bool{},
		DisabledSources:       map[Source]bool{},
		ReportInodeMetrics:    true,
	}
}

// Clone returns a deep copy, so that a prepared-but-not-committed
// configuration can never alias the live one.
func (s Settings) Clone() Settings {
	out := s
	out.Intervals = make(map[Source]time.Duration, len(s.Intervals))
	for k, v := range s.Intervals {
		out.Intervals[k] = v
	}
	out.FilesystemExclude = append([]string(nil), s.FilesystemExclude...)
	out.FilesystemTypeExclude = append([]string(nil), s.FilesystemTypeExclude...)
	out.NetworkExclude = append([]string(nil), s.NetworkExclude...)
	out.DiskExclude = append([]string(nil), s.DiskExclude...)
	out.DisabledMetrics = make(map[string]bool, len(s.DisabledMetrics))
	for k, v := range s.DisabledMetrics {
		out.DisabledMetrics[k] = v
	}
	out.DisabledSources = make(map[Source]bool, len(s.DisabledSources))
	for k, v := range s.DisabledSources {
		out.DisabledSources[k] = v
	}
	return out
}

// Interval returns the configured interval for a source.
func (s Settings) Interval(src Source) time.Duration {
	if d, ok := s.Intervals[src]; ok && d > 0 {
		return d
	}
	return defaultIntervals()[src]
}

// settingKeys is the complete, closed set of accepted keys.
var settingKeys = func() map[string]bool {
	keys := map[string]bool{
		"collection.timeout":      true,
		"cpu.per_core":            true,
		"cpu.max":                 true,
		"filesystem.exclude":      true,
		"filesystem.type.exclude": true,
		"filesystem.max":          true,
		"filesystem.inodes":       true,
		"network.exclude":         true,
		"network.max":             true,
		"disk.exclude":            true,
		"disk.max":                true,
		"metrics.disabled":        true,
		"sources.disabled":        true,
	}
	for _, src := range AllSources {
		keys["interval."+src.String()] = true
	}
	return keys
}()

// ParseSettings decodes and validates a module fragment.
//
// It is total and side-effect free: it touches no OS resource and mutates
// nothing, which is what makes it safe to run against a candidate configuration
// during the prepare phase before deciding whether to commit.
func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	var problems []string

	fail := func(key, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s: %s", key, fmt.Sprintf(format, args...)))
	}

	keys := make([]string, 0, len(mc.Settings))
	for k := range mc.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		raw := strings.TrimSpace(mc.Settings[key])
		if !settingKeys[key] {
			fail(key, "unknown setting")
			continue
		}

		switch {
		case strings.HasPrefix(key, "interval."):
			src, ok := sourceByName(strings.TrimPrefix(key, "interval."))
			if !ok {
				fail(key, "unknown source")
				continue
			}
			d, err := time.ParseDuration(raw)
			if err != nil {
				fail(key, "invalid duration %q", raw)
				continue
			}
			// A one-second floor is a guard rail, not a preference. Sub-second
			// polling of /proc costs more CPU than the thing it measures, and
			// an operator who sets 100ms has almost certainly made a typo.
			if d < time.Second {
				fail(key, "must be at least 1s, got %s", d)
				continue
			}
			if d > 24*time.Hour {
				fail(key, "must be at most 24h, got %s", d)
				continue
			}
			s.Intervals[src] = d

		case key == "collection.timeout":
			d, err := time.ParseDuration(raw)
			if err != nil {
				fail(key, "invalid duration %q", raw)
				continue
			}
			if d < 100*time.Millisecond || d > time.Minute {
				fail(key, "must be between 100ms and 1m, got %s", d)
				continue
			}
			s.CollectionTimeout = d

		case key == "cpu.per_core":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.CPUPerCore = b

		case key == "filesystem.inodes":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.ReportInodeMetrics = b

		case key == "cpu.max", key == "filesystem.max", key == "network.max", key == "disk.max":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fail(key, "invalid integer %q", raw)
				continue
			}
			if n < 1 || n > 4096 {
				fail(key, "must be between 1 and 4096, got %d", n)
				continue
			}
			switch key {
			case "cpu.max":
				s.MaxCPUs = n
			case "filesystem.max":
				s.MaxFilesystems = n
			case "network.max":
				s.MaxInterfaces = n
			case "disk.max":
				s.MaxDisks = n
			}

		case key == "filesystem.exclude":
			s.FilesystemExclude = splitList(raw)
		case key == "filesystem.type.exclude":
			s.FilesystemTypeExclude = splitList(raw)
		case key == "network.exclude":
			s.NetworkExclude = splitList(raw)
		case key == "disk.exclude":
			s.DiskExclude = splitList(raw)

		case key == "metrics.disabled":
			s.DisabledMetrics = map[string]bool{}
			for _, name := range splitList(raw) {
				if !IsKnownMetric(name) {
					fail(key, "unknown metric %q", name)
					continue
				}
				s.DisabledMetrics[name] = true
			}

		case key == "sources.disabled":
			s.DisabledSources = map[Source]bool{}
			for _, name := range splitList(raw) {
				src, ok := sourceByName(name)
				if !ok {
					fail(key, "unknown source %q", name)
					continue
				}
				s.DisabledSources[src] = true
			}
		}
	}

	if len(problems) > 0 {
		return Settings{}, fmt.Errorf("host: invalid configuration: %s", strings.Join(problems, "; "))
	}
	return s, nil
}

// splitList parses a comma-separated list, dropping empty entries. An empty
// string means an empty list, which is how an operator clears a default.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sourceByName(name string) (Source, bool) {
	for _, src := range AllSources {
		if src.String() == name {
			return src, true
		}
	}
	return 0, false
}
