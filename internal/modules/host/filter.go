package host

import (
	"sort"
	"strings"
)

// selectBounded applies exclusion rules and a hard series cap.
//
// Two properties matter more than they look:
//
//  1. Selection is DETERMINISTIC — items are sorted by name and the first max
//     are kept. If the cap were applied in whatever order the OS returned, a
//     host over its cap would report a different subset every cycle, producing
//     a churn of half-populated series that is worse than reporting nothing.
//     A stable subset is at least a consistent, explainable view.
//
//  2. Exclusion is by SUBSTRING, case-insensitively. The names that need
//     excluding are generated — vethAB12CD, "vEthernet (Default Switch)-QoS
//     Packet Scheduler-0000" — so prefix matching alone would force operators
//     to enumerate what they cannot predict.
//
// The number dropped by the cap is returned so the caller can emit it, because
// a silently truncated metric is a trap for whoever reads the dashboard.
func selectBounded[T any](items []T, name func(T) string, exclude []string, max int) (kept []T, droppedByCap int) {
	filtered := make([]T, 0, len(items))
	for _, item := range items {
		if !excluded(name(item), exclude) {
			filtered = append(filtered, item)
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return name(filtered[i]) < name(filtered[j])
	})

	if max > 0 && len(filtered) > max {
		return filtered[:max], len(filtered) - max
	}
	return filtered, 0
}

// excluded reports whether name contains any exclusion substring.
func excluded(name string, exclude []string) bool {
	if len(exclude) == 0 {
		return false
	}
	lower := strings.ToLower(name)
	for _, e := range exclude {
		if e == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

// filterFilesystems applies mountpoint and filesystem-type exclusions and the
// mount cap.
//
// Type exclusion runs first because it is the cheaper and higher-yield filter:
// on a container host the overwhelming majority of mounts are pseudo-filesystems
// that no exclusion of mountpoints would catch, since their paths are
// unpredictable.
func filterFilesystems(in []FilesystemStats, s Settings) ([]FilesystemStats, int) {
	byType := make([]FilesystemStats, 0, len(in))
	for _, fs := range in {
		if excluded(fs.FSType, s.FilesystemTypeExclude) {
			continue
		}
		// A mount with no usable size is a bind mount or a placeholder; it
		// carries no information and would occupy a series slot that a real
		// filesystem needs.
		if !fs.TotalBytes.OK || fs.TotalBytes.V == 0 {
			continue
		}
		byType = append(byType, fs)
	}
	return selectBounded(byType,
		func(fs FilesystemStats) string { return fs.Mountpoint },
		s.FilesystemExclude, s.MaxFilesystems)
}
