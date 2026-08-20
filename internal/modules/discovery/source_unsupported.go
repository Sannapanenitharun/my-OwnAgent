//go:build !linux && !windows && !darwin

package discovery

// platformSet reports every domain as unavailable, with a reason.
//
// The module then reports itself unsupported at Start, which puts it in the
// supervisor's terminal unsupported state: degraded agent health, a diagnostic,
// and no restart attempts against a condition that cannot change. It does not
// fabricate an empty topology, because "this host has nothing on it" and "this
// agent cannot see" are different claims and only one of them is true.
func platformSet() Set {
	const reason = "discovery is not implemented for this operating system"
	unsupported := make([]Unsupported, 0, len(AllDomains))
	for _, d := range AllDomains {
		unsupported = append(unsupported, Unsupported{Domain: d, Reason: reason})
	}
	return Set{Unsupported: unsupported}
}
