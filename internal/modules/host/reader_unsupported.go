//go:build !linux && !windows && !darwin

package host

// Platforms outside the six supported targets get a reader set with no readers
// at all. The module still starts, still reports health, and still says exactly
// why it has nothing to collect — it does not panic, does not fail the agent,
// and does not invent data.
//
// This file exists so that adding a new GOOS to the build matrix is a
// compile-and-run exercise rather than a compile error, and so that the
// "everything unsupported" path is a real code path the tests can reach rather
// than a hypothetical.

func platformSet() Set {
	reason := "host collection is not implemented for this operating system"
	unsupported := make([]Unsupported, 0, len(AllSources))
	for _, src := range AllSources {
		unsupported = append(unsupported, Unsupported{Source: src, Reason: reason})
	}
	return Set{Unsupported: unsupported}
}
