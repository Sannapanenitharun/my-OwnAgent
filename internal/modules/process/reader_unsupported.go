//go:build !linux && !windows && !darwin

package process

// Platforms outside the six supported targets get a reader set with no readers
// at all. The module reports unsupported at Start, degrades agent health, and
// says exactly why — it does not panic, does not fail the agent, and does not
// invent data.
//
// This file exists so that adding a GOOS to the build matrix is a
// compile-and-run exercise rather than a compile error, and so that the
// "everything unsupported" path is a real code path the tests reach rather than
// a hypothetical one.

func platformSet() Set {
	reason := "process collection is not implemented for this operating system"
	unsupported := make([]Unsupported, 0, len(AllFeatures))
	for _, f := range AllFeatures {
		unsupported = append(unsupported, Unsupported{Feature: f, Reason: reason})
	}
	return Set{Unsupported: unsupported}
}
