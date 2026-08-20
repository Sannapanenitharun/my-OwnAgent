package module

import "context"

// PressureLevel describes how hard the agent is being asked to back off.
//
// It is a LEVEL, not a collection interval or a scale factor, and that is
// deliberate: policy ("the host is under memory pressure") belongs to the
// resource governor, while mechanism ("so I will stop reading inode counts and
// stretch my filesystem interval") belongs to the module that knows what its
// own work costs. A governor that dictated intervals would need to understand
// every module's internals, and would be re-tuned every time one changed.
type PressureLevel int

const (
	// PressureNone is normal operation. A module at PressureNone must collect
	// at its configured intervals.
	PressureNone PressureLevel = iota
	// PressureModerate asks for a modest reduction: stretch intervals, drop
	// optional detail.
	PressureModerate
	// PressureHigh asks for a large reduction: collect only what is needed to
	// stay useful and to keep reporting health.
	PressureHigh
	// PressureCritical asks the module to do the minimum that keeps it alive.
	// The agent is close to harming its host; the next step above this is the
	// governor stopping the module outright.
	PressureCritical
)

func (p PressureLevel) String() string {
	switch p {
	case PressureNone:
		return "none"
	case PressureModerate:
		return "moderate"
	case PressureHigh:
		return "high"
	case PressureCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Throttleable is implemented by modules that can reduce their own workload on
// request.
//
// This is the seam the resource governor (Stage 13) will drive. It is defined
// now, and implemented by modules now, because retrofitting back-pressure into
// a collector that was written assuming a fixed schedule means rewriting its
// scheduler — whereas a collector built against this interface from the start
// only has to decide what it is willing to give up.
//
// Nothing in the agent calls Throttle yet. That is stated plainly rather than
// disguised: Stage 2 delivers the contract and a working implementation of it,
// not the governor that will use it.
//
// Implementations must:
//   - return promptly, doing no collection work of their own;
//   - be idempotent, since the governor may re-assert the same level;
//   - be safe to call from any goroutine at any time after Start;
//   - return to configured behaviour when called with PressureNone.
//
// A module that cannot throttle simply does not implement this interface, and
// the governor learns that it must stop the module instead of slowing it.
type Throttleable interface {
	Throttle(ctx context.Context, level PressureLevel) error
}
