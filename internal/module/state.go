package module

import (
	"errors"
	"fmt"

	"github.com/obsagent/observability-agent/internal/platform"
)

// ErrUnsupported is returned by Start when a module cannot operate in this
// environment — wrong OS, missing kernel feature, absent hardware.
//
// It is distinct from a failure. A module returning ErrUnsupported is moved to
// StateUnsupported, is NOT restarted, degrades agent health rather than failing
// it, and emits an unsupported diagnostic. This is the mechanism that lets the
// agent ship one binary for every platform without ever faking data.
var ErrUnsupported = fmt.Errorf("module: %w", platform.ErrUnsupported)

// Unsupported wraps a reason as an unsupported error.
func Unsupported(reason string) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, reason)
}

// IsUnsupported reports whether err indicates unsupported functionality.
func IsUnsupported(err error) bool {
	return errors.Is(err, platform.ErrUnsupported)
}

// State is a module's lifecycle state as tracked by the supervisor.
type State int

const (
	// StateRegistered means known to the supervisor but not started.
	StateRegistered State = iota
	// StateStarting means Start is in flight.
	StateStarting
	// StateRunning means started and operating.
	StateRunning
	// StatePausing means Pause is in flight.
	StatePausing
	// StatePaused means suspended but holding resources.
	StatePaused
	// StateResuming means Resume is in flight.
	StateResuming
	// StateStopping means Stop is in flight.
	StateStopping
	// StateStopped means cleanly stopped.
	StateStopped
	// StateFailed means start or runtime failure; eligible for restart.
	StateFailed
	// StateCrashLooping means the restart budget is exhausted. The module is
	// quarantined and will not be restarted until the configuration is
	// reloaded or the agent restarts.
	StateCrashLooping
	// StateUnsupported means the module cannot run in this environment. It is
	// terminal and is not an error.
	StateUnsupported
	// StateDisabled means configuration disabled the module. It holds no
	// resources.
	StateDisabled
)

func (s State) String() string {
	switch s {
	case StateRegistered:
		return "registered"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StatePausing:
		return "pausing"
	case StatePaused:
		return "paused"
	case StateResuming:
		return "resuming"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateFailed:
		return "failed"
	case StateCrashLooping:
		return "crash_looping"
	case StateUnsupported:
		return "unsupported"
	case StateDisabled:
		return "disabled"
	default:
		return "invalid"
	}
}

// Terminal reports whether a state will not change without operator action or
// a configuration reload.
func (s State) Terminal() bool {
	switch s {
	case StateCrashLooping, StateUnsupported, StateDisabled, StateStopped:
		return true
	default:
		return false
	}
}

// Active reports whether the module currently holds resources and may be
// producing telemetry.
func (s State) Active() bool {
	switch s {
	case StateStarting, StateRunning, StatePausing, StatePaused, StateResuming, StateStopping:
		return true
	default:
		return false
	}
}

// allowedTransitions is the complete lifecycle state machine.
//
// It is enumerated rather than enforced ad hoc so that an illegal transition is
// a detectable bug — a module observed going from Stopped straight to Running,
// for instance, means a restart path skipped Starting and therefore skipped
// permission re-checks.
var allowedTransitions = map[State][]State{
	StateRegistered: {StateStarting, StateDisabled, StateStopped},
	StateStarting:   {StateRunning, StateFailed, StateUnsupported, StateStopping},
	StateRunning:    {StatePausing, StateStopping, StateFailed},
	StatePausing:    {StatePaused, StateFailed, StateStopping},
	StatePaused:     {StateResuming, StateStopping, StateFailed},
	StateResuming:   {StateRunning, StateFailed, StateStopping},
	StateStopping:   {StateStopped, StateFailed},
	// Stopped -> Failed covers a module stopped because its dependency died:
	// it is stopped, but it is not "fine", and it is awaiting restart.
	StateStopped: {StateStarting, StateDisabled, StateFailed},
	StateFailed:  {StateStarting, StateCrashLooping, StateStopping, StateStopped, StateDisabled},
	// CrashLooping -> Failed is how a configuration reload releases a
	// quarantine: the module returns to the restartable pool without being
	// started from inside the reload path.
	StateCrashLooping: {StateStarting, StateStopped, StateDisabled, StateFailed},
	StateUnsupported:  {StateStopped, StateDisabled},
	StateDisabled:     {StateStarting, StateStopped},
}

// CanTransition reports whether from -> to is a legal lifecycle transition.
// A transition to the same state is always legal and is a no-op.
func CanTransition(from, to State) bool {
	if from == to {
		return true
	}
	for _, s := range allowedTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// ErrIllegalTransition reports a rejected lifecycle transition.
type ErrIllegalTransition struct {
	Module ID
	From   State
	To     State
}

func (e *ErrIllegalTransition) Error() string {
	return fmt.Sprintf("module %s: illegal transition %s -> %s", e.Module, e.From, e.To)
}
