package supervisor

import (
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// runner is the supervisor's per-module bookkeeping.
//
// It holds no goroutine of its own. Every module in the agent is driven from
// the single supervisor control loop, with individual Start/Stop/Health calls
// dispatched to short-lived goroutines so that one slow module cannot stall the
// others. A permanent goroutine per runner would be affordable at a dozen
// modules and unaffordable at the scale the same pattern gets copied to, so the
// agent does not establish the habit.
//
// All fields are guarded by Supervisor.mu. Module methods are never invoked
// while that lock is held.
type runner struct {
	mod      module.Module
	manifest module.Manifest
	id       module.ID

	cfg      config.ModuleConfig
	required bool

	state   module.State
	lastErr error
	lease   platform.Lease

	backoff *backoff
	window  *restartWindow
	attempt int

	// opInFlight is true while a Start or Stop call is outstanding. It bounds
	// concurrency to one lifecycle operation per module.
	opInFlight bool
	// probeInFlight is true while a Health call is outstanding. A module whose
	// Health hangs must not accumulate probe goroutines every tick.
	probeInFlight bool

	// retryAt is when the next start attempt is due; zero means none pending.
	retryAt time.Time
	// blockedOnDeps distinguishes "waiting for a dependency" from "failed".
	// Dependency waits do not consume the crash-loop budget, because the
	// module did not crash — something it needs is not up yet.
	blockedOnDeps bool

	report    health.Report
	startedAt time.Time
	restarts  int64
	// generation increments on every start attempt. Results from a previous
	// generation are discarded, which is how a late Start result from a
	// module that was meanwhile stopped cannot resurrect it.
	generation uint64
}

func newRunner(m module.Module, manifest module.Manifest, cfg config.ModuleConfig, rc config.RestartConfig, rng randSource) *runner {
	return &runner{
		mod:      m,
		manifest: manifest,
		id:       manifest.ID,
		cfg:      cfg,
		required: cfg.Required,
		state:    module.StateRegistered,
		backoff:  newBackoff(rc, rng()),
		window:   newRestartWindow(rc),
		report:   health.Report{Status: health.Unknown},
	}
}

// componentHealth maps lifecycle state onto health.
//
// State is authoritative over the module's self-reported health: a module that
// last reported Healthy and has since failed to start is not healthy, and a
// module that cannot run on this platform is degraded rather than broken.
func (r *runner) componentHealth() health.Report {
	switch r.state {
	case module.StateRunning:
		return r.report
	case module.StatePaused, module.StatePausing, module.StateResuming:
		return health.DegradedReport("module is paused")
	case module.StateUnsupported:
		msg := "module is not supported in this environment"
		if r.lastErr != nil {
			msg = r.lastErr.Error()
		}
		return health.DegradedReport(msg)
	case module.StateFailed:
		if r.blockedOnDeps {
			return health.DegradedReport("waiting for a dependency to become available")
		}
		return health.UnhealthyReport(errText(r.lastErr, "module failed"))
	case module.StateCrashLooping:
		return health.UnhealthyReport(errText(r.lastErr, "module is crash-looping and has been quarantined"))
	case module.StateStarting:
		return health.Report{Status: health.Unknown, Message: "starting"}
	case module.StateStopping, module.StateStopped, module.StateRegistered:
		return health.Report{Status: health.Unknown, Message: r.state.String()}
	default:
		return health.Report{Status: health.Unknown}
	}
}

func errText(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return err.Error()
}

// ModuleStatus is an external, read-only view of one module.
type ModuleStatus struct {
	ID           module.ID
	Version      string
	Category     module.Category
	Priority     module.Priority
	State        module.State
	Required     bool
	Enabled      bool
	Health       health.Report
	Restarts     int64
	StartedAt    time.Time
	LastError    string
	Dependencies []module.ID
	Capabilities []module.Capability
	Statistics   module.Statistics
}

// Snapshot is an external, read-only view of the whole supervisor.
type Snapshot struct {
	ConfigRevision uint64
	Health         health.Aggregate
	Modules        []ModuleStatus
	StartedAt      time.Time
}

func (r *runner) status(deps []module.ID) ModuleStatus {
	return ModuleStatus{
		ID:           r.id,
		Version:      r.manifest.Version,
		Category:     r.manifest.Category,
		Priority:     r.manifest.Priority,
		State:        r.state,
		Required:     r.required,
		Enabled:      r.cfg.Enabled,
		Health:       r.componentHealth(),
		Restarts:     r.restarts,
		StartedAt:    r.startedAt,
		LastError:    errText(r.lastErr, ""),
		Dependencies: deps,
	}
}
