package supervisor

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// reloadMu serialises configuration applies. Two concurrent reloads could
// interleave their prepare and commit phases and leave modules on different
// revisions, which is exactly the partial application the model forbids.
var reloadMu sync.Mutex

// Reload applies a new configuration as an all-or-nothing transaction.
//
// The sequence is:
//
//  1. Validate the candidate, and re-resolve the dependency graph over the
//     modules it enables. Structural problems are rejected here, before
//     anything has been touched.
//  2. PREPARE every affected Configurable module. A single rejection aborts
//     the reload and rolls back every module that already prepared.
//  3. COMMIT every prepared module and swap in the new configuration.
//  4. Reconcile the module set: stop what was disabled, start what was
//     enabled, and release crash-loop quarantines.
//
// Nothing observable changes before step 3. If the reload is rejected, the
// agent keeps running exactly the configuration it was running before, which is
// the only safe outcome: an operator pushing a bad configuration to a fleet
// should lose the change, not the fleet.
func (s *Supervisor) Reload(ctx context.Context, candidate config.Config) error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	if err := config.Validate(candidate); err != nil {
		s.recordConfigRejected(err)
		return err
	}

	s.mu.RLock()
	if !s.started || s.stopped {
		s.mu.RUnlock()
		return errors.New("supervisor: cannot reload before Start or after Shutdown")
	}
	oldCfg := s.cfg.Clone()
	timeout := s.cfg.Agent.ModuleStartTimeout.Std()

	manifests := make(map[module.ID]module.Manifest, len(s.runners))
	unknown := make([]string, 0)
	for id, r := range s.runners {
		if candidate.ModuleFor(string(id)).Enabled {
			manifests[id] = r.manifest
		}
	}
	for id := range candidate.Modules {
		if _, ok := s.runners[module.ID(id)]; !ok {
			unknown = append(unknown, id)
		}
	}
	s.mu.RUnlock()

	// A configuration naming a module this binary does not contain is almost
	// always a version skew between the config management system and the
	// installed agent. Reject rather than silently ignore: silently ignoring
	// is how an operator concludes a collector is running when it is not.
	if len(unknown) > 0 {
		err := fmt.Errorf("supervisor: configuration references modules not present in this build: %v", unknown)
		s.recordConfigRejected(err)
		return err
	}

	newGraph, err := Resolve(manifests)
	if err != nil {
		s.recordConfigRejected(err)
		return err
	}

	// ---- Phase 1: prepare -------------------------------------------------
	type prepared struct {
		id  module.ID
		mod module.Configurable
	}
	var (
		toPrepare []prepared
		committed []prepared
	)

	s.mu.RLock()
	for _, id := range s.regOrder {
		r := s.runners[id]
		newFragment := candidate.ModuleFor(string(id))
		if reflect.DeepEqual(r.cfg, newFragment) {
			continue
		}
		// Only a running module can be reconfigured in place. A stopped or
		// failed module picks up the new fragment when it next starts.
		if r.state != module.StateRunning {
			continue
		}
		if c, ok := r.mod.(module.Configurable); ok {
			toPrepare = append(toPrepare, prepared{id: id, mod: c})
		}
	}
	s.mu.RUnlock()

	rollbackAll := func(reason error) {
		for _, p := range committed {
			if rerr := timedCall(ctx, timeout, p.mod.RollbackConfig); rerr != nil {
				s.log.Error("module failed to roll back configuration",
					"module", string(p.id), "error", rerr)
				s.diags.Record(diagnostics.Record{
					Code:        diagnostics.CodeConfigRolledBack,
					Severity:    diagnostics.Error,
					Source:      string(p.id),
					Message:     "rollback after a rejected configuration failed; module may be inconsistent",
					Remediation: "restart the agent to return this module to a known configuration",
				})
			}
		}
		s.inst.configRollbacks.Add(1)
		s.diags.Record(diagnostics.Record{
			Code:        diagnostics.CodeConfigRolledBack,
			Severity:    diagnostics.Warn,
			Source:      "supervisor",
			Message:     "configuration rejected during prepare; previous configuration retained",
			Remediation: "correct the configuration and reload; the agent is still running the previous revision",
			Attrs:       map[string]string{"reason": reason.Error()},
		})
		s.ports.Telemetry.Emit(platform.Event{
			Name:      EventConfigRolledBack,
			Severity:  platform.SeverityWarn,
			Timestamp: s.ports.Clock.Now(),
		})
	}

	for _, p := range toPrepare {
		fragment := candidate.ModuleFor(string(p.id))
		err := timedCall(ctx, timeout, func(cctx context.Context) error {
			return p.mod.PrepareConfig(cctx, fragment)
		})
		if err != nil {
			rollbackAll(err)
			wrapped := fmt.Errorf("supervisor: module %q rejected the configuration: %w", p.id, err)
			s.log.Warn("configuration reload rejected", "module", string(p.id), "error", err)
			return wrapped
		}
		committed = append(committed, p)
	}

	// ---- Phase 2: commit --------------------------------------------------
	// A commit failure cannot be undone by rolling the others back — some
	// modules are already on the new configuration. It is recorded loudly and
	// the reload proceeds, because leaving the agent half-committed with no
	// record is worse than a documented inconsistency an operator can act on.
	for _, p := range committed {
		if err := timedCall(ctx, timeout, p.mod.CommitConfig); err != nil {
			s.log.Error("module failed to commit configuration",
				"module", string(p.id), "error", err)
			s.diags.Record(diagnostics.Record{
				Code:        diagnostics.CodeConfigInvalid,
				Severity:    diagnostics.Error,
				Source:      string(p.id),
				Message:     "commit failed after a successful prepare; module configuration is inconsistent",
				Remediation: "restart the agent to return this module to a known configuration",
			})
		}
	}

	// ---- Phase 3: swap and reconcile --------------------------------------
	applied := candidate.Clone()

	s.mu.Lock()
	s.cfg = applied
	s.graph = newGraph
	var toStop, toStart []module.ID
	for _, id := range s.regOrder {
		r := s.runners[id]
		was := r.cfg
		now := applied.ModuleFor(string(id))
		r.cfg = now
		r.required = now.Required

		switch {
		case was.Enabled && !now.Enabled:
			toStop = append(toStop, id)
		case !was.Enabled && now.Enabled:
			toStart = append(toStart, id)
		}

		// A reload is the documented way to release a quarantine, so an
		// operator who has fixed the underlying fault does not have to
		// restart the whole agent and lose every other module's state.
		if r.state == module.StateCrashLooping && now.Enabled {
			r.window.reset()
			r.attempt = 0
			r.lastErr = nil
			r.retryAt = s.ports.Clock.Now()
			s.setStateLocked(r, module.StateFailed)
			s.log.Info("crash-loop quarantine released by configuration reload", "module", string(id))
		}
	}
	stopTimeout := applied.Agent.ModuleStopTimeout.Std()
	s.mu.Unlock()

	for _, id := range toStop {
		if err := s.stopModule(ctx, id, stopTimeout); err != nil {
			s.log.Warn("module disabled by configuration did not stop cleanly",
				"module", string(id), "error", err)
		}
		s.mu.Lock()
		if r, ok := s.runners[id]; ok {
			r.retryAt = time.Time{}
			s.setStateLocked(r, module.StateDisabled)
		}
		s.mu.Unlock()
	}

	if len(toStart) > 0 {
		enable := make(map[module.ID]bool, len(toStart))
		for _, id := range toStart {
			enable[id] = true
		}
		s.mu.Lock()
		for _, id := range toStart {
			if r, ok := s.runners[id]; ok && r.state == module.StateDisabled {
				s.setStateLocked(r, module.StateStopped)
			}
		}
		s.mu.Unlock()
		// Start in the new graph's order so dependencies come up first.
		for _, id := range newGraph.StartOrder() {
			if enable[id] {
				s.startOnce(ctx, id)
			}
		}
	}

	s.inst.configReloads.Add(1)
	s.inst.configRevision.Set(float64(applied.Revision))
	s.ports.Telemetry.Emit(platform.Event{
		Name:      EventConfigApplied,
		Severity:  platform.SeverityInfo,
		Timestamp: s.ports.Clock.Now(),
	})
	s.log.Info("configuration applied",
		"revision", applied.Revision,
		"previous_revision", oldCfg.Revision,
		"reconfigured", len(committed),
		"started", len(toStart),
		"stopped", len(toStop))

	s.nudge()
	return nil
}

func (s *Supervisor) recordConfigRejected(err error) {
	s.diags.Record(diagnostics.Record{
		Code:        diagnostics.CodeConfigInvalid,
		Severity:    diagnostics.Error,
		Source:      "supervisor",
		Message:     err.Error(),
		Remediation: "correct the configuration and reload; the previous configuration is still in effect",
	})
	s.inst.configRollbacks.Add(1)
	s.log.Warn("configuration rejected", "error", err)
}
