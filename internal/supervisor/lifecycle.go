package supervisor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// Shutdown stops every module in reverse dependency order and releases all
// resources. It is idempotent.
//
// Shutdown is bounded twice: each module gets at most ModuleStopTimeout, and
// the whole sequence gets at most ShutdownTimeout. Both bounds matter. Without
// the per-module bound one hung collector consumes the entire budget and the
// rest are never asked to stop; without the overall bound the service manager
// eventually SIGKILLs the agent, which discards buffered telemetry that a
// clean shutdown would have flushed.
func (s *Supervisor) Shutdown(ctx context.Context) error {
	begin := s.ports.Clock.Now()

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	if !s.started {
		s.stopped = true
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	cancel := s.loopCancel
	loopDone := s.loopDone
	shutdownTimeout := s.cfg.Agent.ShutdownTimeout.Std()
	moduleTimeout := s.cfg.Agent.ModuleStopTimeout.Std()
	var order []module.ID
	if s.graph != nil {
		order = s.graph.StopOrder()
	}
	s.mu.Unlock()

	// Shutdown deadlines are computed from the real clock, not from
	// platform.Clock. Everything they gate — context deadlines, time.After,
	// the service manager's own stop timeout — is denominated in real time, so
	// a test clock here would produce a deadline that is compared against a
	// different time base and expires immediately or never. Restart scheduling
	// is the opposite case and stays on the injected clock, because nothing
	// outside the agent observes it.
	deadline := time.Now().Add(shutdownTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// Stop the control loop first so that it cannot schedule a restart of a
	// module we are in the middle of stopping.
	if cancel != nil {
		cancel()
	}
	if loopDone != nil {
		select {
		case <-loopDone:
		case <-time.After(time.Until(deadline)):
			s.log.Warn("supervisor control loop did not exit within the shutdown deadline")
		}
	}

	// Let in-flight start/stop/probe goroutines settle before stopping, so a
	// module is not asked to Stop while its Start is still running.
	s.waitOps(time.Until(deadline))

	var errs []error
	for _, id := range order {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			errs = append(errs, fmt.Errorf("module %q: shutdown deadline exceeded before stop was attempted", id))
			s.diags.Record(diagnostics.Record{
				Code:        diagnostics.CodeShutdownTimeout,
				Severity:    diagnostics.Warn,
				Source:      string(id),
				Message:     "shutdown deadline exceeded before this module was stopped",
				Remediation: "increase agent.shutdown_timeout or investigate slow modules earlier in the stop order",
			})
			continue
		}
		timeout := moduleTimeout
		if remaining < timeout {
			timeout = remaining
		}
		if err := s.stopModule(ctx, id, timeout); err != nil {
			errs = append(errs, fmt.Errorf("module %q: %w", id, err))
		}
	}

	elapsed := s.ports.Clock.Now().Sub(begin)
	s.inst.shutdownLatency.Observe(elapsed.Seconds())
	s.ports.Telemetry.Emit(platform.Event{
		Name:      EventAgentStopped,
		Severity:  platform.SeverityInfo,
		Timestamp: s.ports.Clock.Now(),
	})
	s.log.Info("agent stopped", "duration", elapsed, "errors", len(errs))

	return errors.Join(errs...)
}

// stopModule stops a single module and moves it to Stopped.
func (s *Supervisor) stopModule(ctx context.Context, id module.ID, timeout time.Duration) error {
	s.mu.Lock()
	r, ok := s.runners[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	// A module that is not active holds nothing: it either never started, is
	// unsupported or disabled, or already had its cleanup Stop called on the
	// failed-start path. Calling Stop again would be harmless but pointless,
	// and it would make stop latency meaningless.
	if !r.state.Active() {
		if r.state != module.StateDisabled && r.state != module.StateUnsupported {
			r.retryAt = time.Time{}
			s.setStateLocked(r, module.StateStopped)
		}
		s.mu.Unlock()
		return nil
	}
	r.generation++
	lease := r.lease
	r.lease = nil
	s.setStateLocked(r, module.StateStopping)
	s.mu.Unlock()

	// The shutdown path does not wait for settled: the process is exiting, so a
	// module still parked inside Stop dies with it. Waiting here would let one
	// hung module consume the budget every later module needs.
	err, _ := s.callStop(ctx, r, lease, timeout)

	s.mu.Lock()
	r.startedAt = time.Time{}
	r.retryAt = time.Time{}
	s.setStateLocked(r, module.StateStopped)
	s.mu.Unlock()

	if err != nil {
		s.diags.Record(diagnostics.Record{
			Code:     diagnostics.CodeStopFailed,
			Severity: diagnostics.Warn,
			Source:   string(id),
			Message:  err.Error(),
		})
		s.log.Warn("module did not stop cleanly", "module", string(id), "error", err)
	}
	return err
}

// waitOps waits for dispatched module operations to finish, bounded by d.
func (s *Supervisor) waitOps(d time.Duration) {
	if d <= 0 {
		return
	}
	done := make(chan struct{})
	go func() {
		s.ops.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		s.log.Warn("in-flight module operations did not complete within the shutdown deadline")
	}
}

// Health returns the aggregate agent health.
//
// Disabled modules are excluded entirely: an operator who turned a collector
// off did not ask to be told the agent is degraded because it is off.
func (s *Supervisor) Health() health.Aggregate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	components := make([]health.ComponentHealth, 0, len(s.runners))
	for _, id := range s.regOrder {
		r := s.runners[id]
		if r.state == module.StateDisabled || !r.cfg.Enabled {
			continue
		}
		components = append(components, health.ComponentHealth{
			ID:       string(id),
			Required: r.required,
			Report:   r.componentHealth(),
		})
	}
	return health.AggregateOf(components)
}

// State returns one module's lifecycle state.
func (s *Supervisor) State(id module.ID) (module.State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runners[id]
	if !ok {
		return 0, false
	}
	return r.state, true
}

// Snapshot returns a consistent, read-only view of the whole supervisor. It is
// the agent's diagnostics surface.
func (s *Supervisor) Snapshot(ctx context.Context) Snapshot {
	s.mu.RLock()
	snap := Snapshot{
		ConfigRevision: s.cfg.Revision,
		StartedAt:      s.startedAt,
		Modules:        make([]ModuleStatus, 0, len(s.runners)),
	}
	type probeTarget struct {
		mod   module.Module
		index int
	}
	var targets []probeTarget
	for _, id := range s.regOrder {
		r := s.runners[id]
		var deps []module.ID
		if s.graph != nil {
			deps = s.graph.Dependencies(id)
		}
		snap.Modules = append(snap.Modules, r.status(deps))
		if r.state == module.StateRunning {
			targets = append(targets, probeTarget{mod: r.mod, index: len(snap.Modules) - 1})
		}
	}
	s.mu.RUnlock()

	snap.Health = s.Health()

	// Capabilities and statistics are pulled outside the lock, and only from
	// running modules. Both are optional interfaces: a module that does not
	// implement them reports nothing rather than an empty structure that would
	// read as "no capabilities available".
	for _, t := range targets {
		if cr, ok := t.mod.(module.CapabilityReporter); ok {
			if caps, err := safeValue(func() []module.Capability { return cr.Capabilities(ctx) }); err == nil {
				snap.Modules[t.index].Capabilities = caps
			}
		}
		if sr, ok := t.mod.(module.StatisticsReporter); ok {
			if stats, err := safeValue(func() module.Statistics { return sr.Statistics(ctx) }); err == nil {
				snap.Modules[t.index].Statistics = stats
			}
		}
	}
	return snap
}
