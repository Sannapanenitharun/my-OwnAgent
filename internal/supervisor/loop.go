package supervisor

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	runtimemetrics "runtime/metrics"
	"time"

	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/health"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform"
)

// loop is the supervisor's single long-lived goroutine.
//
// Everything periodic or reactive happens here: health probing, restart
// scheduling, and runtime failure handling. Work that can block — any call into
// module code — is dispatched to a short-lived goroutine so that the loop
// itself never waits on a module.
func (s *Supervisor) loop(ctx context.Context) {
	defer close(s.loopDone)

	s.mu.RLock()
	interval := s.cfg.Agent.HealthInterval.Std()
	s.mu.RUnlock()

	ticker := s.ports.Clock.NewTicker(interval)
	defer ticker.Stop()

	var retryCh <-chan time.Time
	var armedFor time.Time

	for {
		s.processDueRetries(ctx)

		// Arm a timer for the next scheduled restart, re-arming only when the
		// deadline actually changes so that a busy loop does not accumulate
		// timers.
		if soonest, ok := s.soonestRetry(); ok {
			if !soonest.Equal(armedFor) {
				d := soonest.Sub(s.ports.Clock.Now())
				if d < 0 {
					d = 0
				}
				retryCh = s.ports.Clock.After(d)
				armedFor = soonest
			}
		} else {
			retryCh = nil
			armedFor = time.Time{}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			s.collectSelfMetrics()
			s.probeAll(ctx)
		case <-retryCh:
			armedFor = time.Time{}
		case <-s.wake:
		case f := <-s.failures:
			s.handleRuntimeFailure(ctx, f)
		}
	}
}

// processDueRetries starts every module whose restart deadline has arrived.
func (s *Supervisor) processDueRetries(ctx context.Context) {
	now := s.ports.Clock.Now()

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	var due []module.ID
	for _, id := range s.regOrder {
		r := s.runners[id]
		if r.state != module.StateFailed || r.opInFlight || r.retryAt.IsZero() {
			continue
		}
		if !r.retryAt.After(now) {
			due = append(due, id)
		}
	}
	s.mu.Unlock()

	for _, id := range due {
		id := id
		r, host, gen, ok := s.claimStart(ctx, id)
		if !ok {
			continue
		}
		s.mu.Lock()
		r.restarts++
		s.mu.Unlock()
		s.inst.restarts.Add(1, platform.A(AttrModule, string(id)))

		s.ops.Add(1)
		go func() {
			defer s.ops.Done()
			s.runStart(ctx, r, host, gen)
		}()
	}
}

// soonestRetry returns the earliest pending restart deadline.
func (s *Supervisor) soonestRetry() (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var soonest time.Time
	found := false
	for _, r := range s.runners {
		if r.state != module.StateFailed || r.retryAt.IsZero() || r.opInFlight {
			continue
		}
		if !found || r.retryAt.Before(soonest) {
			soonest = r.retryAt
			found = true
		}
	}
	return soonest, found
}

// probeAll probes the health of every running module.
func (s *Supervisor) probeAll(ctx context.Context) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	timeout := s.cfg.Agent.HealthProbeTimeout.Std()
	var targets []*runner
	for _, id := range s.regOrder {
		r := s.runners[id]
		if r.state != module.StateRunning || r.probeInFlight {
			continue
		}
		r.probeInFlight = true
		targets = append(targets, r)
	}
	s.mu.Unlock()

	for _, r := range targets {
		r := r
		s.ops.Add(1)
		go func() {
			defer s.ops.Done()
			s.probe(ctx, r, timeout)
		}()
	}

	s.publishAggregateHealth()
}

// probe runs one module's health check under a deadline.
func (s *Supervisor) probe(ctx context.Context, r *runner, timeout time.Duration) {
	attr := platform.A(AttrModule, string(r.id))
	begin := s.ports.Clock.Now()

	report, err, settled := valueWithTimeout(ctx, timeout, func(cctx context.Context) health.Report {
		return r.mod.Health(cctx)
	})

	elapsed := s.ports.Clock.Now().Sub(begin)
	s.inst.healthLatency.Observe(elapsed.Seconds(), attr)

	// Record the outcome now so health reflects the timeout promptly, but hold
	// the probe slot until the module's Health call really returns. A late
	// result is discarded: it describes a moment that has already passed.
	defer func() {
		<-settled
		s.mu.Lock()
		r.probeInFlight = false
		s.mu.Unlock()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case err == nil:
		r.report = report
		s.inst.healthStatus.Set(float64(report.Status), attr)
		for _, d := range report.Diagnostics {
			d.Source = string(r.id)
			s.diags.Record(d)
		}

	default:
		var pe *PanicError
		if errors.As(err, &pe) {
			s.inst.panics.Add(1, attr)
			s.log.Error("module panicked during health probe",
				"module", string(r.id), "panic", fmt.Sprint(pe.Value))
			r.report = health.UnhealthyReport("health probe panicked")
			s.diags.Record(diagnostics.Record{
				Code:     diagnostics.CodePanic,
				Severity: diagnostics.Error,
				Source:   string(r.id),
				Message:  "module panicked during health probe and was isolated",
			})
		} else {
			// A probe that overran its deadline tells us the module is not
			// answering. Reporting Unknown rather than Unhealthy is
			// deliberate: a slow probe is evidence of a slow module, not
			// proof of a broken one, and escalating it to Unhealthy would
			// page operators for transient scheduler pressure.
			s.inst.healthTimeouts.Add(1, attr)
			r.report = health.Report{Status: health.Unknown, Message: "health probe did not complete within its deadline"}
			s.diags.Record(diagnostics.Record{
				Code:        diagnostics.CodeHealthTimeout,
				Severity:    diagnostics.Warn,
				Source:      string(r.id),
				Message:     "health probe exceeded its deadline",
				Remediation: "inspect module load; a probe must be cheap and non-blocking",
			})
		}
		s.inst.healthStatus.Set(float64(r.report.Status), attr)
	}
}

// handleRuntimeFailure processes a failure reported by a running module.
//
// The failed module and everything that depends on it are stopped, then the
// failed module is scheduled for restart. Stopping dependents is not collateral
// damage: a module whose dependency has gone is operating on assumptions that
// no longer hold, and letting it keep emitting is how an agent produces
// confidently wrong telemetry. Dependents are marked dependency-blocked, which
// does not consume their crash-loop budget, and they restart automatically once
// the dependency is running again.
func (s *Supervisor) handleRuntimeFailure(ctx context.Context, f moduleFailure) {
	s.mu.Lock()
	r, ok := s.runners[f.id]
	if !ok || s.stopped || f.generation != r.generation || r.state != module.StateRunning || r.opInFlight {
		s.mu.Unlock()
		return
	}
	r.opInFlight = true
	r.lastErr = f.err
	s.setStateLocked(r, module.StateStopping)
	lease := r.lease
	r.lease = nil
	stopTimeout := s.cfg.Agent.ModuleStopTimeout.Std()
	var dependents []module.ID
	if s.graph != nil {
		dependents = s.graph.TransitiveDependents(f.id)
	}
	s.mu.Unlock()

	s.log.Warn("module reported a runtime failure", "module", string(f.id), "error", f.err)

	s.ops.Add(1)
	go func() {
		defer s.ops.Done()

		for _, dep := range dependents {
			s.stopForDependency(ctx, dep, f.id, stopTimeout)
		}

		err, settled := s.callStop(ctx, r, lease, stopTimeout)
		if err != nil {
			s.diags.Record(diagnostics.Record{
				Code:     diagnostics.CodeStopFailed,
				Severity: diagnostics.Warn,
				Source:   string(f.id),
				Message:  err.Error(),
			})
		}
		// This module is scheduled for restart, so its Stop must have really
		// finished before the slot is released and a Start can be dispatched.
		<-settled

		s.mu.Lock()
		r.opInFlight = false
		r.startedAt = time.Time{}
		s.setStateLocked(r, module.StateStopped)
		s.failLocked(r, f.err, s.ports.Clock.Now(), diagnostics.CodeStartFailed)
		s.mu.Unlock()
		s.nudge()
	}()
}

// stopForDependency stops a module because a dependency went away, and marks it
// for automatic restart without charging its crash-loop budget.
func (s *Supervisor) stopForDependency(ctx context.Context, id, cause module.ID, timeout time.Duration) {
	s.mu.Lock()
	r, ok := s.runners[id]
	if !ok || r.opInFlight || !r.state.Active() {
		s.mu.Unlock()
		return
	}
	r.opInFlight = true
	r.generation++
	lease := r.lease
	r.lease = nil
	s.setStateLocked(r, module.StateStopping)
	retryDelay := s.cfg.Agent.Restart.InitialBackoff.Std()
	s.mu.Unlock()

	err, settled := s.callStop(ctx, r, lease, timeout)
	if err != nil {
		s.diags.Record(diagnostics.Record{
			Code:     diagnostics.CodeStopFailed,
			Severity: diagnostics.Warn,
			Source:   string(id),
			Message:  err.Error(),
		})
	}
	// The dependent restarts once its dependency recovers, so hold the slot
	// until Stop has genuinely returned.
	<-settled

	s.mu.Lock()
	defer s.mu.Unlock()
	r.opInFlight = false
	r.startedAt = time.Time{}
	r.blockedOnDeps = true
	r.lastErr = fmt.Errorf("stopped because dependency %q failed", cause)
	r.retryAt = s.ports.Clock.Now().Add(retryDelay)
	s.setStateLocked(r, module.StateStopped)
	s.setStateLocked(r, module.StateFailed)
	s.diags.Record(diagnostics.Record{
		Code:        diagnostics.CodeDependencyUnavailable,
		Severity:    diagnostics.Warn,
		Source:      string(id),
		Message:     "stopped because a dependency failed; will restart automatically when it recovers",
		Remediation: "resolve the failure in the named dependency",
		Attrs:       map[string]string{"dependency": string(cause)},
	})
}

// callStop invokes a module's Stop under a deadline and releases its lease.
//
// The lease is released whether or not Stop succeeded. A module that cannot
// stop cleanly must still surrender its capability admission, or a restart
// would be refused because the old registration is still held.
//
// The returned settled channel closes when Stop genuinely returns. Callers that
// will restart the module must wait for it before releasing the module's
// in-flight slot, so that Start is never invoked while a previous Stop is still
// executing. The shutdown path deliberately does NOT wait: the process is
// exiting, a leaked goroutine dies with it, and waiting would let one hung
// module consume the whole shutdown budget.
func (s *Supervisor) callStop(ctx context.Context, r *runner, lease platform.Lease, timeout time.Duration) (error, <-chan struct{}) {
	attr := platform.A(AttrModule, string(r.id))
	begin := s.ports.Clock.Now()

	err, settled := withTimeout(ctx, timeout, func(cctx context.Context) error {
		return r.mod.Stop(cctx)
	})

	s.inst.stopLatency.Observe(s.ports.Clock.Now().Sub(begin).Seconds(), attr)

	if lease != nil {
		if rerr := lease.Release(ctx); rerr != nil && err == nil {
			err = fmt.Errorf("releasing capability lease: %w", rerr)
		}
	}

	var pe *PanicError
	if errors.As(err, &pe) {
		s.inst.panics.Add(1, attr)
		s.log.Error("module panicked during stop",
			"module", string(r.id), "panic", fmt.Sprint(pe.Value))
	}
	return err, settled
}

// heapBytesMetric is the runtime/metrics sample used for the agent's own heap
// gauge. runtime/metrics is used rather than runtime.ReadMemStats because
// ReadMemStats stops the world, and an observability agent must not pause the
// process it shares with the customer's workload merely to report on itself.
const heapBytesMetric = "/memory/classes/heap/objects:bytes"

// collectSelfMetrics publishes the agent's own resource usage through the same
// Telemetry Plane port every module uses.
func (s *Supervisor) collectSelfMetrics() {
	s.inst.goroutines.Set(float64(runtime.NumGoroutine()))

	samples := []runtimemetrics.Sample{{Name: heapBytesMetric}}
	runtimemetrics.Read(samples)
	if samples[0].Value.Kind() == runtimemetrics.KindUint64 {
		s.inst.heapBytes.Set(float64(samples[0].Value.Uint64()))
	}

	s.inst.diagnosticsDropped.Set(float64(s.diags.Dropped()))

	s.mu.RLock()
	revision := s.cfg.Revision
	s.mu.RUnlock()
	s.inst.configRevision.Set(float64(revision))
}

// publishAggregateHealth recomputes and publishes agent-level health.
func (s *Supervisor) publishAggregateHealth() {
	agg := s.Health()
	s.inst.agentHealth.Set(float64(agg.Status))
}
