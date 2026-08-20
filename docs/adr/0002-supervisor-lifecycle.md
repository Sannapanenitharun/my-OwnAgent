# ADR-0002: A process-local supervisor alongside the platform Capability Runtime

- **Status:** Accepted
- **Date:** 2026-08-11
- **Stage:** 1 (agent shell + supervisor)

## Context

The architectural constraint is explicit: do not implement a second runtime or a
second capability lifecycle. The Capability Runtime already exists and is frozen.

The agent nevertheless needs behaviour that a platform-side runtime does not and
should not provide:

- Restarting a collector that lost its kernel subscription, **on one host**,
  without a round trip to a control plane.
- Quarantining a module that crash-loops, so a broken collector cannot consume a
  customer's CPU indefinitely.
- Starting and stopping the agent's own modules **in dependency order inside a
  single address space**, so the otel-engine is never torn down while a
  collector is still writing to it.
- Recovering a module panic so that a defect in the process module does not take
  down host, logs, network and discovery with it.
- Aggregating health across modules to produce one agent health value.

All of these are properties of one operating-system process on one machine. A
platform runtime cannot perform them: it is not in the address space, it cannot
recover a panic, and it cannot make a restart decision on the millisecond
timescale a local supervision loop can.

## Decision

Split the responsibility along the boundary that already exists:

- **Capability Runtime (platform, via `platform.CapabilityRuntime` port) owns
  ADMISSION.** Which capabilities may exist, with which permissions. The
  supervisor calls `Register` before any module code runs and `Authorize` for
  permission checks. A module that is not admitted never has `Start` called.

- **`internal/supervisor` (agent) owns PROCESS-LOCAL SUPERVISION.** Dependency
  ordering, restart with backoff, crash-loop quarantine, panic isolation, health
  aggregation, graceful shutdown, and the configuration reload transaction.

This is the documented architectural gap the constraint allows for. The
supervisor is not a second capability lifecycle: it never decides *whether* a
capability may exist, only how the local process runs one that has been admitted.

## Key design choices, and why

**One control loop, no goroutine per module.** The supervisor has exactly one
long-lived goroutine. Module calls are dispatched to short-lived goroutines with
deadlines, at most one lifecycle operation and one health probe per module in
flight. A goroutine per module is affordable at a dozen modules and unaffordable
at the scale this pattern gets copied to; the agent does not establish the habit.
Measured: 11 modules running steady state = **+1 goroutine** over baseline.

**Deadlines govern waiting, not execution.** Go cannot cancel a goroutine that
ignores its context. So a module's in-flight slot is held until its call
*genuinely* returns, even long after the deadline. Releasing at the deadline
instead would dispatch a second concurrent call into a module still executing the
first — accumulating a goroutine per tick, and in the case of `Start`, running
two starts of one module at once. This is enforced by
`TestSlowProbeDoesNotAccumulateGoroutines`.

**Structural failures stop startup; module failures do not.** A dependency cycle
or a missing dependency means the configuration cannot be honoured, so `Start`
returns an error. One collector failing to start is isolated, restarted, and
reflected in health — the agent runs. An agent that refuses to boot because one
collector is unavailable takes the working collectors down with it.

**Unsupported is not failure.** A module returning `module.ErrUnsupported` moves
to a terminal `Unsupported` state, degrades health, emits a diagnostic, and is
never retried. This is what allows one binary on every platform without faking
data: eBPF on Windows reports honestly instead of returning empty success.

**Optional module failure can only degrade.** Required-module failure makes the
agent unhealthy; optional-module failure caps at degraded. Without this
asymmetry, every expected capability gap would page an operator.

**Dependents are stopped when a dependency fails.** A module whose dependency has
gone is operating on assumptions that no longer hold, and letting it keep
emitting produces confidently wrong telemetry. Dependents are marked
dependency-blocked, which **does not consume their crash-loop budget** — they did
not crash — and they restart automatically when the dependency recovers.

**Crash-loop detection uses a sliding window.** A fixed lifetime cap would
permanently quarantine a module that failed five times over six months. A sliding
window quarantines only a module failing *now*, which is the condition that
actually harms the host.

**Restart backoff is jittered.** Without jitter, every host in a fleet that lost
the same backend retries in lockstep, and the recovering backend is hit by a
synchronised herd at every backoff step.

## Consequences

The supervisor is roughly 900 lines of the agent's most safety-critical code, and
it must be reviewed against the real Capability Runtime once available — in
particular to confirm that `Register`/`Authorize` are the whole of the admission
contract, and that the runtime does not also expect to drive start/stop.

If the real Capability Runtime turns out to provide process-local supervision
primitives, the correct response is to delete the overlapping parts of this
package, not to run both.

Shutdown deadlines deliberately use the **real** clock while restart scheduling
uses the injected `platform.Clock`. Shutdown is gated by things denominated in
real time — context deadlines, service-manager stop timeouts — whereas nothing
outside the agent observes restart timing. Mixing the two produced a defect
during development where a deadline was compared against a different time base.
