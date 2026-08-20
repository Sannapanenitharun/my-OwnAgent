# ADR-0004: An additive `Throttleable` interface for adaptive collection

- **Status:** Accepted
- **Date:** 2026-08-11
- **Stage:** 2 (host module)
- **Amends:** ADR-0003 (module contract) — additively

## Context

The resource governor lands in Stage 13. The host module ships in Stage 2. If
collectors are written between now and then assuming a fixed schedule, Stage 13
becomes "rewrite every collector's scheduler" rather than "add a governor".

The requirement is explicit: define the seam now, and do **not** implement a
complex adaptive algorithm.

This forces a decision about the frozen module contract. There was no way to
express "reduce your workload" through the existing interfaces:

- `Configurable` is the wrong mechanism. Throttling is a transient response to
  machine conditions, not a configuration change: it must not alter the
  operator's stated configuration, must not appear as a config revision, and
  must be reversible without an operator action.
- `Pausable` is too blunt. Stopping collection entirely loses the very signal
  an operator needs to understand the pressure.

## Decision

Add one **optional** interface to `internal/module`:

```go
type Throttleable interface {
    Throttle(ctx context.Context, level PressureLevel) error
}
```

with `PressureLevel` ∈ {None, Moderate, High, Critical}.

**This is additive and backward compatible.** No existing interface changes, no
existing implementer breaks, and every Stage 1 test passes unchanged. A module
that cannot throttle simply does not implement it, and the governor learns it
must stop that module instead of slowing it — which is information the governor
needs and could not otherwise obtain.

### Why a LEVEL and not an interval or a scale factor

The governor knows the machine is under memory pressure. It does not know that
the host module's expensive operation is `statfs` against 400 mounts, or that
dropping inode counts saves most of it while keeping the module useful.

Passing a level keeps **policy** in the governor and **mechanism** in the module.
Passing intervals would require the governor to understand every module's
internals and be re-tuned whenever any of them changed — the coupling this
architecture exists to prevent.

### Why the steps are wide (×1, ×2, ×4, ×8)

If the agent is being asked to back off, it should back off enough to matter. A
10% reduction is not worth the complexity of having a governor at all.

### What Stage 2 implements

The host module implements `Throttle` by multiplying every collection interval
by the level's factor, capped at 30 minutes — beyond which it is no longer
observing the host in any useful sense and the governor should stop it instead.

`Throttle` returns immediately, is idempotent, and is safe from any goroutine.

**Nothing calls it yet.** That is stated plainly in the code and in
`docs/READINESS.md` rather than left to be discovered: Stage 2 delivers the
contract and a working implementation of it, not the governor that will drive it.

## Consequences

Every future collector should implement `Throttleable`. The reference pattern
is one method that adjusts a multiplier the scheduler already reads, which is
cheap precisely because the scheduler was designed around a computed next-due
time rather than fixed timers.

Stage 13 must decide how the supervisor discovers and drives throttleable
modules. This ADR deliberately does not: doing so would mean designing the
governor now, with none of the measurements that should inform it.

If Stage 13 finds that a level is insufficient — for example if it needs to
express "reduce network collection specifically" — the fix is a second optional
interface, not a change to this one. Adding is cheap; changing a released
contract is not.

## Alternatives considered

**Reuse `Configurable` with a synthetic fragment.** Rejected: it would conflate
operator intent with machine conditions, make throttling appear as a
configuration revision in telemetry, and require the governor to synthesise
valid configuration for every module type.

**A `ResourceBudget` struct (CPU %, memory bytes).** Rejected as premature. It
presumes the governor can attribute CPU and memory to a module accurately, which
is exactly what Stage 13 has to find out. A level is expressible today and can be
refined later; a budget would be a guess encoded in a contract.

**Wait for Stage 13 and retrofit.** Rejected: this is the option that costs the
most. Every collector written in Stages 3–12 would need its scheduler reworked.
