# ADR-0005: Process module — identity, cardinality, and an additive entity port

**Status:** accepted (Stage 3)
**Supersedes:** nothing. **Amends:** ADR-0001 (ports), additively.

## Context

The process module is the first collector whose cost is not bounded by the
hardware it observes. A host has one CPU count, a dozen filesystems and a handful
of interfaces; it can have fifty thousand processes, and that number changes
every second.

Three problems follow, and none of them is "read process information".

## Decision 1: metrics roll up by executable; PID is never a metric label

### The problem

A naive per-process metric set on a 10,000-process host creates 10,000 × N
series. Even bounded at 1,000 processes it creates 9,000 series per host, forever
— because a PID that appears once creates a series that outlives the process by
the retention period of the metrics store.

### What was decided

Per-process metrics are aggregated by **executable name** before emission. Series
count becomes proportional to the number of distinct *programs* on the host,
which on any real machine is dozens, and is flat in the number of *processes*,
which is not.

Per-instance detail — PID, parent, start time, lifetime, command line — moves to
the **event** path. An event is a bounded record with a lifetime. A series is
forever.

### Consequences

Good: measured at 258 total series for 10,000 processes across 40 executables.
The same executable count produces identical per-executable series at 100 and at
20,000 processes.

Bad: "which nginx worker is eating the CPU?" is no longer a metric query. That is
answered by `events.top_n`, which is off by default because at one event per
process per cycle it is the module's most expensive output. The runbook says so
explicitly rather than leaving operators to discover the gap.

### Alternatives rejected

**Per-PID series with a hard cap.** Bounds the count but not the *churn*: a host
at its cap emits a different set of PIDs every cycle, so the store accumulates
short-lived series indefinitely. The bound is on concurrent series, not on series
created, and it is the latter that costs money.

**Sampling.** Rejected outright. A sampled process view cannot answer "is this
service running", which is the primary question the module exists for.

## Decision 2: identity is a process instance, not a PID

### The problem

PIDs are reused. Linux's default `pid_max` is 32768; a busy host cycles it in
minutes. An agent keyed on `(host, pid)` will, sooner or later:

- attribute one program's CPU time to another,
- emit a negative or wrapped counter delta when the new process's cumulative
  counters start below the old one's,
- report a lifetime that is the sum of two unrelated programs.

None of these fail loudly. They produce plausible numbers.

### What was decided

Every piece of retained state is keyed by `InstanceKey{boot, pid, start_stamp}`.
A PID whose start stamp changed is a *different instance*: the old one is
reported exited, the new one started, a replacement is counted, and all counter
baselines are reset.

The start stamp is used **raw** — Linux jiffies since boot, a Windows FILETIME,
Darwin microseconds — never converted to wall-clock time first. Conversion
rounds, and two consecutive instances of a recycled PID can round to the same
second.

Boot identity is included because the Linux stamp is boot-relative: without it, a
process started 500 jiffies after boot and another started 500 jiffies after the
*next* boot share a key.

### Consequences

A process whose start stamp the platform cannot supply is *identity-limited*: it
counts toward the aggregates but is never given counter baselines and is never
resolved to an entity, because it cannot be told apart from the next process to
hold its PID. That is a real degradation, and it is visible rather than silent.

## Decision 3: an additive `EntityResolver` port

### The conflict

The Stage 3 specification requires that the module resolve process entities
"through the existing platform seam" and never mint an EntityID itself. The
existing seam, `platform.Identity`, has exactly three methods — `AgentID`,
`TenantID`, `HostID` — and no way to resolve a *child* entity.

Per the standing rule, implementation stopped here rather than either inventing
IDs locally or silently reshaping a frozen contract.

### What was decided

The **smallest additive extension**: two new types and one new interface in
`internal/platform`. Nothing existing changed signature or behaviour.

```go
type EntityKind string
type EntityRef struct {
    Kind   EntityKind   // "process"
    Parent string       // the resolved host EntityID
    Keys   []Attr       // the natural key: boot, pid, start, executable
}

// OPTIONAL capability of an Identity adapter.
type EntityResolver interface {
    ResolveEntity(ctx context.Context, ref EntityRef) (string, error)
}

// Discovers it by type assertion, once, so no collector repeats it.
func ResolveEntity(ctx context.Context, id Identity, ref EntityRef) (string, error)
```

It is **optional**, discovered by type assertion, for one reason that decides the
design: every adapter that exists today keeps compiling and keeps working. An
adapter without a resolver is not broken — the caller emits an unresolved
diagnostic and continues with host-scoped telemetry, which is the contract
`Identity` already has. A test asserts exactly this.

Note carefully what `EntityRef` is: a **natural key**, not an identifier. The
collector states observable facts and the platform decides what entity they
denote. A collector that hashed those facts itself would fork the entity graph
the first moment another component hashed them differently, and reconciling a
forked entity graph is vastly more expensive than a missing attribute.

The in-process reference adapter *does* derive an identifier, deterministically,
from the natural key — because it stands in for the Discovery Runtime, which is
the assignment authority. That derivation lives behind the port, where only an
adapter can reach it, and never in a helper a module could call.

### Consequences

- If the real platform contract exposes entity resolution differently, the change
  is confined to `internal/platform` and its adapters. No module moves.
- Resolution is per instance and cached on the tracked state, so a process
  running for a week is resolved once and steady state makes zero calls.
- Metrics stay bound to the **host** entity. Binding a metric series to a process
  entity would recreate exactly the cardinality Decision 1 exists to avoid.

### Alternative rejected

**Adding the method to `platform.Identity` directly.** Smaller-looking, but it
breaks every existing adapter and every test double, and it forces adapters that
have no entity authority to implement a method they must always fail. Optional
interfaces are already how this codebase expresses "may or may not be able to"
(`Pausable`, `Configurable`, `Throttleable`); this follows that grain.

## Decision 4: churn, denial and error are three different things

Collapsing them into one "errors" counter is how a healthy, busy host gets
reported as broken. They are counted separately and only the third feeds health:

- **Vanished** — exited between enumeration and inspection. The normal case on a
  busy host.
- **Denied** — the agent may not inspect it. On unelevated Windows this is ~140
  of ~320 processes, and on Linux `/proc/PID/io` is owner-only. This is least
  privilege working.
- **Unreadable** — anything else. The only one that indicates a fault.

Making denial degrade health by default would create pressure to run the agent as
SYSTEM or root to get a green dashboard — trading a real security property for a
cosmetic one. The behaviour is configurable for operators who genuinely expect
full visibility, and it defaults off.

## Decision 5: the macOS baseline is narrow on purpose

`kinfo_proc` is `extern_proc` (296 bytes, stable, derivable from published
headers) followed by `eproc` (embeds `struct vmspace` and `struct ucred`, whose
sizes have changed across releases). Parent PID and owning UID live in `eproc`.

A decoder with one wrong offset there does not fail — it returns a parent PID
that is part of a pointer. That is unverifiable from a machine that cannot run
macOS, so those fields are reported **unsupported** rather than guessed, and the
reader gates on the 648-byte record size: a buffer that is not a whole number of
records means this kernel differs from the one the decoder targets, and nothing
is decoded at all.

macOS therefore reports 3 of 10 features. That is a real limitation, recorded in
the readiness review as the largest cross-platform gap in the phase.

## Status of the priority model

`Throttleable` drives both a longer interval and a priority floor, dropping whole
classes of output lowest-first so that what survives stays internally consistent.
Nothing calls it yet; the resource governor is Stage 13. That is stated plainly
rather than disguised.
