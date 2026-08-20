# ADR-0003: A small required module interface with optional capability interfaces

- **Status:** Accepted
- **Date:** 2026-08-11
- **Stage:** 1 (agent shell + supervisor)

## Context

Every module — the seven collectors, discovery, the otel engine, the secret
scrubber, the updater — must conform to one common contract. The specified
concepts are: ID, Version, Manifest, Dependencies, Permissions, Start, Stop,
Pause, Resume, Configure, Health, Diagnostics, Statistics, Capabilities.

The obvious encoding is a single interface with all fourteen. The problem is
what that produces in practice: a module that cannot be paused writes an empty
`Pause`, a module with no statistics returns an empty map, and a module that
cannot be reconfigured returns `nil` from `Configure` and quietly ignores the
new settings. The interface is satisfied; none of the behaviour exists; and the
supervisor cannot tell the difference between "paused successfully" and "did
nothing and said yes".

## Decision

**Required interface — `module.Module`:** `Manifest`, `Start`, `Stop`, `Health`.
Four methods, every one of which every module genuinely has.

**Optional interfaces**, each detected with a type assertion:

| Interface | Meaning when absent |
|---|---|
| `Pausable` | this module cannot be paused; the governor must stop it instead |
| `Configurable` | this module takes configuration only at start |
| `Diagnosable` | this module has no on-demand constraints to report |
| `StatisticsReporter` | this module exposes no operational counters |
| `CapabilityReporter` | this module declares no conditional capabilities |

Absence is now *answerable*. The supervisor reports "not pausable" rather than
calling a method that lies. `module.Base` supplies defaults for the optional
interfaces so a module writes only the behaviour it has, and deliberately does
**not** satisfy `Module`, so the required four can never be forgotten. That is
asserted by `TestBaseDoesNotSatisfyModule`.

## The three-phase configuration contract

`Configurable` is not `Configure(cfg) error`. It is:

```
PrepareConfig  validate and stage; MUST NOT change live behaviour
CommitConfig   atomically switch to the staged configuration
RollbackConfig discard the staged configuration and release what prepare took
```

This is what makes "invalid configuration must not partially apply" a property
of the system rather than an aspiration. The supervisor prepares every affected
module first; a single rejection rolls back every module that already prepared
and the agent keeps running the previous revision untouched. A one-phase
`Configure` cannot offer this: by the time the fifth module rejects, four are
already running the new settings.

The residual weakness is honest and documented: a failure during **commit**
cannot be undone, because earlier modules have already switched. The supervisor
records that loudly with a remediation of "restart the agent", and modules are
contracted to do all fallible work in prepare.

## Runtime failure reporting

`Start` returns promptly and a module's real work runs on goroutines it owns, so
a failure in that work is invisible to the supervisor. `Host.ReportFailure` is
how a module says its collection loop died. Without it, a module whose loop
crashed would sit in `Running` forever, silently collecting nothing — the worst
failure mode an observability agent can have, because the absence of telemetry
reads identically to the absence of problems.

`ReportFailure` is non-blocking and coalescing: repeated reports before the
supervisor acts are dropped, since the outcome is the same and blocking inside a
callback would stall the reporting module.

## What a module can reach

A module receives `module.Host` and nothing else: its own ID, a scoped logger, the
Telemetry port, the Clock, the Identity port, a **scoped** diagnostic sink, an
`Authorize` function bound to its own capability, its configuration fragment, and
`ReportFailure`.

It has no reference to the supervisor and no way to name another module. This is
why module-to-module coupling is impossible rather than merely discouraged. The
diagnostic sink stamps the source itself, so a module cannot attribute a
diagnostic to another module — asserted by
`TestScopedSinkStampsSourceAndCannotBeForged`.

## Consequences

Module authors must implement four methods and opt into the rest. Reviewers can
see at a glance which capabilities a module genuinely has.

The supervisor must type-assert, which is slightly more code than calling a
method — paid once, in one place.

When the real Capability SDK becomes available, this contract must be reconciled
with it. If the SDK defines its own module interface, the right move is for
`module.Module` to become an adapter onto it rather than a competitor; the four
required methods were chosen to be a subset of any plausible lifecycle contract
precisely to keep that adaptation cheap.
