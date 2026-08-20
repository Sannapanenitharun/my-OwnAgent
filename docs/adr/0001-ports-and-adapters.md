# ADR-0001: The agent depends on the platform through ports, not directly

- **Status:** Accepted
- **Date:** 2026-08-11
- **Stage:** 1 (agent shell + supervisor)
- **Supersedes:** none

## Context

The observability agent is specified as a host/execution product built on an
existing, frozen enterprise platform: Capability Runtime, Capability SDK,
Discovery Runtime, Digital Twin, Telemetry Plane, Data Plane, Transport,
Storage, Query and IAM. The governing constraint is that the agent must **reuse**
that platform and must not implement a second runtime, telemetry pipeline,
transport, authorization system or entity identity system.

At implementation time, **those platform contracts were not available to build
against**. No source, headers, module path or interface definitions could be
located. This was verified before any code was written.

That leaves three options:

1. **Wait.** Deliver nothing until the contracts are available.
2. **Guess.** Write the supervisor and modules directly against invented
   interfaces named after the real ones, and hope they match.
3. **Depend on ports.** Define a narrow interface for each platform capability
   the agent actually needs, own those interfaces inside the agent, and satisfy
   them with an adapter.

Option 2 is the dangerous one, because it looks like option 3 while producing
the opposite outcome: guessed interfaces spread through every module, and every
one of them has to change when reality arrives.

## Decision

The agent depends on the platform exclusively through the ports in
`internal/platform`:

| Port | Platform capability | Used for |
|---|---|---|
| `CapabilityRuntime` | Capability Runtime + IAM | capability admission, permission checks |
| `Telemetry` | Telemetry Plane | all agent and module telemetry |
| `Identity` | IAM / Identity / Tenancy | agent, tenant and host identifiers |
| `Clock` | — | time, so collection intervals are testable |

Three rules make this real rather than decorative:

1. **The ports are narrow and derived from need.** Each method exists because
   Stage 1 calls it. There is no speculative surface, because speculative
   surface is exactly what turns out to be wrong.
2. **Only the entrypoint chooses an adapter.** `cmd/observability-agent`
   constructs the concrete adapters; nothing else imports an adapter package.
   This is asserted by `TestOnlyTheEntrypointChoosesAdapters`.
3. **The ports are marked PROVISIONAL in their package documentation.** They are
   the agent's statement of what it needs from the platform, not a claim about
   what the platform's contracts are.

Stage 1 ships `internal/platform/inproc`, an in-process reference adapter set.
It terminates telemetry in memory, admits capabilities against an explicit grant
set, and returns `ErrUnresolved` for every identifier it was not given. It
exports nothing and is not a second telemetry pipeline.

## Consequences

**What this buys.** When the real platform contracts arrive, the work is: write
one adapter package, change `buildPorts()` in `main.go`, and reconcile any port
whose shape was wrong. No module, the supervisor, the config subsystem or the
agent shell has to move. The import-boundary tests fail the build if that
property is ever broken.

**What it costs.** There is one extra indirection between the agent and the
platform, and the port definitions are a small amount of code that will
ultimately be a translation layer rather than a contract. That is a real cost
and it is worth paying: the alternative is that the shape of an unavailable
contract is baked into eleven modules.

**Where the risk actually sits.** The risk is not that the ports are wrong — a
wrong port is a localised fix. The risk is *semantic*: if the real Telemetry
Plane has, say, a push-based backpressure signal that `Telemetry` has no way to
express, the adapter cannot invent one, and the otel-engine's design (Stage 5)
would be affected. This is recorded in `docs/READINESS.md` as the top open risk
for Stage 5, and it is the reason the ports should be reconciled against the
real contracts **before** Stage 5 rather than after.

**Reference adapters must never ship as the real thing.** `inproc` exports no
telemetry. An agent running on it collects into a void. Stage 15 packaging must
not produce a binary wired to `inproc`, and the release checklist says so.

## Alternatives considered

**Vendor a copy of the platform.** Rejected: there was nothing to vendor.

**Generate ports from the platform's protobuf/OpenAPI definitions.** Preferred
if such definitions exist — this decision should be revisited the moment they
are found, because generated ports cannot drift.

**Skip the abstraction and call the platform directly once available.** This is
the end state the constraint implies, and it remains available: the ports can be
deleted and their call sites pointed at the real contracts if the real contracts
turn out to be a good direct fit. Ports do not preclude that; they make the
agent buildable and testable until the choice can be made with information.
