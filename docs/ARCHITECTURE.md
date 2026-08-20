# Architecture

This describes what exists after **Stage 3**. Where a component is planned but
not built, it says so explicitly.

## Position in the product

The observability agent is a **host/execution product** on top of the existing
enterprise platform. It collects and processes telemetry. The platform stores,
queries, correlates and analyses it. Storage and query live outside the agent and
always will.

```
                         ┌──────────────────────────────┐
   customer host         │  observability-agent         │
                         │  one binary, one service     │
                         └──────────────┬───────────────┘
                                        │  platform ports (ADR-0001)
                                        ▼
   ┌────────────────────────────────────────────────────────────────┐
   │ Capability Runtime · Telemetry Plane · Data Plane · Transport   │
   │ Discovery Runtime · Digital Twin · IAM · Storage · Query        │
   └────────────────────────────────────────────────────────────────┘
```

## Package structure

```
cmd/observability-agent/     entrypoint: flags, adapter selection, hand-off
internal/
  agent/                     shell: wiring, signals, run loop
  supervisor/                root lifecycle controller
  module/                    the one module contract + lifecycle state machine
  modules/
    host/                    host collector (Stage 2) — the reference module
    process/                 process collector (Stage 3) — the first at scale
    discovery/               entity and relationship discovery (Stage 4)
    logs/                    log collector (files, journald, event log)
    httpcheck/               HTTP endpoint up/latency collector
    otelengine/              OTLP/HTTP receiver for application traces
  config/                    versioned config, validation, transaction model
  health/                    health model and aggregation rules
  diagnostics/               structured diagnostics, bounded retention
  guard/                     panic recovery + deadline-with-settle, shared
  platform/                  PORTS to the enterprise platform (ADR-0001)
    clockfake/               deterministic clock, tests only
    inproc/                  in-process reference adapters
    native/                  first-party HTTPS JSON exporter (ADR-0007)
    otlp/                    optional OTLP/HTTP exporter (ADR-0006)
  architecture/              executable architecture rules (tests only)
  integration/               cross-component tests (tests only)
cmd/obsagent-intake/          demo sink for native obsagent.v1 payloads
```

### Dependency direction

Dependencies point inward and never back out:

```
cmd ──▶ agent ──▶ supervisor ──▶ module ──▶ config
                       │            │        health
                       │            └──────▶ diagnostics
                       └───────────────────▶ platform (ports)
```

This is asserted, not merely documented, by `internal/architecture`:

- `platform` imports nothing else from the agent.
- `config`, `health`, `diagnostics` cannot reach `module` or `supervisor`.
- `module` cannot reach `supervisor` — so no module can reach another module.
- `supervisor` cannot reach `agent`.
- `guard` cannot reach any of them; it is a leaf shared by the supervisor and
  by every collector.
- **A module cannot import another module.** Two collectors that share a helper
  today share a release cadence tomorrow. The process module therefore carries
  its own copy of the byte-scanning helpers and the optional-value type; fifty
  lines of duplication cost far less than coupling two independently released
  units.
- **No collector reads a forbidden OS interface.** `/proc/PID/environ`, `mem`,
  `maps`, `smaps`, `ReadProcessMemory` and `NtQueryInformationProcess` are
  asserted against, not merely documented — a reviewer adding one must also
  delete a line from the rule table.
- Only `cmd` selects a platform adapter.
- No production package imports a test double.
- The module has **zero third-party dependencies**, checked against imports and
  against `go.mod`.

These run under all six target platforms, so a build-tagged file that crosses a
boundary on Linux is caught while developing on Windows.

## Target module set

Built: **host**, **process**, **discovery**, **logs**, **otel-engine**.

Planned, each behind the same `module.Module` contract:

| Category | Modules | Stage |
|---|---|---|
| Collector | **host (built)**, **process (built)**, **logs (built)**, network, ebpf, security, profiler | 2, 3, 7–11 |
| Discovery | **discovery (built)** | 4 |
| Processing | **otel-engine (built)**, secret-scrubber | 5, 6 |
| Lifecycle | updater | 12 |

Agent infrastructure — config, identity, diagnostics, resource governor,
platform adapters — are not modules and are not telemetry collectors.

## Lifecycle

### Startup

1. Load and validate configuration; assign a revision.
2. Resolve identity through the Identity port. Unresolved identity is recorded
   as a diagnostic and does **not** block startup; no identifier is invented.
3. Register modules. The complete graph must be known before anything runs, so
   start order never depends on registration order.
4. Resolve the dependency graph over **enabled** modules. A cycle, a
   self-dependency, or a dependency on a disabled module aborts startup.
5. Start modules in dependency order. For each: admit with the Capability
   Runtime (permission check strictly precedes any module code), then `Start`
   under a deadline.
6. Launch the single control loop.

### Steady state

One goroutine drives everything:

```
loop:
  process restart deadlines that have arrived
  arm a timer for the next one (re-armed only when it changes)
  select:
    context cancelled  -> exit
    health tick        -> collect self metrics, probe running modules
    restart timer      -> loop
    wake nudge         -> loop
    runtime failure    -> stop the module and its dependents, schedule restart
```

Module calls never run on this goroutine and never hold the supervisor lock.

### Failure handling

| Condition | Result |
|---|---|
| `Start` returns an error | cleanup `Stop`, lease released, restart with backoff |
| `Start` returns `ErrUnsupported` | terminal `unsupported`, degrades health, never retried |
| Capability admission denied | `Start` never called, restart with backoff |
| Panic in `Start`/`Stop`/`Health` | recovered, counted, isolated to that module |
| `ReportFailure` from a running module | dependents stopped, module stopped, restart scheduled |
| Restart budget exhausted in window | quarantined `crash_looping` until reload or agent restart |
| Dependency unavailable | deferred, **does not** consume the crash-loop budget |
| Health probe overruns | `unknown`, not `unhealthy`; slot held until the call returns |

### Shutdown

Control loop stopped first (so nothing schedules a restart mid-teardown), then
in-flight operations drained, then modules stopped in **reverse** dependency
order. Bounded twice: per module and overall.

## Health model

`healthy` · `degraded` · `unhealthy` · `unknown`, with two rules that matter:

- A **required** module's status propagates unchanged.
- An **optional** module's status is capped at `degraded` — it can never make the
  agent unhealthy. Without this, every expected capability gap (eBPF on Windows,
  profiling on a locked-down host) pages an operator.
- **Disabled** modules are excluded entirely.
- No modules at all is `unknown`, never `healthy`.

## Configuration model

Versioned, JSON, layered over built-in defaults, with unknown fields **rejected**
so a typo cannot silently change behaviour. A fixed allowlist of `OBSAGENT_*`
environment variables may override; the environment can toggle a declared module
but can never conjure one the operator did not declare, and credentials are never
accepted there.

Reload is a transaction (ADR-0003): validate → re-resolve graph → prepare all →
commit all → reconcile the module set. A rejection at any point before commit
leaves the agent running the previous revision exactly as it was.

## Self-observability

The agent monitors itself through the same Telemetry Plane port every module
uses. It does not build a parallel monitoring system for itself.

The **only** attribute the agent core attaches to telemetry is `module`, whose
value set is the fixed list of registered module IDs. No PID, request ID, path,
command line, timestamp or error string is ever a metric label — a rule the
process module extends to its own output, where per-instance detail is routed to
the event path instead. The in-process telemetry
adapter additionally enforces a hard per-instrument series bound and counts what
it drops, so the agent cannot become the source of the cardinality incident it
exists to detect.

Instrument names are listed in `internal/supervisor/metrics.go` and are part of
the operator-facing contract.

## Security posture (Stage 1)

- **Fail closed.** Capability admission and permission checks deny on any error,
  including an expired context.
- **Permission before code.** A module that is not admitted never runs.
- **No invented identity.** Unresolved identifiers produce a diagnostic, never a
  fabricated ID that would fork the platform entity graph.
- **Scoped diagnostics.** A module cannot attribute a diagnostic to another.
- **No secrets in the model.** Configuration has no credential fields;
  diagnostics carry bounded structured attributes and no collected content.
- **Empty supply chain.** Zero third-party dependencies, enforced by test.

Neither collector adds a privilege requirement. Every Linux path they read is
world-readable, and every Windows call is a query API available to a normal user;
the process module specifically requests `PROCESS_QUERY_LIMITED_INFORMATION`,
because `PROCESS_QUERY_INFORMATION` would additionally permit reading process
memory. Where a source *would* need elevation — block-device I/O counters on
Windows — it is reported unsupported rather than making the agent demand
Administrator.

**Entity identity for child entities** (Stage 3). A collector observing something
that is not the host — a process instance — states its natural key and asks the
platform what entity it denotes, through the optional `platform.EntityResolver`.
It never derives an identifier itself. See
[ADR-0005](adr/0005-process-module.md).

Not yet built: the secret scrubber (Stage 6), signed updates (Stage 12), tamper
detection, and audit. See `docs/READINESS.md`.
