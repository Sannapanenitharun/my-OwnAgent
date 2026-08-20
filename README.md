# observability-agent

A single enterprise observability agent: one installation, one binary, one
service, one identity, one configuration model, one security model, one update
mechanism, one telemetry pipeline — and many independently managed modules
behind it.

The agent **collects and processes** telemetry. The platform stores, queries,
correlates and analyses it. Storage and query live outside the agent.

On AWS EC2, if `OBSAGENT_HOST_ID` is unset, the agent uses the instance id from
IMDS (`i-…`) as host identity. That is AWS's identifier, not one the agent
invents. Off EC2, host identity stays unresolved and collection still runs.
See [docs/AWS_AGENT.md](docs/AWS_AGENT.md).

> **Stage 3 of 15, plus an OTLP export path.** The agent shell, the supervisor,
> host/process/discovery/logs collectors, an OTLP/HTTP receiver (`otel-engine`),
> and an OTLP/HTTP exporter so telemetry can leave the host.
> See [docs/READINESS.md](docs/READINESS.md) and
> [docs/review/process-module-readiness.md](docs/review/process-module-readiness.md)
> for measured results, defects found, and known limitations.

## Build and run

```bash
make build
./build/observability-agent --version
./build/observability-agent --check          # validate config + wiring, then exit
./build/observability-agent --config agent.json
# local UI: http://127.0.0.1:8181
```

| Flag | Purpose |
|---|---|
| `--config` | configuration file; empty uses built-in defaults |
| `--check` | validate configuration and module wiring, then exit |
| `--ui-listen` | local status UI; default `127.0.0.1:8181`; `off` disables |
| `--log-level` | `debug` / `info` / `warn` / `error` |
| `--log-format` | `text` / `json` |
| `--version` | build identity |

## Development

```bash
make check          # fmt, vet, test, cross-compile — the pre-commit gate
make race           # race detector (needs cgo; run on Linux or in CI)
make stress         # full suite ×10, for order- and timing-dependent failures
make bench          # benchmarks
make scale          # process collection cost at 100 / 1K / 10K / 50K
make readers        # the REAL platform readers against this machine
make measure        # steady-state footprint
make release        # per-platform binaries + SHA256SUMS
```

## What is built

| Component | Status |
|---|---|
| Supervisor: dependency ordering, restart, crash-loop protection, health aggregation, failure isolation, graceful shutdown | built |
| Module contract and lifecycle state machine | built |
| Versioned configuration with prepare/commit/rollback reload | built |
| Diagnostics with stable operator-facing codes | built |
| Platform ports + in-process reference adapters | built |
| Agent self-observability | built |
| **local status UI** (this host: identity, health, live metrics) | **built** |
| **process module** (inventory, CPU, memory, I/O, threads, lifecycle) | **built** |
| **discovery module** (services, containers, endpoints, cloud instance) | **built** |
| **logs module** (files, journald, Windows Event Log; redaction) | **built** |
| **otel-engine** (OTLP/HTTP receiver on 127.0.0.1:4318) | **built** |
| **httpcheck module** (HTTP up/latency probes) | **built** |
| **obsagent-intake** (demo sink for native JSON) | **built** |
| **OTLP/HTTP exporter** (metrics, logs, traces → existing backends) | **built** |
| **native HTTPS JSON exporter** (Datadog-style first-party writer) | **built** |
| adaptive-collection seam (`Throttleable`) | built; governor in Stage 13 |
| network · ebpf · security · profiler | Stages 8–11 |
| secret-scrubber · updater | Stages 6, 12 |
| resource governor | Stage 13 |
| packaging and installers | Stage 15 |

## Design commitments

These are the properties the code is built to hold, each backed by tests:

- **A module failure never crashes the agent.** Panics are recovered per module;
  failures are isolated, restarted with jittered backoff, and quarantined if they
  crash-loop.
- **Unsupported is not failure.** A module that cannot run in an environment says
  so and degrades health. One binary ships everywhere; nothing is ever faked.
- **Identity is never invented.** An unresolvable identifier produces a
  diagnostic, never a fabricated ID that would fork the platform entity graph.
- **Configuration never partially applies.** Reload is a prepare/commit/rollback
  transaction; a rejection leaves the previous revision running untouched.
- **Nothing is unbounded.** No unbounded queues, no goroutine per module per
  tick, bounded diagnostics retention, and a hard cardinality bound on the
  agent's own metrics.
- **Fail closed.** Capability admission and permission checks deny on any error,
  and a module that is not permitted never has its code run.
- **Identity is an instance, not a handle.** PIDs are reused within minutes on a
  busy host, so every piece of per-process state is keyed by
  `(boot, pid, start_stamp)`. A recycled PID never inherits the previous
  process's counter baselines.
- **Cardinality is bounded by what is bounded.** Process metrics roll up by
  executable, never by PID: ten thousand processes across forty programs produce
  258 series, not ten thousand. Per-instance detail lives on the event path,
  where a record has a lifetime.
- **Empty supply chain.** Zero third-party dependencies, enforced by test — the
  collectors reach `/proc`, Win32 and `sysctl` through the standard library
  alone.
- **Modules cannot see each other.** Enforced by test, not convention.
- **Boundaries are executable.** Import rules live in `internal/architecture` and
  fail the build when crossed, under all six target platforms.

## Measured

The agent with the host module enabled, collecting real telemetry from the
machine it runs on:

| | Stage 1 (no modules) | Stage 2 (host) | Stage 3 (host + process) |
|---|---|---|---|
| Binary size | 2.87 MB | 3.05 MB | **3.24 MB** |
| Working set | 6.39 MiB | 7.52 MiB | **8.4 MiB** |
| CPU, steady state | ~0.00 % | ~0.00 % | **0.16 % of one core** |
| Goroutines added per module | — | +1 | **+1** |
| Full host collection | — | 8.5 µs, 55 allocs | unchanged |
| Full process collection, 10,000 processes | — | — | **7.4 ms, 423 allocs** |
| Full process collection, 50,000 processes | — | — | **60 ms, 418 allocs** |

Allocation count is flat in process count: 418 at fifty thousand processes
against 475 at one thousand.

Full context — including what these numbers do and do not prove — in
[docs/READINESS.md](docs/READINESS.md).

## Documentation

| | |
|---|---|
| [docs/AWS_AGENT.md](docs/AWS_AGENT.md) | EC2 IMDS identity, native/OTLP export, install |
| [docs/ROADMAP_DYNATRACE.md](docs/ROADMAP_DYNATRACE.md) | Dynatrace-style layers, stages, repo deep-dives |
| [docs/INTAKE.md](docs/INTAKE.md) | demo sink for obsagent.v1 (`obsagent-intake`) |
| [docs/HTTPCHECK.md](docs/HTTPCHECK.md) | HTTP endpoint check collector |
| [docs/LOGS_MODULE.md](docs/LOGS_MODULE.md) | logs collector |
| [docs/OTEL_ENGINE.md](docs/OTEL_ENGINE.md) | OTLP/HTTP receiver |
| [ADR-0007](docs/adr/0007-native-exporter.md) | first-party HTTPS JSON exporter |
| [ADR-0006](docs/adr/0006-otlp-adapter.md) | OTLP adapter as Telemetry Plane stand-in |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | diagnostic codes, procedures, configuration reference |
| [docs/HOST_MODULE.md](docs/HOST_MODULE.md) | host module: platform matrix, metrics, cardinality, tuning |
| [internal/modules/process/README.md](internal/modules/process/README.md) | process module: platform matrix, metrics, cardinality, tuning |
| [docs/runbooks/process-module.md](docs/runbooks/process-module.md) | process module: incident procedures |
| [docs/diagrams/process-module.md](docs/diagrams/process-module.md) | process module: collection, identity, churn, back-pressure |
| [docs/READINESS.md](docs/READINESS.md) | Stage 1 and 2 assessment, measurements, limitations, debt |
| [docs/review/process-module-readiness.md](docs/review/process-module-readiness.md) | Stage 3 assessment: what is proven and what is not |
| [CHANGELOG.md](CHANGELOG.md) | per-stage history |
| [ADR-0001](docs/adr/0001-ports-and-adapters.md) | why the agent depends on platform ports |
| [ADR-0002](docs/adr/0002-supervisor-lifecycle.md) | why a supervisor exists alongside the Capability Runtime |
| [ADR-0003](docs/adr/0003-module-contract.md) | why the module interface is small |
| [ADR-0004](docs/adr/0004-adaptive-collection-seam.md) | the adaptive-collection seam |
| [ADR-0005](docs/adr/0005-process-module.md) | process identity, cardinality, and the additive entity port |
