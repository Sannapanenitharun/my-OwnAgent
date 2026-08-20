# Changelog

All notable changes to the observability agent. Each stage is a phase gate: the
stage is not complete until the code is production quality, measured, and its
limitations are recorded.

## Unreleased — native exporter, OTLP, logs, traces, richer AWS identity

The agent can be installed on EC2 and ship telemetry either through its own
HTTPS JSON writer (Datadog-style) or through OTLP. Collection still happens on
the host; storage and query stay outside.

See [docs/AWS_AGENT.md](docs/AWS_AGENT.md), [ADR-0007](docs/adr/0007-native-exporter.md),
and [ADR-0006](docs/adr/0006-otlp-adapter.md).

### Added

- **`httpcheck` module** — probes configured HTTP targets; emits
  `httpcheck.up` / latency gauges.
- **`cmd/obsagent-intake`** — demo HTTP sink for `obsagent.v1` (`/v1/logs|metrics|traces`).
- **`packaging/build-linux.ps1`** — cross-build agent + intake for EC2 from Windows.
- **`internal/platform/native`** — first-party HTTPS JSON exporter. Gzip POST
  to `/v1/logs`, `/v1/metrics`, `/v1/traces` with schema `obsagent.v1`.
  `export.native.endpoint` / `OBSAGENT_EXPORT_ENDPOINT` enable it.
- **`internal/platform/otlp`** — OTLP/HTTP exporter (`/v1/metrics`, `/v1/logs`,
  `/v1/traces`). Wraps the in-process adapter so the local UI still works.
  `export.otlp.endpoint` / `OBSAGENT_OTLP_ENDPOINT` enable it. Empty endpoint
  keeps the previous in-memory-only behaviour.
- **`platform.Telemetry.EmitLog` / `IngestTraces`** — additive port methods for
  log bodies and application OTLP payloads.
- **`internal/imds`** — region, instance type, AMI id, account id (from the
  instance identity document), used as OTLP resource attributes. Unresolved
  fields are omitted; hostnames are never used as `host.id`.
- **discovery module** registered in the binary (was written, not started).
- **`internal/modules/logs`** — file tail (start-at-EOF), journald on Linux,
  Windows Event Log; inline redaction of AWS keys, bearer tokens, password
  assignments.
- **`internal/modules/otelengine`** — OTLP/HTTP receiver on `127.0.0.1:4318`.
- **`packaging/`** — systemd unit, `install.sh`, EC2 user-data example.

### Added (earlier in this unreleased window)

- **`internal/imds`** — EC2 instance id from IMDSv2 (v1 fallback).
- **`internal/localui`** — localhost UI for identity, module health, and gauges.

## Stage 3 — Process module

The second collector, and the first whose cost is not bounded by the hardware it
observes. See [ADR-0005](docs/adr/0005-process-module.md) and
[the readiness review](docs/review/process-module-readiness.md).

### Added

- **`internal/modules/process`** — process inventory, resource usage and
  lifecycle telemetry on Linux, Windows and macOS.
  - Metrics roll up by **executable**, never by PID. 10,000 processes across 40
    executables produce 258 series; the same executable count produces identical
    series at 100 and at 20,000 processes.
  - Identity is a process **instance** — `(boot, pid, start_stamp)` — so a
    recycled PID never inherits the previous process's counter baselines.
  - Lifecycle events (`process.started`, `.exited`, `.replaced`, `.churn`,
    `.top`) carry per-instance detail on the event path, bounded per cycle, with
    a churn summary that survives the budget.
  - Churn, permission denial and read failure are counted separately; only the
    third affects health.
  - Process names are sanitised: control characters replaced, length capped,
    distinct count capped. Process names are attacker-controlled.
  - One goroutine and one timer, measured as independent of process count.
- **`platform.EntityRef` / `platform.EntityResolver` / `platform.ResolveEntity`**
  — an **additive, optional** extension letting a collector resolve a child
  entity's natural key through the platform. Every existing `Identity` adapter
  keeps working unchanged; an adapter without a resolver produces an unresolved
  diagnostic rather than a locally invented ID.
- **Architecture rule: collectors may not read forbidden OS interfaces.**
  `/proc/PID/environ`, `mem`, `maps`, `smaps`, `ReadProcessMemory` and
  `NtQueryInformationProcess` are now enforced by test rather than by convention.
- Documentation: module README, ADR-0005, diagrams, runbook, readiness review.
- `make scale` and `make readers`; CI jobs for platform readers and process
  benchmarks.

### Changed

- `cmd/observability-agent` registers the process module and grants it
  `process:read`.
- `Makefile` version to `0.3.0-stage3`.

### Fixed

- **A pre-existing Stage 2 test race.** The host module's integration test waited
  for memory telemetry then immediately asserted on `host.info`, which the run
  loop collects later in the same cycle. Latent since Stage 2; surfaced once the
  integration package took longer to run.

### Measured

| | Stage 2 | Stage 3 |
|---|---|---|
| Binary | 3.05 MB | 3.24 MB |
| Working set (this machine, ~320 processes) | 7.52 MiB | 8.4 MiB |
| CPU, steady state | ~0.00 % | 0.156 % of one core |
| Goroutines added by the process module | — | **+1**, at 10 and at 20,000 processes |
| Full collection, 10,000 processes | — | 7.4 ms, 423 allocations |
| Full collection, 50,000 processes | — | 60 ms, 418 allocations |

### Known limitations

- The Linux and macOS readers have **never been executed** — compiled and
  parser-tested only. CI now runs them.
- The **race detector still has not run** (no C toolchain on the development
  machine). CI job is mandatory.
- No multi-hour soak.
- macOS provides 3 of 10 features: `kinfo_proc`'s `eproc` half has no layout
  stable enough to decode without cgo, so parent PID and owning UID are reported
  unsupported rather than guessed.
- Windows provides 7 of 10: no per-process run state (Windows schedules threads),
  and no command line (it would require reading process memory).
- `collect.command_line` is off by default and depends on the Stage 6 central
  scrubber, which does not exist yet.

---

## Stage 2 — Host module

The first production collector, and the reference pattern for every later one.
See [docs/HOST_MODULE.md](docs/HOST_MODULE.md).

### Added

- **`internal/modules/host`** — CPU, memory, disk, filesystem, network
  interfaces, OS, kernel, architecture, load, uptime and host identity on Linux,
  Windows and macOS.
  - Narrow reader interfaces, one per source: a source a platform cannot provide
    is *absent*, not empty.
  - Optional values (`U64`/`F64`) so "unknown" is never emitted as zero.
  - One goroutine with a computed next-due sleep, replacing seven tickers.
  - Deterministic bounded selection with drop accounting.
- **`internal/guard`** — panic recovery and deadline-with-settle, extracted from
  the supervisor so the Stage 1 lessons are encoded once.
- **`module.Throttleable`** — the adaptive-collection seam. See
  [ADR-0004](docs/adr/0004-adaptive-collection-seam.md).
- Architecture rule: **modules may not import each other.**

### Measured

Binary 3.05 MB, working set 7.52 MiB, +1 goroutine, full collection 8.5 µs / 55
allocations on a typical host.

### Notable findings

- A stock Windows 11 laptop reports **42 network interfaces**, of which 23 are
  NDIS filter-driver bindings. Excluded at the reader: a filter binding is not an
  interface, which is a fact about the API rather than a policy choice.
- A leak-shaped working-set trend turned out to be Windows heap-segment
  commitment plus a Go heap that had not yet reached its first GC threshold —
  established by four experiments including `gctrace`, which showed **zero GC
  cycles in 150 s**. No `FreeOSMemory` or GOGC override was added.

---

## Stage 1 — Agent shell and supervisor

### Added

- Supervisor: dependency ordering, restart with jittered backoff, crash-loop
  quarantine, health aggregation, failure isolation, graceful shutdown.
- The single module contract and its lifecycle state machine.
- Versioned configuration with a prepare/commit/rollback reload transaction.
- Structured diagnostics with stable operator-facing codes.
- Platform ports and in-process reference adapters. See
  [ADR-0001](docs/adr/0001-ports-and-adapters.md).
- Executable architecture rules in `internal/architecture`.
- Zero third-party dependencies, enforced by test.

### Notable findings

- **A deadline heisenbug.** The worker goroutine cancelled its own deadline
  context after delivering a result, making both arms of the waiting select ready
  at once — so successful calls were reported as timeouts roughly half the time
  under load. Invisible to unit tests; found by benchmarking under contention.
- **A leaked goroutine per tick.** Releasing the caller's in-flight slot at the
  deadline let the next tick dispatch a second concurrent call into code still
  executing the first.

Both are encoded, with their reasoning, in `internal/guard`.
