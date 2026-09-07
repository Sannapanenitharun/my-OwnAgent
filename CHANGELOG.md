# Changelog

All notable changes to the observability agent. Each stage is a phase gate: the
stage is not complete until the code is production quality, measured, and its
limitations are recorded.

## Unreleased - Ubuntu log coverage: depth, suffixes, and login accounting

Closing the gaps found by enumerating a live Ubuntu host rather than working
from a list of well-known log locations.

### Added

- **Login accounting (`logins` source).** `/var/log/btmp` records failed login
  attempts and nothing else on the system records them in a form meant to be
  counted -- 289 of them on a host whose SSH port answers the public internet.
  `/var/log/wtmp` carries the successful side. Both are flat arrays of 384-byte
  glibc `utmp` structs, decoded in `internal/modules/logs/utmp.go`. Failed
  logins are emitted at warning level, successes at info. Validated against
  `lastb` on real data: usernames, source hosts, terminals and timestamps match
  record for record.
- **Binary detection in the file tailer.** Every newly seen file is sniffed
  once; one NUL byte or more than 10% C0 control characters means it is not
  text and is never tailed. UTF-8 continuation bytes count as text, so accented
  and CJK logs are unaffected. This is the prerequisite for the widened paths
  below -- `wtmp`, `btmp`, `lastlog` and atop's archives sit in the same
  directories as the suffix-less text logs now being matched, and tailing one
  line-by-line would ship struct padding into the pipeline.

### Changed

- **Default log paths rebuilt for Ubuntu.** Two patterns were missing whole
  categories:
  - *Depth.* `/var/log/*/*.log` is exactly one directory deep, so
    `/var/log/amazon/ssm/amazon-ssm-agent.log` was invisible, as would be a
    Kubernetes node's `/var/log/pods/<pod>/<container>/0.log`. Added
    `/var/log/*/*/*.log`, `/var/log/containers/*.log` and
    `/var/log/pods/*/*/*.log`.
  - *Suffix.* Requiring `.log` hid the Apache naming convention
    (`/var/log/cups/access_log`) and files with no suffix at all
    (`/var/log/dmesg`). Added those by name rather than by a bare `/var/log/*`
    wildcard, which would sweep in every rotated archive.

### Not done, deliberately

- **atop, sysstat `sa*`, and `lastlog` stay unread.** They are binary
  re-encodings of process and host metrics the agent already collects directly,
  in a format that would cost a parser each. `lastlog` is a sparse table
  indexed by UID rather than a log, and `wtmp` carries the same information as
  events.
- **`utmp` timestamps are 32-bit.** `ut_tv.tv_sec` is a signed 32-bit integer
  even on 64-bit systems, so these records overflow in January 2038. The file
  says what it says; the decoder does not pretend otherwise.

## Unreleased - OTLP signal routing, log discovery, service hardening

Three items from the gap analysis against Datadog and Dynatrace collection
methods, in severity order.

### Fixed

- **Received OTLP metrics and logs were silently discarded.** The receiver
  served `/v1/metrics` and `/v1/logs`, answered 200, and incremented
  `otel.receiver.accepted`; the native exporter then dropped every non-trace
  payload in `IngestTraces` with no counter and no diagnostic. An application
  exporting to the agent saw a healthy pipeline at both ends while its
  telemetry went nowhere. Payloads are now decoded and routed per signal into
  the same envelopes host telemetry uses, so the intake and fleet view render
  them with no downstream change.
- **The span decoder could turn a metric into a span.** OTLP's three request
  types share field numbers all the way down, and `Metric.name` is field 1 of
  type bytes -- the slot `Span.trace_id` occupies. A metrics body therefore
  parsed cleanly into a span whose trace ID was the metric's name in hex, and
  the old "reject only if BOTH IDs are empty" gate admitted it. Both IDs are
  now required, and `encodeTraces` refuses a non-trace signal outright.

- **Decoded OTLP content was shipped unredacted.** Everything a module emits
  passes through the scrub wrapper; received OTLP does not, because it arrives
  as opaque bytes and rewriting protobuf in flight would corrupt it. That was
  harmless while the bytes stayed opaque, and stopped being harmless the
  moment this change began decoding them: an application logging
  `password=hunter2` over OTLP had it shipped off the host in the clear, where
  the same line read from a file was redacted. Decoded log bodies, span names
  and all attribute values are now scrubbed at the point of decode.
- **Every dropped OTLP payload was counted as a dropped trace.** The receive
  batch is shared across signals, so a metrics flood can crowd out traces;
  labelling those drops `traces` sent an operator hunting a tracing problem
  that did not exist. Drops now carry their own signal.

### Added

- **OTLP metric and log decoders** (`internal/platform/native/otlpmetrics.go`,
  `otlplogs.go`) -- protobuf and JSON, no third-party dependency. Gauges, sums
  (monotonic to counters, non-monotonic to gauges) and histograms reduced to
  count/sum/min/max; exponential histograms and summaries are counted as
  unsupported rather than approximated. Resource attributes ride on each point
  and record, so `service.name` survives.
- **`agent.export.otlp_decoded` / `otlp_undecoded` / `otlp_unsupported` /
  `otlp_unrouted`** -- the outcome of a decode run is now a number. An operator
  chasing missing telemetry can tell "the agent could not read it" from "the
  application never sent it".
- **Log discovery through `/proc/<pid>/fd`** (`logs` setting `discover`, off by
  default) -- finds log files by asking which ones processes hold open for
  writing, which establishes the file and its owning process in one step.
  Lines carry `process` and `pid` attributes. Candidate paths are checked
  against an allow-list of roots (`/var/log` by default) BEFORE anything opens
  them: the paths come from whatever processes have open, which is
  attacker-influenced input.

### Changed

- **Application metrics can be charted.** The fleet store granted a sample ring
  only to `host.*` and two container gauges, so a metric received over OTLP
  arrived, was stored, showed a current value, and could never be drawn --
  "request latency is climbing" was a fact the store held and could not show.
  `isChartable` becomes `chartClassOf`, splitting the answer three ways rather
  than widening the yes:
  - `chartCore` (`host.*`, the two container gauges) keeps its own reserved
    budget and charts from first sight, so a chatty service can never blank the
    overview. Two counters make that structural rather than a matter of tuning.
  - `chartExtra` (application metrics, plus the agent's own `httpcheck.*` and
    `agent.export.*`) draws on a separate `HistorySeriesExtra` budget, default
    256, and must report **twice** before earning a ring. That second condition
    is the cardinality guard: a label unique per request -- an order ID, a
    request ID -- makes every series a one-off, and first-come budgeting would
    let one burst take every slot until the staleness sweep.
  - `chartNone` keeps the two exclusions that had real reasons: `process.*` is
    keyed per executable, and the container network counters are cumulative
    totals that make a poor chart in any case.

  Retired series return their slot to the budget it came from. Worst case per
  host roughly doubles, from about 1 MB of rings to 2 MB at the defaults.
- **The metrics page draws application charts.** Fixing only the store would
  have changed nothing visible: the chart grid was four hand-written specs
  matching `host.*` by regex. Cards beyond those four are now built from
  whatever arrived with history, one per metric name, with the legend keyed on
  the label that actually distinguishes the lines.
- **`packaging/observability-agent.service` is hardened.** The unit previously
  set `User=root` directly beneath a comment saying not to run as root. Root
  stays -- reading another user's `/proc/<pid>/{io,fd,ns}` requires it -- and
  is now bounded: `CapabilityBoundingSet` cut to `CAP_DAC_READ_SEARCH`,
  `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`, plus `ProtectSystem=strict`,
  `NoNewPrivileges`, seccomp and address-family restrictions.
  `ProtectProc=default` and `ProcSubset=all` are pinned with a comment
  explaining that the usual hardening values for both would blind the
  collectors outright.

- **journald collected 0.08% of what the host logged.** The reader scanned
  newly appended bytes for the literal `MESSAGE=`. On teleport that took 30
  lines out of 39,485 journal entries in the same window, while reporting
  success on all 9,865 collection cycles -- the source looked healthy and was
  effectively off. Replaced with a parser for the journal's object arena
  (`internal/modules/logs/journalfile.go`): an ENTRY object holds offsets to
  the DATA objects that make up that entry, so reading an entry means
  following its items. Regular and compact layouts, tail-resumable, bounded
  against corrupt input. Records now carry `_PID`, `_COMM`, `_SYSTEMD_UNIT`
  and `CONTAINER_ID`, and journald's `PRIORITY` sets the level in place of
  guessing it from the message text. Compressed payloads (XZ/LZ4/ZSTD) are
  still skipped -- each would be a third-party dependency -- but they are
  counted rather than shipped empty.

  Validated against a real journal copied from the live host: `journalctl`
  reported 54 entries, the parser returned 54, messages byte-identical, with
  attribution the byte scan could never have produced.

### Known limitation

- ~~**Journald records still carry no process attribution.**~~ *Fixed above.*
  The original note read: The gap analysis
  estimated this at 1-2 days on the assumption that `_PID` and `_COMM` were
  already in the bytes being scanned. They are in the file, but journal DATA
  objects are deduplicated and shared across entries, so a byte scan cannot
  say which message a given `_COMM=` belongs to -- associating them requires
  parsing ENTRY objects and following their items array. Shipping a proximity
  heuristic would produce confident wrong attribution, which is worse than
  none. Log discovery above delivers the same outcome soundly for file-based
  logs.


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
