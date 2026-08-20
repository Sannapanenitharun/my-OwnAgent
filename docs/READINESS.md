# Readiness assessment

> **Stage 3 note.** This document covers Stages 1 and 2. The process module's
> assessment is [review/process-module-readiness.md](review/process-module-readiness.md).
> The two outstanding gates recorded below — the race detector and a multi-hour
> soak — remain open, and Stage 3 adds a third: neither the Linux nor the macOS
> reader has ever been executed.

Current stage: **2 — host module**. Stage 1 (agent shell + supervisor) is
recorded at the end.

---

# Stage 2 — host module

**Date:** 2026-08-11
**Verdict:** feature-complete and production-quality in code, **not yet cleared
for production deployment.** Two gates are outstanding: the race detector (no C
toolchain on this machine) and a multi-hour soak to confirm the predicted memory
ceiling on Windows. Both are named, both are reproducible, neither is hand-waved.

Stage 2 delivers the first real collector and, more importantly, the reusable
pattern every later module follows. That pattern is documented in
[HOST_MODULE.md](HOST_MODULE.md).

## Phase gate status

| Gate | Status | Evidence |
|---|---|---|
| Architecture review | Done | ADR-0004; module/reader split |
| Implementation | Done | no TODOs, no stubs, no fabricated values |
| Unit tests | Done | 284 tests and benchmarks across the repository |
| OS abstraction tests | Done | parsers tested on every platform via fixtures |
| Reader tests | Done | real-platform plausibility tests + Windows validated on hardware |
| Unsupported tests | Done | absent sources, all-unsupported start path |
| Configuration tests | Done | strict keys, bounds, prepare/commit/rollback |
| Health tests | Done | healthy / degraded / unavailable |
| Failure isolation tests | Done | panicking reader, failing reader, stalled reader |
| Concurrency tests | Done | logical; **`-race` not run** (see gaps) |
| Resource tests | Done | goroutine and retained-heap ceilings asserted |
| Cardinality tests | Done | caps, deterministic selection, drop accounting |
| Entity binding tests | Done | bound, and unresolved-without-invention |
| Telemetry contract tests | Done | attribute allowlist, unknown-never-zero, delta semantics |
| Integration tests | Done | `internal/integration`, real supervisor + real module |
| Benchmarks | Done | numbers below |
| Cross-platform builds | Done | six targets + one unsupported OS |
| Backward compatibility | Done | every Stage 1 test green, unchanged |
| Documentation | Done | HOST_MODULE.md, RUNBOOK additions, ADR-0004 |

## Measured results

Windows 11, AMD Ryzen 5 5500U (6c/12t), 16 GiB, Go 1.26.5. Reproduce with
`make bench` and `make measure`.

### Agent process, host module enabled, real collection

| Metric | Stage 1 (no modules) | Stage 2 (host enabled) |
|---|---|---|
| Binary size (stripped) | 2.87 MB | **3.05 MB** (+180 KB) |
| Working set at t=5s | 6.39 MiB | **7.52 MiB** |
| Working set at t=485s | 6.39 MiB (flat) | 9.17 MiB (rising; see investigation) |
| Private bytes | 12.38 MiB | 13.13 MiB |
| OS threads | 7 | 5 |
| CPU over 480 s steady state | ~0 | **172 ms = 0.036 %** |
| Goroutines added by the module | — | **+1** |

The module costs roughly **1.1 MiB of working set, +1 goroutine, and 0.036 % of
one core** while collecting seven sources on a real machine. Target was <10 MB
RAM for host-only capability and <0.2 % CPU; both are met with wide margin.

### Module internals

| Measurement | Result |
|---|---|
| Goroutines after 1,403 collections | **+1** |
| Retained heap after 200 cycles | 105.9 KiB (does not scale with cycles) |
| `Start` return time | < 1 ms |
| Counter baselines after 50 cycles of total interface churn | bounded, reaped |

### Benchmarks (`-benchtime=300x`, ns/op · B/op · allocs/op)

Full collection — emit path for all seven sources:

| Shape | ns/op | B/op | allocs/op |
|---|---|---|---|
| typical host (3 mounts, 4 NICs, 8 cores) | 8,493 | 2,867 | 55 |
| large host (64 mounts, 32 NICs, 64 cores) | 93,045 | 32,507 | 349 |
| container host (500 mounts, 200 NICs, 96 cores) | 648,150 | 238,156 | 1,773 |
| many cores (256) | 8,067 | 3,251 | 55 |

Real OS readers on this machine:

| Reader | ns/op | B/op | allocs/op |
|---|---|---|---|
| memory | 753 | 72 | 2 |
| cpu | 4,462 | 984 | 7 |
| os | 13,677 | 470 | 6 |
| filesystem | 99,008 | 4,224 | 27 |
| **network (`GetIfTable2`)** | **1,155,337** | 7,072 | 23 |

Linux parsers (fixture-based, run on every platform):

| Parser | ns/op | B/op | allocs/op |
|---|---|---|---|
| meminfo | 882 | 144 | 2 |
| `/proc/stat` | 2,147 | 720 | 4 |
| `/proc/stat`, 128 cores | 14,137 | 720 | 4 |
| `/proc/net/dev` | 2,659 | 1,856 | 10 |
| `/proc/mounts` | 3,082 | 2,296 | 61 |

**Reading these honestly.** A typical host's full collection costs 8.5 µs every
10 s — approximately 0.0001 % of a core. The dominant real cost on Windows is
`GetIfTable2` at 1.16 ms, which at the default 10 s interval is 0.012 % of a
core. `/proc/stat` parsing is allocation-flat as core count rises (4 allocs at
both 4 and 128 cores), which is the property that matters for large hosts.

### Cross-platform

Builds clean for linux/amd64, linux/arm64, windows/amd64, windows/arm64,
darwin/amd64, darwin/arm64, **and** an unsupported OS (freebsd/amd64) where every
source correctly reports unsupported. `go vet` clean under linux and darwin
cross-compilation as well as the host platform.

| Platform | Sources | Health | Verification |
|---|---|---|---|
| Linux | 7 / 7 | healthy | compiled; parsers fixture-tested; **not executed** |
| Windows | 5 / 7 | degraded (expected) | **executed and validated on real hardware** |
| macOS | 4 / 7 | degraded (expected) | **compiled only; not executed** |

## Findings from real hardware

Running the Windows reader against a real machine produced two findings that no
amount of design review would have surfaced:

1. **Windows reports 42 network interfaces on a stock laptop, 23 of which are
   NDIS lightweight filter bindings** (WFP, QoS Packet Scheduler, virtual switch
   extensions) with near-zero counters. Left alone this is a 2× cardinality
   inflation on every Windows host in a fleet. `MIB_IF_ROW2` exposes a
   `FilterInterface` bit, so these are excluded in the reader — a filter binding
   is not a network interface, which makes this a fact about the API rather than
   a policy choice. 42 → 19, then 14 after default filtering.

2. **`MIB_IF_ROW2` layout was correct** — verified as 1,352 bytes against the
   documented 64-bit size, with physical/logical core counts (6/12) matching the
   actual CPU. A struct-layout error here produces plausible-looking garbage
   rather than an error, which is why the reader tests assert plausibility
   bounds rather than merely "no error".

## The Windows working-set investigation

Worth recording in full, because the first measurement looked like a memory leak
and the temptation to either ignore it or "fix" it blindly was real.

**Observation.** With the host module enabled, the agent's working set grew from
7.52 MiB to 9.17 MiB over 8 minutes — about 3.4 KiB/s, which extrapolates to
roughly 290 MB/day. That is leak-shaped.

**Four experiments, in order:**

1. **A/B control.** The same binary, same duration, host module *disabled*:
   working set reached 7,144 KiB at t=65 s and then stayed there, byte-for-byte
   flat for the remaining 7 minutes. So the growth is attributable to the
   module, not to the runtime or the supervisor.

2. **Per-reader attribution.** 3,000 iterations of each reader, measuring
   process working set: `network` +1,117 B/call, `filesystem` +489 B/call,
   `os` +257 B/call — and `cpu` and `memory` *negative*. Negative growth is a
   strong hint: this is allocator behaviour, not accumulation.

3. **Plateau test.** Six consecutive batches of 2,000 `ReadInterfaces` calls:
   +2,513 B/call, then +211, +236, +68, +25, +178 — decaying by two orders of
   magnitude, and non-monotonic (the working set *fell* between two batches). A
   leak does not decay and does not go backwards. Note also the scale: a genuine
   failure to release the `MIB_IF_TABLE2` would leak ~57 KB per call, which over
   3,000 calls would be 171 MB, not 3.35 MB.

4. **GC trace.** `GODEBUG=gctrace=1` over 150 seconds: **zero GC cycles.** The
   agent allocates so little that it never reaches Go's 4 MiB minimum heap
   threshold, so the Go heap simply grows untouched by collection. Re-running
   with `GOGC=20` changed nothing, which is consistent — `GOGC` has no effect
   below the minimum heap size.

**Conclusion.** Two benign mechanisms, neither a leak:

- The Windows process heap commits segments to serve `GetIfTable2`'s ~57 KB
  allocation six times a minute. `FreeMibTable` returns the memory, but the heap
  manager retains the committed segments and the working set counts them until
  the OS trims. Experiment 3 shows this reaching a ceiling.
- The Go heap grows toward its first collection, which at this allocation rate
  is hours away.

**Predicted ceiling** by extrapolating experiment 3: roughly 12.5 MiB working
set — inside the <10 MB *module* budget once the ~7 MiB agent baseline is
subtracted, and far inside the agent-level target.

**What was deliberately NOT done:** no `debug.FreeOSMemory` call, no forced GC
timer, no `GOGC` override baked into the binary. Each would trade real CPU for a
number that is already going to plateau on its own, and would be tuning against
a measurement rather than a problem. The honest action is the soak test.

## Defects found and fixed during Stage 2

1. **Entity binding was resolved but never applied.** `resolveEntity` stored the
   host entity ID on the module but never passed it to the emitter, so every
   observation was emitted unbound while health reported identity as resolved —
   the worst combination, because the dashboard would look fine. Caught by the
   entity-binding test; fixed by propagating to the emitter.

2. **Three standard-library API assumptions were wrong**, caught by
   cross-compilation before any test ran: `syscall.ST_RDONLY` does not exist on
   Linux (it is a statvfs constant, not the mount flag), `syscall.SysctlUint64`
   does not exist on Darwin, and `syscall.NewLazySystemDLL` is in
   `golang.org/x/sys`, not the standard library. The last one mattered: it meant
   the DLL-planting hardening had to be implemented explicitly rather than
   inherited, which is now done by resolving non-KnownDLLs by absolute path from
   the system directory.

3. **`go vet` flagged a `uintptr`→`unsafe.Pointer` round trip** in the Windows
   interface table walk. Fixed by declaring `MIB_IF_TABLE2` as a real struct so
   the layout lives in the type rather than in pointer arithmetic.

## Backward compatibility

Every Stage 1 test passes unchanged. The supervisor, module contract, config
contract, health contract and platform ports are semantically unmodified.

Two changes were made to shared code, both deliberate and both reviewed:

1. **`internal/guard` extracted.** The supervisor's panic-recovery and
   deadline-with-settle helpers moved into a package the host module also uses.
   The supervisor's own functions are now thin wrappers with identical names and
   semantics, so no Stage 1 test changed. The alternative was duplicating the
   agent's most safety-critical concurrency code into every collector.

2. **`module.Throttleable` added** — a new *optional* interface. Additive: no
   existing interface changed, no existing implementer broke. Rationale in
   ADR-0004.

Two new architecture rules were added and pass: `internal/guard` may not import
agent code, and **modules may not import each other**.

## Known limitations

1. **`-race` has not been run.** Unchanged from Stage 1: the race detector needs
   cgo and this machine has no C toolchain. The host module adds a second
   concurrent component, so this gate matters more now than it did. `make race`
   and the CI job exist. **This is the top gap.**

2. **Working-set growth on Windows: diagnosed, benign, not yet observed to
   plateau in-process.** See "The Windows working-set investigation" below. The
   evidence says it is Windows heap-segment commitment from `GetIfTable2`, which
   plateaus, and not a leak — but the plateau has been demonstrated in a tight
   loop, not in a long-running agent. **A multi-hour soak is required before
   production** to confirm the predicted ~12.5 MiB ceiling.

3. **macOS is compiled, not executed.** Four of seven sources, verified only by
   the type checker. The `sysctl` structure decoding (`vm.loadavg`,
   `vm.swapusage`, `kern.boottime`) is the highest-risk part and is exactly the
   kind of thing that produces plausible garbage rather than an error. A macOS
   CI runner exists in the workflow but has not been run.

4. **Linux is compiled and fixture-tested, not executed.** The parsers have
   thorough coverage against captured `/proc` formats, but the file-reading and
   `statfs` paths have not run on a Linux kernel.

5. **Per-core CPU is off by default and unbenchmarked at scale.** Enabling it on
   a 256-core host adds 256 series per cycle. The cap exists; the cost has not
   been measured on real hardware that large.

6. **Windows swap is not reported.** Windows exposes the commit limit, not
   page-file usage. Reporting commit as swap would be a different measurement
   under a familiar name, so it is absent. Operators migrating from agents that
   do report it will notice.

7. **`GetLogicalProcessorInformation` sees one processor group.** On Windows
   hosts with more than 64 logical processors, physical core count undercounts.
   It reports not-known on failure but cannot detect this case.

8. **No resource governor.** `Throttleable` is implemented and tested, but
   nothing calls it. Deferred to Stage 13 by the stage plan.

9. **Configuration is a flat string map.** The frozen `config.ModuleConfig`
   contract defines `Settings map[string]string`, so host settings use a
   namespaced flat key space (`interval.cpu`, `filesystem.exclude`). This works
   and is fully validated, but it is not pleasant for a module with genuinely
   nested configuration. **Smallest compatible extension, if a later module
   needs it:** add an optional `Raw json.RawMessage` field to
   `config.ModuleConfig` alongside `Settings`. Purely additive; existing modules
   ignore it. Not needed yet, so not done.

## Technical debt

| Item | Cost if deferred | Suggested point |
|---|---|---|
| Run `-race` on Linux CI | Latent concurrency bugs in two components now | Immediately |
| Multi-hour soak to confirm the ~12.5 MiB Windows ceiling | Unknown production memory profile | Before Stage 3 |
| Execute the suite on Linux and macOS runners | Two of three platforms unverified at runtime | Before Stage 3 |
| Reconcile ports against real platform contracts | Grows with every stage | Before Stage 5 |
| `selectBounded` sorts the full list before capping | 737 µs at 1,000 interfaces | Only if a host exceeds ~500 interfaces |
| `/proc/mounts` parsing is 61 allocs | Trivial at 60 s intervals | Only if the interval drops |
| Fuzz the `/proc` parsers | Malformed-input robustness | Stage 6, with the scrubber's fuzzing |

## Recommendation for Stage 3

Proceed to the **process module**, with three preconditions carried from the
gates above:

1. Run `make race` on Linux and fix anything it reports.
2. Run the suite on Linux and macOS runners. macOS especially: four sources have
   never executed.
3. Run a multi-hour soak and either explain the working-set trend or fix it.

The process module is the right next step because it stresses exactly what the
host module did not: **unbounded, high-churn entity counts**. A host has 4
interfaces and 3 mounts; a host has 10,000 processes that come and go every
second. The cardinality machinery, the counter-baseline reaping and the
deterministic bounded selection built here are the foundations it will need, and
it will be the first real test of whether they hold at scale.

---

# Stage 1 — agent shell + supervisor

**Date:** 2026-08-11
**Verdict:** delivered; superseded by Stage 2 for current status.

Stage 1 delivered the lifecycle foundation: supervisor, module contract,
versioned configuration with transactional reload, health model, diagnostics,
platform ports and agent self-observability. It deliberately shipped no
collectors, and reported health as `unknown` rather than `healthy` to say so.

## Measured results

| Metric | Measured |
|---|---|
| Binary size (stripped) | 2.87 MB |
| Idle working set | 6.39 MiB |
| Idle CPU | ~0.00 % |
| Process start → config validated → exit | 24.3 ms median (n=10) |
| Supervisor startup, 11-module graph | 516 µs |
| Goroutines at steady state | +1 (the control loop) |

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| StartupToRunning (11 modules) | 121,872 | 37,755 | 628 |
| Shutdown (11 modules) | 76,657 | 21,973 | 344 |
| HealthAggregate | 1,525 | 1,989 | 5 |
| Snapshot | 4,410 | 5,604 | 19 |
| ResolveGraph (11 modules) | 7,747 | 4,376 | 72 |
| ResolveGraph (500 modules) | 405,079 | 210,368 | 3,012 |

## Defects found and fixed during Stage 1

1. **Deadline race in `withTimeout`** (serious). The worker goroutine cancelled
   the deadline context immediately after delivering its result, making both
   `select` arms ready at once; Go chose randomly, so a module that started or
   stopped successfully was reported as timed out roughly half the time under
   load — and then given failure cleanup and charged against its crash-loop
   budget. Found by benchmarks under contention, invisible to unit tests. The
   reasoning now lives in `internal/guard`, which both the supervisor and every
   collector share.

2. **In-flight slot released at the deadline** (serious). A module whose call
   overran had its slot freed while still executing, so the next tick dispatched
   another call into it — one leaked goroutine per tick, and for `Start`, two
   concurrent starts of one module.

3. **Mixed time bases in shutdown.** Deadlines computed from the injected clock
   but compared using real-time `time.After`.

4. **`Stop` was not called after a failed `Start`,** contradicting the module
   contract and leaking any resource a partial start had acquired.

5. **Two state transitions the code performed were not in the legal set**
   (`Stopped→Failed`, `CrashLooping→Failed`).
