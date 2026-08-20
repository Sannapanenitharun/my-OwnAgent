# Process module — readiness review (Phase 3)

**Verdict: feature-complete and production-quality in code; NOT yet cleared for
production deployment.**

Three gates are outstanding, all of them environmental rather than design
problems, and all of them stated below with what would close them.

This document exists to separate what has been *measured* from what has been
*reasoned about*. Both are legitimate; conflating them is not.

---

## 1. What was implemented

`internal/modules/process` — the second collector, built on the Stage 2 reference
pattern without modifying it.

| Component | File | What it owns |
|---|---|---|
| Data model, reader interfaces | `reader.go` | narrow interfaces split by *cost*, not just by concern |
| Linux `/proc` parsers | `parse.go` | no build tag, so they are tested on every developer platform |
| Per-platform readers | `reader_{linux,windows,darwin,unsupported}.go` | one file per target, no OS code anywhere else |
| Configuration | `config.go` | 26 settings, all bounded, all hot-reloadable |
| Cardinality policy | `metrics.go` | every attribute with a stated bound |
| Filtering and selection | `filter.go` | name sanitisation, deterministic bounded selection |
| Instance identity | `identity.go` | PID-reuse-safe keys, cached entity resolution |
| Lifecycle and state | `lifecycle.go` | reconciliation, churn, TTL eviction |
| Emission | `emit.go` | executable rollup, event budget, churn summary |
| Collection cycle | `collect.go` | the ordered pipeline and the priority model |
| Module lifecycle | `process.go` | supervisor contract, health, config transaction, throttle |

Plus one **additive** platform extension (`platform.EntityRef`,
`platform.EntityResolver`, `platform.ResolveEntity`) and its reference adapter
implementation. See [ADR-0005](../adr/0005-process-module.md).

**Scale:** 4,930 production lines and 3,876 test lines in the module, carrying
148 tests and benchmarks. Agent-wide: 13,729 production lines, 11,330 test lines,
433 tests and benchmarks, **zero third-party dependencies**, zero TODO/FIXME
markers.

---

## 2. What was measured

All on AMD Ryzen 5 5500U, `windows/amd64`, Go 1.26.5.

### Collection cost by scale

| Processes | Cycle time | ns/process | Allocations | Bytes/cycle |
|---|---|---|---|---|
| 100 | 96 µs | 956 | 75 | 17 KB |
| 1,000 | 655 µs | 655 | 475 | 60 KB |
| 10,000 | 7.4 ms | 741 | 423 | 199 KB |
| 50,000 | 60 ms | 1,204 | 418 | 837 KB |

Allocation count is **flat in process count** — 418 at fifty thousand processes
versus 475 at one thousand. Cost is linear in time and constant in allocations.

At 50,000 processes, a 60 ms cycle every 30 s is **0.2 % of one core**.

### Reconciliation — the stage that is linear in process count

| Processes | Time | ns/process | Allocations |
|---|---|---|---|
| 100 | 8.8 µs | 88 | **1** |
| 1,000 | 92 µs | 92 | **1** |
| 10,000 | 1.8 ms | 177 | **1** |
| 50,000 | 13.2 ms | 263 | **1** |

One allocation regardless of scale. Steady-state reconcile allocates **8 bytes
per process**.

### Cardinality

| Scenario | Result |
|---|---|
| 10,000 processes / 40 executables | **258 total series** |
| 100 processes vs 20,000, same 10 executables | **identical** per-executable series (60 each) |
| 1,000 processes / 500 executables, cap 20 | 20 series, drops counted |
| 5,000 hostile 300-char names with control characters | ≤128 series, sanitisations and drops both counted |
| Telemetry adapter's own cardinality bound | **never reached** — the module's bounds hold first |

### Churn — the mandatory Phase 3 scenario

10,000 processes, 5,000 replaced per cycle, 12 generations:

| | Result |
|---|---|
| Process starts observed | 70,000 |
| Process exits observed | 60,000 |
| Goroutines | **no growth** |
| State entries | 10,000 (tracks the live count exactly) |
| Metric series | **no growth** — 56, flat |
| Heap | no unbounded growth |

Churn storm with a 50-event budget: **100 lifecycle events emitted**, plus one
summary reading `started=5000 suppressed=9950`.

15 generations of full PID recycling across a 200-PID space: **2,800
replacements detected, 2,800 expected**, state entries exactly 200.

### Resource behaviour

| | Result |
|---|---|
| Goroutines added, 10 processes | **+1** |
| Goroutines added, 20,000 processes | **+1** |
| Timers armed with 5,000 processes | 1 |
| Detail reads, 1,000 processes at `max_processes=10` | exactly 10 of each |
| State retained | 350–540 B per tracked process (~10 MiB at 20,000) |
| Goroutines after Stop | 0 left behind |

### The shipping binary on this machine (~320 processes, host + process modules)

| | Stage 2 | Stage 3 |
|---|---|---|
| Binary | 3.05 MB | **3.24 MB** |
| Working set at t=5 s | 7.52 MiB | **8.4 MiB** |
| CPU, steady state | ~0.00 % | **0.156 % of one core** |
| OS threads | 7 | 7 |

### Real Windows hardware validation

| | |
|---|---|
| Processes enumerated | 316–343 |
| Openable unelevated | ~182 |
| Denied (other users) | ~134 |
| Distinct executables | 98–108 |
| PPID decoded | matches `os.Getppid()` exactly |
| `PROCESSENTRY32W` size | 568 bytes, as documented |
| Processes reporting a run state | **0** — correctly, Windows has none |

---

## 3. What is proven

- **Cardinality is bounded by executables, not processes.** Not argued —
  measured at two scales differing by 200×, producing identical series counts.
- **PID reuse is detected and never silently inherits a counter baseline.**
  Tested directly, and under 15 generations of full PID-space recycling.
- **Churn leaks nothing.** Goroutines, state, series and heap all flat across
  70,000 process starts.
- **One goroutine, one timer, independent of process count.** Measured at 10 and
  at 20,000 processes.
- **Expensive reads follow selection.** 1,000 processes with a cap of 10 performs
  10 reads, not 1,000.
- **Failure isolation works.** Panics contained, deadlines suspend rather than
  accumulate goroutines, per-process failures never fail a cycle, a failed cycle
  never fails the module.
- **Churn and permission denial do not degrade health.** Tested explicitly,
  including the configurable escape hatch.
- **Nothing is faked.** Every unsupported feature carries a reason; a platform
  that claims a feature must deliver it for at least some process, asserted
  against real hardware.
- **The Windows reader is correct on real hardware.** Struct layout verified by
  size and by comparing decoded PPID against a value the Go runtime already
  knows.
- **The additive port extension is genuinely additive.** An `Identity` adapter
  that predates it keeps working, with process entity binding simply absent —
  tested.
- **Modules cannot see each other.** Enforced by test across all six targets.
- **Forbidden OS interfaces are not read.** `/proc/PID/environ`, `mem`, `maps`,
  `smaps`, `ReadProcessMemory`, `NtQueryInformationProcess` — enforced by a test
  in `internal/architecture`, not by convention.

---

## 4. What is NOT proven

This is the section that matters.

### 4.1 The module has never executed on Linux

Every Linux-specific line — the `/proc` enumeration, the raw-syscall read path,
the `stat(2)` UID lookup, the `/proc/PID/fd` scan, `readlink` on `/proc/PID/exe`,
boot-ID reading — is verified by **compilation and by parser unit tests against
captured fixtures**. None of it has run against a real `/proc`.

The parsers themselves are well covered (that is why they carry no build tag),
including the hostile-process-name case. What is untested is the *I/O layer
around them*.

**This is the single largest gap in the phase**, because Linux is the primary
target and the reader there is the most code.

*Closes with:* one CI run of `go test ./...` on `linux/amd64`.

### 4.2 The module has never executed on macOS

Worse than Linux, because the Darwin reader decodes a binary struct by offset.
The decoder is gated — a buffer that is not a whole number of 648-byte records
causes it to report unsupported and decode nothing — so the *failure* mode is
safe. But whether the offsets are *right* is unverified.

Specifically unverified: that `p_stat`, `p_pid`, `p_comm` and `__p_starttime` sit
where `<sys/proc.h>` says they do under LP64, and that XNU actually fills
`__p_starttime` when answering `KERN_PROC_ALL`.

*Closes with:* one run on any Apple machine. `TestRealEnumerationFindsThisProcess`
alone would catch a wrong offset, because it compares the decoded PID against
`os.Getpid()`.

### 4.3 The race detector has still never run

Unchanged from Stages 1 and 2: `-race` requires cgo, and this machine has no C
toolchain (no gcc, clang or mingw).

This matters more than it did in Stage 2. The process module has a genuine
cross-goroutine surface: the collection goroutine owns the store, the emitter and
the resolver, while the supervisor calls `Health`, `Statistics`, `Capabilities`,
`Diagnostics`, `PrepareConfig`, `CommitConfig` and `Throttle` from its own
goroutine.

One race was found and fixed by inspection during development — `Statistics` read
the store's counters directly across that boundary, and now reads a snapshot
taken under the mutex. **The absence of others is not established.**

`make race` exists and the CI job is mandatory.

*Closes with:* the existing CI job running once.

### 4.4 No multi-hour soak

Working set grew 8.6 → 10.3 MiB over 90 seconds, in decaying increments (+844,
+500, +384 KiB). The shape is consistent with growth toward a plateau, and it
matches the Windows heap-commitment behaviour investigated at length in Stage 2 —
but **three data points over 90 seconds cannot distinguish a plateau from a slow
leak**, and it would be dishonest to claim otherwise.

The churn tests do establish that nothing in the module's *own* data structures
grows without bound over 70,000 process lifetimes. What is unestablished is the
allocator's steady-state behaviour over hours.

*Closes with:* a multi-hour run sampling working set. Predicted ceiling, by
analogy with Stage 2 and the measured allocation profile: **12–14 MiB**.

### 4.5 No real 50,000-process host

The 50K figures come from a synthetic reader, so they measure the *module* and
not the operating system. On a real Linux host with 50,000 processes the
enumeration alone is 50,000 file opens, which the benchmarks do not include.

Rough estimate from the raw-syscall read path: 50,000 × ~3 µs ≈ 150 ms, on top of
the measured 60 ms of module work. Still ~0.7 % of one core at a 30 s interval —
but that is arithmetic, not a measurement, and it is labelled as such.

### 4.6 Entity resolution against a real platform

Resolution is tested against the in-process reference adapter, which derives
identifiers deterministically. The real Discovery Runtime may be slower, may
rate-limit, and may fail intermittently.

The design accounts for this — per-instance caching, a per-cycle budget, a
deadline, and graceful degradation to unbound telemetry — and all of those paths
are tested. What is untested is the *latency* characteristic under a real
adapter.

---

## 5. Defects found during development

Recorded because the process of finding them is more informative than the fixes.

**1. New processes never seeded their CPU baseline** *(found by test)*. A newly
discovered process was admitted to the state table without recording its
cumulative CPU counter, so it needed *three* observations before reporting
utilisation instead of two — ninety seconds of silence per process at the default
interval. Fixed by seeding on admission.

**2. `Statistics` raced with the collection goroutine** *(found by inspection)*.
It read the store's lifetime counters directly while the collection goroutine
wrote them. Fixed by snapshotting under the mutex.

**3. The cycle counter lied about completion** *(found by an intermittent test
failure)*. `updateHealth` incremented the cycle count before `reportFailure`
recorded the diagnostic, so an observer acting on the counter could see a failed
cycle with no explanation attached. Fixed by reordering — and this was a
production defect surfaced by a flaky test, not a flaky test.

**4. Three tests waited on a proxy signal** *(found by running the suite
repeatedly)*. Each waited for the first metric or the first event, then asserted
on something emitted later in the same cycle. All three passed alone and failed
under load. Fixed by waiting on cycle *completion*; the helper carries the
explanation.

**5. A pre-existing Stage 2 test race** *(surfaced by the added load)*. The host
module's integration test waited for memory telemetry then immediately asserted
on `host.info`, which the run loop collects later in the same cycle. It had been
latent since Stage 2 and only failed once the package took longer to run. Fixed
in place.

**6. The forbidden-source architecture test had a false positive** *(found on its
first run)*. Matching the bare string `/proc/mem` flagged `/proc/meminfo`. Fixed
by matching the quoted path suffix, which is how these paths are actually
constructed.

---

## 6. Optimisations, and the measurement that justified each

No optimisation was made before measuring.

**Observation slab.** The first benchmark showed **100,419 allocations and 17.2 MB
per cycle at 50,000 processes** — two allocations per process. Observations do not
outlive the cycle that produces them, so they now come from a slab reused across
cycles. Result: 418 allocations, 837 KB. The slab is sized once per cycle before
any pointer into it is handed out, because growing it mid-loop would reallocate
and silently invalidate every pointer already returned.

**Slab hysteresis.** Retaining the slab trades garbage for resident memory, and
that trade only holds if the retention is bounded. The slab is released when it is
more than four times larger than the current cycle needs, so a transient fork
storm cannot leave the agent holding twenty megabytes forever.

**`sanitiseName` fast path.** After the slab, reconcile still allocated once per
process: the sanitiser built a new string even for names needing no change. A
scan-and-return-original fast path removed it — 55 ns and **zero allocations** for
a clean name. This is what took reconcile to one allocation total.

**`parseStat` field buffer — the most valuable find of the phase.** Benchmarking
the Linux hot path in isolation showed **2,787 ns, 3,413 B and 7 allocations per
call**. `/proc/PID/stat` has about fifty fields, and building the field index from
an empty slice costs seven append-grows every single call. This function runs
once per process per cycle, so at fifty thousand processes it was **170 MB of
garbage per cycle from parsing alone** — more than everything else in the module
combined, and it would have been invisible from this machine because the
benchmarks that exercise the collection cycle use a synthetic reader that never
calls it.

Threading a reusable field buffer through, the way `splitFields` was already
designed to allow:

| | Before | After |
|---|---|---|
| Time | 2,787 ns | **761 ns** |
| Bytes | 3,413 B | **5 B** |
| Allocations | 7 | **1** |

The remaining allocation is the executable name, which must be copied because the
read buffer is reused and the name is retained on the tracked instance.

**Raw syscalls in the Linux read path.** `os.Open` allocates an `*os.File` with a
finalizer, and procfs files report size zero so `ReadFile` runs a grow loop. At
50,000 processes per cycle that is the difference between kilobytes and tens of
megabytes. Written this way from the start, with the reasoning in the code —
noted here because it is the one optimisation *not* preceded by a measurement, on
the grounds that it is not measurable from this machine.

**Not done: a worker pool.** The specification permits one. Measurement says it is
unnecessary: 50,000 processes cost 60 ms of module work, and the estimated
enumeration cost on a real Linux host adds ~150 ms — still under 0.7 % of one
core at a 30-second interval. A worker pool would add goroutine-lifetime and
panic-containment complexity to buy nothing measurable, so it was not built. If a
real 50,000-process Linux host disagrees, the seam to add one is `readDetail`,
which is already the only stage that would benefit.

---

## 7. Security review

| Concern | Disposition |
|---|---|
| Environment variable exposure | Never read. Enforced by architecture test. |
| Process memory | Never read. Enforced by architecture test. Windows uses `PROCESS_QUERY_LIMITED_INFORMATION` specifically because the alternative would permit it. |
| Command-line exposure | Off by default. Bounded at reader and at emission. Events only, never a metric label. **Depends on the Stage 6 scrubber, which does not exist yet** — documented in the runbook as an explicit risk. |
| Credential exposure | No credential fields in configuration; diagnostics carry no collected content. |
| **Malicious process names** | **The distinctive risk of this module.** A process chooses its own label. Control characters replaced (log-forging, terminal escapes), length capped at 64 bytes on a rune boundary, distinct count capped with drop accounting. Measured against 5,000 hostile names. |
| Cardinality abuse | Same mitigation; the executable cap holds regardless of what names appear. |
| Resource exhaustion | Every limit finite by default. A process holding a million descriptors costs a bounded count, not a million names. |
| Symlink/path attacks | `/proc/PID/exe` is `readlink`ed, never opened. The target is reported, never followed. |
| PID information leakage | PIDs appear in events, never in metric labels, never in diagnostics. |
| procfs permission errors | Classified as denial, not failure. Do not degrade health by default. |
| Cross-tenant entity binding | The module never mints an EntityID; the platform is the authority. |
| TOCTOU on `/proc/PID` | The PID inside `stat` is checked against the directory name; a mismatch is treated as churn rather than trusted. |
| Command execution | None. No shell, no `ps`/`top`, no WMI. |
| Privilege requirements | None. Least privilege on every platform, verified against real Windows hardware. |

One residual risk worth naming: **enabling `collect.command_line` before Stage 6
ships means unredacted command lines reach the telemetry pipeline.** The module
correctly declines to implement its own scrubbing — duplicating that logic per
collector is how it ends up inconsistent — but the gap is real until the central
scrubber exists.

---

## 8. Technical debt

| Item | Cost | When |
|---|---|---|
| macOS: no PPID, UID, CPU, memory, threads | 3 of 10 features | needs a cgo decision or verified `eproc` offsets |
| Windows: no run state, command line, user | 7 of 10 features | inherent to the platform; no action |
| Linux `USER_HZ` hardcoded to 100 | wrong CPU figures on a kernel that differs | correct for every supported architecture; would need `sysconf`, hence cgo |
| Windows `Denied` counts both enumeration and I/O denial | the counter double-counts one privilege boundary | cosmetic; would need a separate counter |
| Executable name truncated to 15 chars on Linux | `postgres: writer process` becomes `postgres: writ` | inherent to `comm`; `collect.executable_path` gives the full path in events |
| No worker pool | 50K enumeration is sequential | measured as unnecessary; revisit only if a real 50K host disagrees |
| `config.ModuleConfig.Settings` is flat `map[string]string` | include/exclude blocks read awkwardly | see below |

**On the flat settings map.** Twenty-six settings fit the flat namespace without
strain, but the include/exclude groups would read better nested. The smallest
compatible extension, if a later module genuinely needs it, is an optional
`Raw json.RawMessage` field on `config.ModuleConfig` — purely additive, ignored
by every existing module. Not needed yet, and adding it speculatively would be
the wrong call.

---

## 9. Backward compatibility

| Stage 1 / 2 contract | Status |
|---|---|
| Supervisor semantics | **unchanged** |
| Module contract | **unchanged** |
| Configuration contract | **unchanged** |
| Health contract | **unchanged** |
| Diagnostics contract | **unchanged** |
| `platform.Identity` | **unchanged** — the resolver is a separate optional interface |
| `platform.Telemetry`, `Clock`, `CapabilityRuntime` | **unchanged** |
| Host module | **unchanged** |

One test was modified: the host module's integration test, to fix a pre-existing
race it had carried since Stage 2 (§5.5). No production Stage 1 or Stage 2 code
was touched.

All Stage 1 and Stage 2 tests pass. The full suite ran clean 8 consecutive times.

---

## 10. Gate status

| Gate | Status |
|---|---|
| Process collection works | ✅ measured on real Windows hardware |
| Linux implementation | ⚠️ compiled and parser-tested; **never executed** |
| Windows implementation | ✅ validated against real hardware |
| macOS implementation | ⚠️ compiled only; **never executed** |
| Unsupported semantics | ✅ |
| Identity lifecycle-safe, PID reuse handled | ✅ |
| Churn handled | ✅ 70,000 process lifetimes, nothing leaked |
| 10K scenario tested | ✅ |
| 50K benchmarked | ✅ synthetic reader |
| Memory / state / goroutines / timers bounded | ✅ measured |
| Cardinality and telemetry bounded | ✅ measured |
| Back-pressure works | ✅ tested at all four levels |
| Entity binding works | ✅ against the reference adapter |
| Failure isolation works | ✅ |
| Configuration and hot reload work | ✅ |
| Security review complete | ✅ §7 |
| Documentation complete | ✅ |
| Six-target builds pass | ✅ plus freebsd/amd64 |
| Stage 1 and Stage 2 tests pass | ✅ |
| `gofmt`, `go vet`, architecture rules | ✅ |
| **Race detector** | ❌ **cannot run here; CI job defined** |
| **Multi-hour soak** | ❌ **not run** |

---

## 11. Recommendation

**Freeze Phase 3 code. Do not deploy until §4.1, §4.2 and §4.3 close.**

All three are single CI runs. None is a design problem, and none requires code
changes to attempt. If any of them fails, that failure is the finding — and the
tests that would catch it already exist.

The architecture is ready for Phase 4. The process module was the hardest test
the Stage 2 pattern would face — unbounded entity counts, high churn,
attacker-controlled labels, per-instance identity — and the pattern held without
being modified. The one contract gap it exposed, entity resolution for child
entities, was closed additively.
