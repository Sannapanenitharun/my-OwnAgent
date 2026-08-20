# Process module

Collects process inventory, resource usage and lifecycle telemetry. It is the
second collector, and the first one that has to survive scale: a host with fifty
thousand processes, churning constantly, must not become a cardinality or a
resource problem.

## The three decisions that shape everything else

**1. Metrics roll up by executable; PID is never a metric label.**

Ten thousand processes on a typical host are a few dozen distinct programs. Five
hundred nginx workers contribute to one set of series, not five hundred. Series
count is therefore proportional to the number of *programs*, which is flat, and
not to the number of *processes*, which is not.

Measured: 10,000 processes across 40 executables produce **258 total series**.
The same 10 executables at 100 processes and at 20,000 processes produce
**identical** per-executable series counts.

Per-instance detail still exists — it lives on the event path, where a record has
a lifetime, instead of the metric path, where a series is forever.

**2. Identity is a process instance, not a PID.**

PIDs are reused. Linux's default `pid_max` is 32768 and a busy host cycles it in
minutes. Every piece of retained state is keyed by `(boot, pid, start_stamp)`, so
a recycled PID is recognised as a *different* process rather than silently
inheriting the previous one's counter baselines.

The start stamp is used **raw** — jiffies on Linux, a FILETIME on Windows,
microseconds on Darwin — because converting to wall-clock time rounds, and two
consecutive instances of a recycled PID can round to the same second.

**3. Churn is normal; permission denial is a boundary; only real errors are faults.**

A collector that conflated these would report a healthy build server as broken.
The three are counted separately and only the third affects health:

| Outcome | Meaning | Affects health |
|---|---|---|
| **Vanished** | exited between enumeration and inspection | no — this is churn |
| **Denied** | the agent may not inspect it | no — this is least privilege working |
| **Unreadable** | anything else | **yes** |

## Platform support

Nothing is faked. A feature a platform cannot provide is **absent**, with a
recorded reason, an unsupported diagnostic and degraded health.

| Feature | Linux | Windows | macOS | Notes |
|---|---|---|---|---|
| Enumeration | ✅ | ✅ | ✅ | `/proc` · toolhelp snapshot · `kern.proc.all` |
| Name | ✅ | ✅ | ✅ | truncated to 15 chars on Linux, 16 on Darwin |
| Parent PID | ✅ | ✅ | ❌ | see the Darwin note below |
| Start time | ✅ | ✅ | ✅ | |
| Run state | ✅ | ❌ | ✅ | Windows schedules threads, not processes |
| CPU time | ✅ | ✅ | ❌ | |
| Memory | ✅ | ✅ | ❌ | |
| Thread count | ✅ | ✅ | ❌ | |
| I/O counters | ✅ | ✅ | ❌ | Linux: owner-only, so denials are expected |
| Open files | ✅ | ✅ | ❌ | Windows counts *handles*, not descriptors |
| Executable path | ✅ | ✅ | ❌ | |
| Command line | ✅ | ❌ | ❌ | **off by default everywhere** |
| User (UID) | ✅ | ❌ | ❌ | numeric only; no name lookup |

**Features per platform:** Linux 10/10 (healthy), Windows 7/10 (degraded), macOS
3/10 (degraded). Degraded on Windows and macOS is the correct, permanent state —
do not alert on it.

### Why the macOS baseline is narrow

`KERN_PROC_ALL` returns `struct kinfo_proc`, which is `extern_proc` followed by
`eproc`. Only the first has a layout that can be derived confidently from
published headers and reproduced without cgo. `eproc` embeds `struct vmspace` and
`struct ucred`, whose sizes have changed across releases — and that is exactly
where the parent PID and owning UID live.

A decoder with one wrong offset in `eproc` does not fail. It returns *numbers*: a
parent PID that is really part of a pointer. That defect class must not ship, and
it is not verifiable from a machine that cannot run macOS. So those fields are
reported unsupported rather than guessed, and the reader additionally **gates**
on the record size: a buffer that is not a whole number of 648-byte records means
this kernel differs from the one the decoder was written against, and nothing is
decoded at all.

Per-process CPU and memory need `proc_pidinfo` from libproc, which needs cgo.
Command lines and executable paths come from `KERN_PROCARGS2`, which returns the
process **environment** in the same buffer — and this module does not read
process environments.

### Why Windows collects no command lines

Reading another process's command line on Windows means locating its PEB with
`NtQueryInformationProcess` and calling `ReadProcessMemory`. That is inspecting
process memory, which this module never does. The prohibition is worth more than
the field.

### Privileges

None required anywhere. Windows uses `PROCESS_QUERY_LIMITED_INFORMATION` — the
least privilege that answers every question asked. `PROCESS_QUERY_INFORMATION`
would also work and would additionally permit reading process memory, which is
precisely why it is not requested.

On a stock unelevated Windows 11 machine the agent enumerates all ~320 processes
and can open ~180 of them. The other ~140 belong to other users and are counted
as denied. That is least privilege working, not a fault.

## Metrics

| Metric | Type | Attributes |
|---|---|---|
| `process.count` | gauge | — |
| `process.count.by_state` | gauge | `state` (7 fixed values) |
| `process.cpu.utilization` | gauge | `executable` |
| `process.memory.rss` · `memory.virtual` | gauge | `executable` |
| `process.thread.count` · `open_files` | gauge | `executable` |
| `process.io.read_bytes` · `write_bytes` | counter | `executable` |
| `process.instances` | gauge | `executable` |
| `process.start_time_seconds` | gauge | `executable` |

`process.cpu.utilization` is a fraction of **total host capacity**, so 0.5 means
half the machine regardless of core count. The alternative — a fraction of one
core, where 4.0 is legal — reads naturally to anyone who has used `top` and is a
trap for every alert threshold written against it.

`process.instances` is what makes every other rollup interpretable. Without it,
"nginx is using 4 GB" cannot be told apart from "one nginx worker is using 4 GB",
and those call for opposite responses.

Self-observability: `process.collection.duration_seconds`, `.success`,
`.failure`, `process.discovered`, `.selected`, `.filtered`, `.dropped`,
`.unreadable`, `.exited_during_collection`, `.started_total`, `.exited_total`,
`.replaced_total`, `.telemetry.generated`, `.telemetry.dropped`,
`.state_entries`, `.executables`, `.unsupported`.

## Events

Per-instance detail lives here, including the PID.

| Event | When |
|---|---|
| `process.started` | a new instance appears (carries `restart=true` if the same executable exited recently) |
| `process.exited` | a tracked instance is gone, with its observed lifetime |
| `process.replaced` | a PID was reused by a different instance |
| `process.churn` | one per cycle, carrying the true totals |
| `process.top` | the highest-CPU processes — **off by default** |

Lifecycle events are emitted only for the **selected** set, so volume is
proportional to `max_processes` rather than to churn. They are capped again by
`max_events_per_cycle`, and whatever the cap sheds is reported in the churn
summary — which deliberately bypasses the budget, because it is the one event
that explains why the others are missing.

Measured: a cycle with 5,000 starts and 5,000 exits at a 50-event budget emitted
**100 lifecycle events plus one summary reading `started=5000 suppressed=9950`**.

## Cardinality

| Attribute | Bound |
|---|---|
| `executable` | `max_executables`, default 128 |
| `state` | 7 fixed values |
| `feature` | 10 fixed values |
| `reason` | 6 fixed values |

Never used as metric attributes: **PID, PPID, command line, arguments,
environment variables, executable paths, user names, file descriptors, network
endpoints, timestamps, error strings.**

### Process names are attacker-controlled

This is what makes process telemetry different from host telemetry: the observed
thing chooses its own label. A process can rewrite its name at any time via
`prctl(PR_SET_NAME)` or by overwriting `argv[0]`, and on Windows the name can be
260 characters.

Three defences, all measured:

1. **Control characters are replaced with `_`** — including the newline that
   would forge a log line and the ANSI escape that would reprogram a terminal
   reading it. Replaced rather than stripped, so two names differing only in
   control characters do not collide into one.
2. **Names are truncated to 64 bytes**, on a rune boundary.
3. **`max_executables` caps the distinct count**, with deterministic selection
   and drop accounting.

Measured: 5,000 processes with unique 300-character names full of control
characters produced **at most 128 series**, with the sanitisations and the
executable drops both counted.

## Configuration

```json
{
  "modules": {
    "process": {
      "enabled": true,
      "settings": {
        "interval": "30s",
        "collection.timeout": "2s",
        "max_processes": "1000",
        "max_executables": "128",
        "max_events_per_cycle": "500",
        "max_tracked": "16384",
        "exit_retention": "60s",
        "include.names": "",
        "exclude.names": "",
        "include.pids": "",
        "include.users": "",
        "include.states": "",
        "min.cpu": "0",
        "min.memory": "0",
        "collect.cpu": "true",
        "collect.memory": "true",
        "collect.threads": "true",
        "collect.state": "true",
        "collect.io": "true",
        "collect.open_files": "false",
        "collect.executable_path": "false",
        "collect.command_line": "false",
        "collect.user": "false",
        "events.enabled": "true",
        "events.top_n": "0",
        "metrics.disabled": "",
        "health.unreadable_ratio": "0.10",
        "health.denied_is_failure": "false"
      }
    }
  }
}
```

Unknown keys are **rejected**. A misspelled cap that is silently ignored is how
an operator concludes they have bounded an agent's cost when they have not — and
on this module, an ignored cap is the difference between a bounded series count
and a cardinality incident.

Two cross-field rules are enforced: `max_tracked` must be at least
`max_processes` (or selected processes would lose their counter baselines every
cycle), and `collection.timeout` must be shorter than `interval`.

**Every setting is safe to change live.** The interval, filters and caps are read
fresh at the top of each cycle, and the state store is keyed by process instance
rather than by anything configuration controls — so a reload never invalidates a
counter baseline, and no setting requires an agent restart.

### Filters, and why the order matters

```
enumerate ─▶ PID pre-filter ─▶ cheap read ─▶ name/state/user/threshold filters
          ─▶ bounded selection ─▶ EXPENSIVE reads ─▶ rollup ─▶ emit
```

The PID pre-filter is the only one that can run before any per-process work,
which is why it is worth having despite seeing only the PID: with `include.pids`
set on a fifty-thousand-process host it turns fifty thousand file reads into a
handful. It also narrows the aggregate counts, which no other filter does.

Threshold filters (`min.cpu`, `min.memory`) apply only to **known** values. A
process whose CPU could not be read is not dropped by `min.cpu`, because that
would make an unreadable process indistinguishable from an idle one.

### Selection under `max_processes`

Deterministic, in this order: explicitly included processes, then kernel and
init, then by CPU, then by memory, then by name and PID. The last two keys exist
so the ordering is *total* — without them a host with a thousand identical idle
processes would report a different subset every cycle, producing a churn of
half-populated series that is worse than reporting nothing.

Nothing is sampled and nothing is dropped silently.

## Security

**Never collected:** environment variables, process memory, memory maps, smaps,
credentials, tokens, private keys. The prohibition on `/proc/PID/environ`,
`/proc/PID/mem`, `/proc/PID/maps`, `/proc/PID/smaps`, `ReadProcessMemory` and
`NtQueryInformationProcess` is enforced by a test in `internal/architecture`, not
just documented — a reviewer adding one must also delete a line from that table,
which turns an easy mistake into an explicit decision.

**No command execution, no shell, no `ps`/`top` subprocesses, no WMI.** Direct OS
interfaces only.

**Command lines are off by default**, and that is a security default rather than
a cost one: credentials passed as arguments are routine. When enabled they are
bounded at the reader (32 args, 4 KB) and again at emission (1 KB rendered), they
never become a metric label, and they leave only through the Telemetry Plane's
event path — the stage the platform's central scrubber operates on. The module
implements no scrubbing of its own; duplicating that logic per collector is how
it ends up inconsistent.

## Resource behaviour

**One goroutine.** Measured at both 10 processes and 20,000: **+1 goroutine
each**. No goroutine per process, no timer per process, no watcher per process.

**One timer.** The fake clock counts armed timers directly; with 5,000 processes
the module arms one.

**Bounded state.** `max_tracked` caps the state table. New instances are admitted
in ascending PID order — not arbitrary: low PIDs are the long-lived system
services an operator cares about and high PIDs are the churn, so under pressure
the module sheds the churn and keeps the services. A process that does not fit is
still counted in the aggregates and the rollup; what it loses is delta-based
values and entity binding, and that is counted.

**Deadline-bounded.** The whole cycle runs under `collection.timeout` inside one
panic guard. A cycle that overruns **suspends** further cycles until the read
genuinely returns, so a wedged procfs costs one parked goroutine once rather than
one per interval forever.

## Back-pressure

`Throttleable` drives both a longer interval and a priority floor. Whole classes
of output are dropped, lowest first, so what survives is always internally
consistent — an agent that shed a uniform fraction of everything would produce
rollups whose instance counts did not match their memory sums.

| Pressure | Interval | Still emitted |
|---|---|---|
| None | ×1 | everything |
| Moderate | ×2 | drops detail reads and top-N |
| High | ×4 | drops per-executable rollups |
| Critical | ×8 | aggregate counts only |

Nothing drives it yet; the resource governor lands in Stage 13.

## Measured

Benchmarks on AMD Ryzen 5 5500U, `windows/amd64`, Go 1.26.5:

| Processes | Cycle | ns/process | Allocations | Bytes |
|---|---|---|---|---|
| 100 | 96 µs | 956 | 75 | 17 KB |
| 1,000 | 655 µs | 655 | 475 | 60 KB |
| 10,000 | 7.4 ms | 741 | 423 | 199 KB |
| 50,000 | 60 ms | 1,204 | 418 | 837 KB |

Reconcile — the stage whose cost is linear in process count — is **one
allocation** regardless of scale, and 8 bytes per process in steady state.

The Linux per-process parser, which the benchmarks above do not exercise because
they use a synthetic reader: **761 ns, 5 bytes, 1 allocation** per process.

| | |
|---|---|
| State retained | ~350–540 B per tracked process (~10 MiB at 20,000) |
| High churn, 10,000 processes | 15 ms/cycle |
| Working set, this machine (~320 processes, with the host module) | 8.4 MiB |
| CPU, steady state | 0.156 % of one core |
| Goroutines added | **+1**, independent of process count |

At 50,000 processes a 60 ms cycle every 30 s is 0.2 % of one core.

**Not yet measured:** a multi-hour soak, and any execution at all on Linux or
macOS. See `docs/review/process-module-readiness.md`.

## Health

| Condition | Health |
|---|---|
| enumeration works, read failures under threshold | healthy |
| read failure ratio over `health.unreadable_ratio` | degraded |
| features unavailable on this platform (Windows, macOS) | degraded |
| host entity unresolved | degraded |
| processes shed by `max_processes` or `max_executables` | degraded |
| every cycle failing | unhealthy |

Process churn is **not** a health signal. Neither is permission denial. Both are
entirely healthy situations, and an agent that reported them as faults would
train operators to ignore its health signal — the worst outcome available.

## Entity binding

Metrics carry the **host** entity. Binding a metric series to a process entity
would recreate exactly the per-process cardinality the rollup exists to avoid.

Process entities appear on **events**, resolved through the platform seam and
cached per instance — so a process running for a week is resolved once, and in
steady state the module makes zero resolution calls per cycle.

The module **never mints an EntityID**. It states the facts that identify a
process — boot, PID, start stamp, executable — and asks the platform what entity
they denote. An adapter that cannot answer produces an unresolved diagnostic and
an unbound observation, never a locally computed identifier. See
[ADR-0005](../../../docs/adr/0005-process-module.md) for the additive port
extension this required.
