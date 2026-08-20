# Runbook: process module

For the module's full reference — platform matrix, every metric, cardinality
policy, tuning keys — see
[internal/modules/process/README.md](../../internal/modules/process/README.md).
This covers what you need during an incident.

## "The process module is degraded" — is that a problem?

Usually not. Read the health message; it names the reason.

| Platform | Features available | Expected health |
|---|---|---|
| Linux | 10 of 10 | healthy |
| Windows | 7 of 10 (no run state, command line, user) | **degraded — expected** |
| macOS | 3 of 10 (enumeration, name, state, start time only) | **degraded — expected** |

Degraded because a platform cannot provide a capability is permanent and correct.
Do not alert on it. Alert on a *change* in the number of available features, or
on `process.collection.failure` increasing.

The other degraded reasons, in rough order of how often you will see them:

| Message | Meaning | Action |
|---|---|---|
| `N processes exceeded max_processes` | more processes than the detail budget | see "Processes are missing" below |
| `N executables exceeded max_executables` | more distinct programs than the series budget | see "An executable is missing" below |
| `N% of processes could not be read` | genuine read failures above threshold | investigate; this is the one that means something is wrong |
| `host entity ID is unresolved` | platform identity is not answering | check platform discovery; the module keeps collecting unbound |

## Things that are NOT problems

**High `process.exited_during_collection`.** Processes exiting between
enumeration and inspection is the normal case on a busy host. A build server
finishing a job can produce tens of thousands. It never affects health, and it is
counted separately from read failures precisely so you can tell them apart.

**High `process.unreadable{reason=permission_denied}` on Windows.** An unelevated
agent cannot open processes belonging to other users. On a stock Windows 11
machine roughly 140 of 320 processes are denied. Those processes are still
counted, still named, and still contribute their thread counts — only CPU and
memory are missing.

Do **not** run the agent as SYSTEM or root to make this number go away. That
trades a real security property for a cosmetic one. If you genuinely need full
visibility and accept the trade, set `health.denied_is_failure: "true"` so the
degradation is at least visible.

**High `process.started_total` and `process.exited_total`.** That is churn. It is
what the host is doing, not what the agent is doing.

## Procedures

### Which process is using the CPU?

This is the question the module's cardinality design deliberately trades away, so
here is the answer path.

`process.cpu.utilization` is per **executable**, not per PID — that is what keeps
10,000 processes from creating 10,000 series. To get to an instance:

1. Find the executable from `process.cpu.utilization{executable=...}`.
2. Check `process.instances{executable=...}`. If it is 1, you already have your
   answer and the PID is in the `process.started` event for it.
3. If it is many, enable top-N reporting:

```json
"settings": { "events.top_n": "10" }
```

Reload (SIGHUP). Within one interval you will get `process.top` events carrying
PID, CPU, RSS and — if enabled — the executable path.

**Turn it off again afterwards.** At one event per process per cycle it is the
module's most expensive output; that is why it defaults to 0.

### Processes are missing from detailed collection

The most common cause is `max_processes`. Check
`process.dropped{reason=max_processes}`.

Selection is deterministic — configured processes, then kernel and init, then by
CPU, then memory, then name and PID — so the *same* processes are dropped every
cycle. You are seeing a stable subset, not a random one.

Fix by narrowing rather than by raising the cap. An exclusion says which
processes you do not care about; a bigger cap just pays for all of them:

```json
"exclude.names": "chrome,slack,Teams",
"min.memory": "50MB"
```

If you genuinely need more, raise `max_processes` **and** `max_tracked` together
— the configuration will reject `max_tracked` below `max_processes`, because
selected processes would otherwise lose their counter baselines every cycle.

### An executable is missing from the metrics

Check `process.dropped{reason=max_executables}` and `process.executables`.

This is the cap that actually bounds your series count, so raising it has a
direct cost: each executable is roughly 9 series. Going from 128 to 1024 turns
~1,150 series per host into ~9,200.

Prefer excluding what you do not need:

```json
"exclude.names": "conhost,svchost,RuntimeBroker"
```

### A sudden explosion in `process.executables`

Look at `process.dropped{reason=invalid_name}` at the same time.

Process names are chosen by the process. A workload that generates unique names —
or something hostile deliberately doing so — inflates the distinct-executable
count. The module holds the line at `max_executables` and sanitises the names,
so this is contained by design, but a step change is worth understanding.

`invalid_name` rising means names contained control characters or needed
truncation. That is not normal for ordinary software.

### "process collection exceeded its deadline"

A cycle overran `collection.timeout`. The module has already handled it: further
cycles are **suspended** until that read genuinely returns, so no goroutine
accumulates.

Causes, in order of likelihood:

1. **Too many expensive reads.** `collect.open_files` scans a directory per
   selected process; on Linux a process holding a million descriptors is slow to
   count. Turn it off, or lower `max_processes`.
2. **A wedged `/proc`.** Usually a process stuck in uninterruptible sleep with a
   dead network filesystem underneath it. Fix the mount.
3. **A genuinely huge process table.** At 50,000 processes a cycle takes ~60 ms;
   if you are seeing timeouts at the 2 s default, the cause is 1 or 2.

Raise `collection.timeout` only after eliminating those, and keep it below
`interval` — the configuration enforces this.

### The module is using more CPU than expected

1. `process.collection.duration_seconds` tells you the cycle cost directly.
2. Cost scales with `process.discovered` (the enumeration, unavoidable) and with
   `process.selected` (the expensive reads, entirely under your control).
3. In order of effect: turn off `collect.open_files` and
   `collect.executable_path`; lower `max_processes`; lengthen `interval`.

Doubling `interval` halves the cost exactly.

### Turning it off

```json
"modules": { "process": { "enabled": false } }
```

Reload (SIGHUP). A disabled module runs no goroutine, no timer and no collection,
holds no capability admission, and is excluded from health entirely.

To keep the module but stop the expensive part, prefer:

```json
"collect.io": "false",
"collect.open_files": "false",
"events.enabled": "false"
```

## Command lines

`collect.command_line` is **off by default, and that is a security decision**.
Command lines routinely carry credentials passed as arguments.

Before enabling it, understand what you are accepting:

- The values leave the module only as event attributes, never as metric labels.
- They are bounded at 32 arguments, 4 KB read, 1 KB rendered.
- **The module performs no scrubbing of its own.** It relies on the platform's
  central secret scrubber at the Telemetry Plane boundary. **That component is
  Stage 6 and is not built yet.** Until it is, enabling this ships command lines
  to your telemetry pipeline unredacted.
- It is unsupported on Windows and macOS regardless — both would require reading
  another process's memory or environment, which this agent does not do.

## Diagnostic codes

The module uses the agent-wide codes documented in [RUNBOOK.md](../RUNBOOK.md).
The ones you will see from it:

| Code | From the process module, means |
|---|---|
| `unsupported` | a feature is unavailable on this platform; the `feature` attribute names it |
| `unresolved_identity` | the host entity could not be resolved; collection continues unbound |
| `health_timeout` | a collection cycle overran and is suspended until its read returns |
| `panic` | a reader panicked and was isolated; the next cycle retries |
| `permission_denied` | read failures are above the configured threshold |
| `start_failed` | a collection cycle failed; the message carries the cause |

## Key metrics during an incident

| Metric | Watch for |
|---|---|
| `process.count` | a step change means something started or died en masse |
| `process.count.by_state{state=zombie}` | rising means a parent is not reaping |
| `process.count.by_state{state=disk_sleep}` | rising is the clearest signal of a storage problem |
| `process.collection.duration_seconds` | rising means the cycle is getting expensive |
| `process.dropped` | anything non-zero means you are not seeing everything |
| `process.executables` | approaching `max_executables` means series pressure |
| `process.state_entries` | should track `process.count`; if it plateaus you are at `max_tracked` |
| `process.replaced_total` | high rates mean rapid PID reuse — normal on busy hosts |
| `process.telemetry.dropped{reason=max_events}` | the event budget is engaging; check the churn summary |
