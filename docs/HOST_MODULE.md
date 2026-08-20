# Host module

Collects CPU, memory, disk, filesystem, network interface, OS, kernel,
architecture, load, uptime and host identity. It is the first collector, and it
is the reference pattern every later module should follow.

## Platform support

Nothing is faked. A source a platform cannot provide is **absent**, with a
recorded reason, an unsupported diagnostic and degraded health.

| Source | Linux | Windows | macOS | Notes |
|---|---|---|---|---|
| CPU counts | ✅ | ✅ | ✅ | physical cores from sysfs topology / `GetLogicalProcessorInformation` / `hw.physicalcpu` |
| CPU utilisation | ✅ | ✅ | ❌ | macOS needs Mach `host_processor_info`, which needs cgo |
| Memory total | ✅ | ✅ | ✅ | |
| Memory used/available | ✅ | ✅ | ❌ | macOS needs Mach `vm_statistics64` |
| Swap | ✅ | ❌ | ✅ | Windows exposes the commit limit, not page-file usage |
| Disk I/O | ✅ | ❌ | ❌ | Windows needs Administrator; macOS needs IOKit/cgo |
| Filesystem | ✅ | ✅ | ✅ | inode counts on Linux/macOS only |
| Network interfaces | ✅ | ✅ | ❌ | macOS needs the routing-socket interface |
| OS / kernel / arch | ✅ | ✅ | ✅ | |
| Load average | ✅ | ❌ | ✅ | Windows has no run-queue load average |

**Sources per platform:** Linux 7/7 (healthy), Windows 5/7 (degraded), macOS 4/7
(degraded). Degraded is the correct, expected state on Windows and macOS — it is
not a fault, and it must not be alerted on.

**Verification status.** Linux and Windows readers are executed by the test
suite. The Windows implementation was validated against real hardware during
development. The macOS reader is verified by **compilation only** for
darwin/amd64 and darwin/arm64; it has not been executed on Apple hardware. See
`docs/READINESS.md`.

### Privileges

None required anywhere. Every Linux path is world-readable, every Windows call
is a query API available to a normal user. Disk I/O counters on Windows would
need Administrator, which is exactly why that source is reported unsupported
rather than making the whole agent demand elevation.

No shell execution, no command execution, no WMI, no file reads outside the
documented OS interfaces.

## Metrics

| Metric | Type | Attributes |
|---|---|---|
| `host.cpu.utilization` | gauge | `state` (busy/user/system/iowait/steal/irq) |
| `host.cpu.count` | gauge | `type` (logical/physical) |
| `host.memory.total_bytes` · `used_bytes` · `available_bytes` · `utilization` | gauge | — |
| `host.memory.swap.total_bytes` · `swap.used_bytes` | gauge | — |
| `host.disk.read_bytes` · `write_bytes` · `read_ops` · `write_ops` · `io_time_seconds` | counter | `device` |
| `host.filesystem.total_bytes` · `used_bytes` · `available_bytes` · `utilization` · `inodes_total` · `inodes_used` | gauge | `mountpoint`, `fstype` |
| `host.network.rx_bytes` · `tx_bytes` · `rx_packets` · `tx_packets` · `rx_errors` · `tx_errors` · `rx_dropped` · `tx_dropped` | counter | `interface` |
| `host.load.1m` · `5m` · `15m` | gauge | — |
| `host.uptime_seconds` | gauge | — |
| `host.info` | gauge (=1) | `os`, `platform`, `platform_version`, `kernel_version`, `architecture` |

Self-observability: `host.collection.duration_seconds`, `.success`, `.failure`,
`.unsupported`, `.last_success_seconds`, `host.telemetry.items`,
`host.telemetry.dropped`, `host.module.health` — all attributed by `source` only.

Every observation carries `entity.id`, the platform-assigned host entity.

### Three behaviours worth knowing

**The first CPU sample emits no utilisation.** Utilisation is a ratio of deltas,
so one sample cannot produce one. Emitting the cumulative counter would report a
spike equal to everything since boot.

**Counters emit deltas, and suppress resets.** A counter that goes backwards
(device re-added, interface recreated, host rebooted) re-seeds its baseline and
emits nothing, rather than a huge or wrapped value.

**Unknown is never zero.** A value the platform cannot supply is not emitted at
all. `host.memory.swap.total_bytes` is simply absent on Windows; it is never 0.

## Cardinality

Every attribute's value set is bounded, and the bound is enforced rather than
assumed:

| Attribute | Bound |
|---|---|
| `state` | 6 fixed values |
| `type` | 2 fixed values |
| `source` | 7 fixed values |
| `device` | `disk.max`, default 32 |
| `interface` | `network.max`, default 32 |
| `mountpoint`, `fstype` | `filesystem.max`, default 64 |

Never used as labels: PID, timestamps, UUIDs, command lines, arbitrary paths,
error strings, device serial numbers.

Selection under a cap is **deterministic** — sorted by name, first N kept — so a
host over its cap reports a stable subset rather than a different one each cycle.
Anything dropped is counted in `host.telemetry.dropped` with
`reason=cardinality_limit` and raises a diagnostic; truncation is never silent.

Two exclusions are applied before the cap, and both were driven by real
measurements on real machines:

- **Windows filter interfaces.** A stock Windows 11 laptop reports 42 interfaces,
  of which 23 are NDIS lightweight filter bindings (WFP, QoS Packet Scheduler,
  virtual switch extensions). These are excluded in the reader, because a filter
  binding is not a network interface — that is a fact about the API, not a
  policy choice. 42 → 19.
- **Pseudo-filesystems.** On a container host, most mounts are overlay/tmpfs/
  cgroup entries that describe kernel bookkeeping. Excluded by type by default.

## Configuration

Settings live in the module's `settings` map. Unknown keys are **rejected**.

```json
{
  "modules": {
    "host": {
      "enabled": true,
      "settings": {
        "interval.cpu": "10s",
        "interval.memory": "10s",
        "interval.network": "10s",
        "interval.load": "10s",
        "interval.disk": "30s",
        "interval.filesystem": "60s",
        "interval.os": "5m",
        "collection.timeout": "5s",
        "cpu.per_core": "false",
        "cpu.max": "256",
        "filesystem.exclude": "/proc,/sys,/dev,/run",
        "filesystem.type.exclude": "tmpfs,overlay,cgroup2",
        "filesystem.max": "64",
        "filesystem.inodes": "true",
        "network.exclude": "veth,docker,br-",
        "network.max": "32",
        "disk.exclude": "loop,ram,dm-",
        "disk.max": "32",
        "metrics.disabled": "host.filesystem.inodes_used",
        "sources.disabled": "disk"
      }
    }
  }
}
```

| Key | Default | Notes |
|---|---|---|
| `interval.<source>` | see below | 1s ≤ v ≤ 24h |
| `collection.timeout` | `5s` | 100ms ≤ v ≤ 1m; bounds a single source read |
| `cpu.per_core` | `false` | off by default: per-core is `cpu.max` extra series |
| `*.exclude` | platform defaults | comma-separated **substrings**, case-insensitive |
| `*.max` | 32/32/64/256 | hard series cap, 1–4096 |
| `metrics.disabled` | empty | must name real metrics; a typo is rejected |
| `sources.disabled` | empty | a disabled source is never read |

Default intervals are deliberately unequal — CPU/memory/network/load 10s, disk
30s, filesystem 60s, OS metadata 5m. Collecting everything at the fastest useful
rate is the single largest avoidable cost in an observability agent, and a
filesystem does not fill up in ten seconds.

Setting an exclusion key to the empty string clears the defaults, which is how an
operator asks for everything.

## Resource behaviour

**One goroutine.** The module owns exactly one collection goroutine. There is no
goroutine per metric, per filesystem, per interface or per CPU, and no per-source
timer: a single computed sleep to the next due source replaces seven tickers.

**Deadline-bounded reads.** Each source read runs under `collection.timeout`. A
source that overruns is **suspended** until its read genuinely returns, so a
wedged NFS mount costs one parked goroutine once — not one per cycle forever —
and the other six sources keep collecting.

**Bounded memory.** Counter baselines for interfaces and devices are reaped when
they disappear, so a host that churns containers does not accumulate state.

**Disabled means disabled.** A disabled module is never started by the
supervisor: zero goroutines, zero timers, zero reads, no capability admission,
and it is excluded from health entirely.

## Health

| Condition | Health |
|---|---|
| every source available and collecting | healthy |
| some sources unavailable (Windows, macOS) or failing | **degraded** |
| entity ID unresolved | degraded |
| no source producing data | unhealthy ("unavailable") |

A partly-working host module is explicitly not a failure. On Windows two of
seven sources are unavailable by design; treating that as failure would mean
every Windows host in a fleet reports a broken agent.

## Failure isolation

A failing or panicking reader fails **one source**. The other six keep
collecting, the module stays running, and the agent is unaffected. Panics are
recovered and recorded as a `panic` diagnostic with the offending source named.

## Extending: the pattern for later modules

1. **Narrow reader interfaces, one per source.** A single fat interface forces
   every platform to implement everything, and the only way to satisfy it where
   you cannot is to return a zero value — the fabrication this design prevents.
2. **Pure parsing separated from I/O.** The `/proc` parsers take `[]byte` and
   live in a file with no build tag, so the entire Linux parsing surface is
   unit-tested on macOS and Windows too.
3. **Optional values, not zero values.** `U64`/`F64` carry an `OK` flag.
4. **One goroutine, computed next-due, deadline-bounded reads.**
5. **Bounded selection with deterministic ordering, and count what you drop.**
6. **Declare permissions; fail closed.**
7. **Implement `Throttleable`** so Stage 13 does not require a rewrite.
8. **Never invent an entity ID.** Emit unbound with a diagnostic instead.
