# Operational runbook

Covers the agent shell, supervisor, host/process/discovery/logs collectors, the
OTLP receiver, and OTLP export. Process-module incidents:
[runbooks/process-module.md](runbooks/process-module.md). Logs:
[LOGS_MODULE.md](LOGS_MODULE.md). Receiver: [OTEL_ENGINE.md](OTEL_ENGINE.md).
AWS install: [AWS_AGENT.md](AWS_AGENT.md).

## Quick reference

```bash
observability-agent --version                # build identity
observability-agent --check                  # validate config + wiring, exit
observability-agent --config /etc/obsagent/agent.json
observability-agent --log-level debug --log-format json
```

| Signal | Linux/macOS | Windows |
|---|---|---|
| Graceful shutdown | `SIGTERM`, `SIGINT` | Ctrl-C / SCM stop |
| Configuration reload | `SIGHUP` | **not available** — restart the service |

Exit code `0` = clean; `1` = startup or shutdown failed. The reason is on stderr.

## Before you touch a running agent

Run `--check` against the configuration you intend to deploy. It performs the
full real path — load, validate, construct the supervisor, register modules,
resolve the dependency graph — and exits without starting anything. A
configuration that fails `--check` will fail on the host.

## Health

Agent health is one of:

| Status | Meaning | Action |
|---|---|---|
| `healthy` | every enabled module is working | none |
| `degraded` | reduced coverage; an optional module is unsupported or failed | investigate at leisure |
| `unhealthy` | a **required** module is not working | act now |
| `unknown` | nothing has reported yet, or no modules are enabled | expected briefly at startup; **persistent `unknown` means the agent is supervising nothing** |

A degraded agent is still collecting. Do not restart it reflexively — a restart
loses in-flight telemetry and rarely fixes a capability gap.

## Diagnostic codes

Every diagnostic carries a stable code. These are the operator-facing contract.

| Code | Meaning | What to do |
|---|---|---|
| `unsupported` | the module cannot run in this environment | **Nothing.** Not a failure. eBPF on Windows, or a kernel without BTF, is expected. |
| `permission_denied` | the agent lacks a required privilege | Grant the permission in IAM, or disable the module. The module never ran. |
| `unresolved_identity` | an identifier could not be resolved | Check platform identity configuration and connectivity. The agent runs without it and does **not** invent an ID. |
| `start_failed` | a module failed to start | Read the message. The module restarts with backoff automatically. |
| `stop_failed` | a module did not stop cleanly | Usually benign at shutdown. Repeated occurrences suggest a module bug. |
| `panic` | a module panicked and was isolated | A defect. Capture logs and file it. The rest of the agent is unaffected. |
| `crash_loop` | restart budget exhausted; module quarantined | See "Releasing a quarantine" below. |
| `dependency_unavailable` | waiting on another module | Fix the named dependency; this module restarts itself. **Does not** count against its own crash-loop budget. |
| `config_invalid` | configuration rejected | Correct it and reload. The previous revision is still running. |
| `config_rolled_back` | a reload was aborted and reverted | A module rejected its fragment. The message names it. |
| `shutdown_timeout` | a module was not stopped in time | Raise `agent.shutdown_timeout`, or investigate slow modules earlier in the stop order. |
| `health_timeout` | a health probe overran its deadline | The module is slow or stuck. Health shows `unknown`, not `unhealthy`. |
| `dropped` | telemetry was shed to a bound | Raise the queue/batch cap, or reduce rate. The agent did not OOM. |

## Self-telemetry

All under `agent.*` in the Telemetry Plane. The most useful during an incident:

| Metric | Watch for |
|---|---|
| `agent.health_status` | anything other than healthy |
| `agent.module.state` | a module not in `running` |
| `agent.module.restarts` | a rising rate = something is flapping |
| `agent.module.crash_loops` | any increase = a module is quarantined |
| `agent.module.panics` | any increase = a defect |
| `agent.goroutines` | steady growth = a leak |
| `agent.memory.heap_bytes` | steady growth = a leak |
| `agent.module.health_timeouts` | a module is not answering |
| `agent.config.rollbacks` | configuration is being rejected |
| `agent.diagnostics.dropped` | diagnostics are being produced faster than retained — something is failing hard |

The only label is `module`. If you see any other label on an `agent.*` series,
that is a bug worth reporting.

## Procedures

### A module is crash-looping

1. Confirm: `agent.module.state` = `crash_looping`, and a `crash_loop`
   diagnostic naming the module.
2. Read the preceding `start_failed` diagnostics — they carry the real cause.
3. The rest of the agent is unaffected. There is **no urgency to restart the
   agent**; the quarantine exists precisely to stop the module consuming CPU.
4. Fix the cause.
5. Release the quarantine (below).

**Why it was quarantined:** it exceeded `agent.restart.max_restarts` within
`agent.restart.window`. It will not be retried until released.

### Releasing a quarantine

Preferred — reload configuration:

```bash
kill -HUP $(pidof observability-agent)     # Linux/macOS
```

This resets the restart budget and schedules an immediate retry, **without
disturbing any other module**. On Windows, restart the service.

Only restart the whole agent if a reload is unavailable. A restart loses every
module's state to fix one module's problem.

### A configuration reload was rejected

The agent is still running the previous revision, unchanged. Nothing partially
applied — that is guaranteed by the prepare/commit design.

1. Find the `config_invalid` or `config_rolled_back` diagnostic; it names the
   field or the module that rejected it.
2. Fix it, verify with `--check`, reload again.

If you instead see `config_invalid` with "commit failed after a successful
prepare", that is the one non-atomic case: some modules are on the new
configuration and some are not. **Restart the agent** to return to a known state,
and file a bug against the named module.

### The agent will not start

Startup fails only for structural reasons. A single failing collector never
prevents startup.

| Message | Cause | Fix |
|---|---|---|
| `dependency cycle: a -> b -> a` | module manifests form a loop | a build defect; file it |
| `depends on X, which is not registered or not enabled` | a dependency is disabled | enable X, or disable the dependent |
| `config: ...` | invalid configuration | run `--check` for the full list |
| `missing required ports` | build/wiring defect | file it |

### The agent is using too much memory or CPU

1. Check `agent.goroutines` and `agent.memory.heap_bytes` over time. Flat = not
   a leak.
2. Identify the module: `agent.module.*` is labelled by `module`.
3. Increase collection intervals for the offending module, or disable it and
   reload.
4. There is **no automatic resource governor** yet; shedding load is manual until
   Stage 13. The `Throttleable` seam exists but nothing drives it.

### Slow or hung shutdown

Shutdown is bounded twice — per module (`agent.module_stop_timeout`) and overall
(`agent.shutdown_timeout`) — so a hung module cannot prevent exit. Modules stop
in reverse dependency order; a `shutdown_timeout` diagnostic names any module the
budget did not reach.

If the service manager is killing the agent, raise `agent.shutdown_timeout`, but
keep it **below** the service manager's own stop timeout (systemd's default
`TimeoutStopSec` is 90 s; the agent defaults to 30 s to sit comfortably inside).

## Host module

The host module's own reference — platform support matrix, every metric, the
cardinality policy and all tuning keys — is [HOST_MODULE.md](HOST_MODULE.md).
The procedures below are the ones you need during an incident.

### "The host module is degraded" — is that a problem?

Usually not. Read the health message; it says which of the seven sources are
unavailable and why.

| Platform | Sources available | Expected health |
|---|---|---|
| Linux | 7 of 7 | healthy |
| Windows | 5 of 7 (no disk I/O, no load average) | **degraded — expected** |
| macOS | 4 of 7 (no CPU utilisation, memory usage, disk I/O, network) | **degraded — expected** |

Degraded because a platform cannot provide a source is a permanent, correct
state. Do not alert on it. Alert on a *change* in the number of available
sources, or on `host.collection.failure` increasing.

### A host metric is missing

Work down this list; the first match is almost always the cause.

1. **The platform cannot provide it.** Check the module's capabilities in the
   diagnostics snapshot — each unavailable source carries a reason.
2. **It needs two samples.** `host.cpu.utilization` never appears on the first
   collection, by design. Wait one interval.
3. **The value is unknown.** The module never emits a fabricated zero. Absent
   swap metrics on Windows are correct, not a bug.
4. **It was filtered.** Check `filesystem.exclude`, `network.exclude`,
   `disk.exclude` and the `*.max` caps.
5. **It hit the cardinality cap.** Look for `host.telemetry.dropped` with
   `reason=cardinality_limit`, and a diagnostic naming the source and count.
6. **It was disabled.** Check `metrics.disabled` and `sources.disabled`.

### A filesystem or device is missing from the metrics

The most common cause is the series cap. `host.telemetry.dropped` tells you how
many were shed, and selection is deterministic (sorted by name, first N kept) —
so the *same* ones are dropped every cycle.

Fix by narrowing rather than by raising the cap: an exclusion expresses which
mounts you do not care about, whereas a bigger cap just pays for all of them.

```json
"filesystem.exclude": "/snap,/var/lib/containers",
"filesystem.max": "128"
```

### "host source read exceeded its deadline"

A source read overran `collection.timeout`. Nearly always a wedged network mount
blocking `statfs`.

The module has already handled it: that source is **suspended** until the read
returns, the other six keep collecting, and no goroutine accumulates. Fix the
mount. If your mounts are legitimately slow, raise `collection.timeout`; if they
are legitimately unreliable, exclude them.

### The host module is using more CPU than expected

1. Look at `host.collection.duration_seconds` by `source` to find which one.
2. Check the series counts — cost scales with mounts and interfaces, not with
   interval alone.
3. Lengthen that source's interval, or exclude what you do not need. Doubling
   `interval.filesystem` halves that source's cost exactly.
4. `cpu.per_core` is off by default. If you enabled it, it is `cpu.max` extra
   series per cycle.

### Turning the host module off

```json
"modules": { "host": { "enabled": false } }
```

Reload (SIGHUP). A disabled module runs no goroutine, no timer and no collection,
holds no capability admission, and is excluded from health entirely.

To keep the module but drop one expensive source, prefer `sources.disabled` —
`"sources.disabled": "filesystem"` — which stops that source being read at all.

## Process module

Its reference and its incident procedures are separate documents:
[the module README](../internal/modules/process/README.md) and
[runbooks/process-module.md](runbooks/process-module.md).

The three things worth knowing before you page someone:

- **Degraded on Windows and macOS is expected and permanent.** Windows provides
  7 of 10 process features, macOS 3 of 10.
- **`process.exited_during_collection` and `process.unreadable{reason=permission_denied}`
  are not faults.** They are process churn and least privilege, respectively, and
  neither affects health by default.
- **`process.cpu.utilization` is per executable, not per PID.** To reach an
  instance, see "Which process is using the CPU?" in the module runbook.

## Configuration reference

```json
{
  "schema_version": 1,
  "agent": {
    "shutdown_timeout": "30s",
    "module_stop_timeout": "10s",
    "module_start_timeout": "30s",
    "health_interval": "15s",
    "health_probe_timeout": "5s",
    "diagnostics_retention": 256,
    "restart": {
      "enabled": true,
      "initial_backoff": "1s",
      "max_backoff": "5m",
      "jitter_fraction": 0.2,
      "max_restarts": 5,
      "window": "10m"
    }
  },
  "modules": {}
}
```

A partial file is legal — unstated fields keep their defaults. Unknown fields are
**rejected**, so a typo fails loudly instead of silently doing nothing.

A module absent from `modules` is **disabled**. Enabling a collector is always an
explicit decision.

`required: true` means the agent is `unhealthy` without it. Use it sparingly.

### Environment overrides

A fixed allowlist only. Credentials are never accepted here.

```
OBSAGENT_CONFIG                     path to the configuration file
OBSAGENT_SHUTDOWN_TIMEOUT           duration
OBSAGENT_MODULE_STOP_TIMEOUT        duration
OBSAGENT_MODULE_START_TIMEOUT       duration
OBSAGENT_HEALTH_INTERVAL            duration
OBSAGENT_HEALTH_PROBE_TIMEOUT       duration
OBSAGENT_RESTART_ENABLED            bool
OBSAGENT_OTLP_ENDPOINT              OTLP collector base URL
OBSAGENT_OTLP_HEADERS               k=v,k2=v2 ingest headers
OBSAGENT_EXPORT_ENDPOINT            native JSON intake base URL
OBSAGENT_EXPORT_HEADERS             k=v,k2=v2 ingest headers (e.g. X-API-Key)
OBSAGENT_MODULE_<ID>_ENABLED        bool, <ID> uppercased with - as _
```

`OBSAGENT_MODULE_<ID>_ENABLED` can only toggle a module the configuration already
declares. The environment cannot introduce a collector nobody opted into.
