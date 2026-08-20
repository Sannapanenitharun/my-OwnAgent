# Logs module

Collects log lines from files, systemd journald (Linux) and the Windows Event
Log, redacts credential-shaped substrings, truncates oversize lines, and emits
`platform.LogRecord`s through the Telemetry port (native JSON and/or OTLP when
export is configured).

## Platform support

| Source | Linux | Windows | macOS |
|---|---|---|---|
| files | yes (syslog/messages defaults + `paths`) | yes (`paths`) | yes |
| journald | yes (scan of `*.journal` files from EOF) | unsupported | unsupported |
| eventlog | unsupported | Application + System | unsupported |

Unsupported sources degrade health; they are not failures.

## Bounds

- `max.line_bytes` (default 16 KiB) — longer lines are truncated and counted.
- `max.bytes_per_s` — read budget per cycle per file.
- `max.files` — glob expansion cap.
- `max.batch` — records emitted per cycle per source.
- File tails **start at EOF** so a restart does not re-ship history. Truncation
  or rotation (size shrinks) resets the offset to 0.

## Redaction

Until the Stage 6 secret-scrubber exists, every body passes through `Redact`:
AWS access key IDs (`AKIA…`), `Bearer` tokens, and `password=` / `secret=` /
`token=` assignments. False positives are accepted; leaks are not.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `interval` | `2s` | collection period |
| `paths` | platform defaults | comma-separated globs |
| `exclude` | empty | basename/glob skip list |
| `event_logs` | `Application,System` | Windows channels |
| `disable.files` / `disable.journald` / `disable.eventlog` | false | turn a source off |

Unknown keys are rejected.
