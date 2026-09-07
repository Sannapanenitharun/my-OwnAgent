# Logs module

Collects log lines from files, systemd journald (Linux), the Windows Event
Log, the login accounting files and the last-login table, redacts
credential-shaped substrings, truncates oversize lines, and emits
`platform.LogRecord`s through the Telemetry port (native JSON and/or OTLP when
export is configured).

## Platform support

| Source | Linux | Windows | macOS |
|---|---|---|---|
| files | yes (syslog/messages defaults + `paths`) | yes (`paths`) | yes |
| journald | yes (scan of `*.journal` files from EOF) | unsupported | unsupported |
| eventlog | unsupported | Application + System | unsupported |
| logins | yes (`btmp` failures, `wtmp` sessions) | unsupported | unsupported |
| lastlog | yes (last-login table, by UID) | unsupported | unsupported |
| archives | yes (atop / sysstat coverage) | unsupported | unsupported |

Unsupported sources degrade health; they are not failures.

### Binary sources

Three of these read fixed-size C structs rather than text, because the data
exists in no other form on the host:

- **logins** — `/var/log/btmp` records failed logins and nothing else does.
  Failures are emitted at warning level; `wtmp` sessions at info.
- **lastlog** — a table indexed by UID, not a stream. It is the only surface
  that answers "which accounts have *never* been used", and it survives the
  `wtmp` rotation that erases the event history. Alone among these readers it
  reports its contents on first sight, because a table has no end to start at.
- **archives** — atop and sysstat write binary history. This reports what
  window each archive **covers**, not its contents: the payloads are raw struct
  dumps whose layout is fixed by the writing binary's build (the header states
  `sstatlen`/`tstatlen` for exactly this reason), and the metrics inside are
  ones the host and process modules already collect live. sysstat's *text*
  `sarNN` reports, which hold the same data readably, are tailed normally.

The file tailer sniffs every newly seen file and refuses any that is not text,
which is what makes the default globs safe to point at directories holding
`wtmp`, `lastlog` and atop archives alongside real logs.

## Bounds

- `max.line_bytes` (default 16 KiB) — longer lines are truncated and counted.
- `max.bytes_per_s` — read budget per cycle per file.
- `max.files` — how many files one cycle may open (default 128). It caps the
  whole cycle, not each pattern, and patterns are read in order: set it below
  the number of files your paths match and the trailing patterns are never
  read at all.
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
| `disable.logins` / `disable.lastlog` / `disable.archives` | false | turn a source off |
| `login_files` | `/var/log/btmp,/var/log/wtmp` | login accounting files |
| `lastlog_file` | `/var/log/lastlog` | last-login table |
| `archive_paths` | atop + sysstat dirs | binary archives to survey |

Unknown keys are rejected.
