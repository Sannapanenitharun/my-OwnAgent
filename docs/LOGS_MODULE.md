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
| syslog | yes (RFC 3164 + 5424 over TCP/UDP) | yes | yes |

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

## Multi-line records

A log record is not always a line. A stack trace is one event written as forty
lines, and shipping it line-by-line produces forty records that cannot be read
without each other.

`multiline` defaults to `auto`, which is safe to default on because it does not
aggregate until it has established, **per file**, that the file's lines really
do start with timestamps: it samples the first 500 lines (or 30 seconds),
emitting them unchanged meanwhile, and enables aggregation only if at least half
of them begin with a recognised record start. A file that fails that test — an
access log, `dmesg`, single-line JSON — is read exactly as before.

That gate is the whole safety argument. Ungated, the rule "a line that does not
start a record continues the previous one" collapses a file with no timestamps
into one unbounded record, which destroys data rather than fragmenting it.

Set `multiline: pattern` with `multiline.pattern` to decide boundaries with your
own regex; it must match at the **start** of a line. `multiline: off` disables
the whole thing. Accumulated records are bounded at 500 lines and 256 KiB and
are **split, not truncated**, when they exceed either.

## Encoding

`encoding` defaults to `auto`, which reads the byte-order mark. This is also
what stops UTF-16 files from being mistaken for binary — their ASCII content is
half NUL bytes, and the binary guard that protects against `wtmp` would
otherwise drop them silently and entirely. A UTF-16 file with **no** BOM must be
declared with `encoding: utf-16-le` or `utf-16-be`; undeclared and unmarked, it
is indistinguishable from a binary file. Shift-JIS is not supported.

## Syslog receiver

Off unless `syslog.listen` is set, and that default is a security posture, not
a convenience: the port accepts unauthenticated writes into the log pipeline
from anyone who can reach it. Bind loopback unless the senders are genuinely
remote, and firewall it when they are.

Both RFC 3164 and RFC 5424 are parsed, and on TCP both RFC 6587 framings
(octet-counted and newline-delimited) are accepted on the same connection.
Anything that fails to parse is forwarded as an unstructured message rather than
dropped. The queue holds 8192 records; past that the **oldest** are dropped and
counted, because a relay backlog is stale by definition.

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
| `include.match` / `exclude.match` | empty | regex line filters; include is evaluated first |
| `multiline` | `auto` | `off`, `auto` or `pattern` |
| `multiline.pattern` | empty | regex, must match at line start |
| `multiline.timeout` | `5s` | how long a partial record waits; must exceed `interval` |
| `start_position` | `end` | `end` or `beginning` for newly seen files |
| `encoding` | `auto` | `auto`, `utf-8`, `utf-16-le`, `utf-16-be` |
| `syslog.listen` | empty (off) | `host:port` for the syslog receiver |
| `syslog.protocol` | `both` | `udp`, `tcp` or `both` |
| `event_logs` | `Application,System` | Windows channels |
| `disable.files` / `disable.journald` / `disable.eventlog` | false | turn a source off |
| `disable.logins` / `disable.lastlog` / `disable.archives` | false | turn a source off |
| `login_files` | `/var/log/btmp,/var/log/wtmp` | login accounting files |
| `lastlog_file` | `/var/log/lastlog` | last-login table |
| `archive_paths` | atop + sysstat dirs | binary archives to survey |

Unknown keys are rejected.
