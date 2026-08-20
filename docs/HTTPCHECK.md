# HTTP check collector

Probes configured HTTP(S) endpoints and emits gauges through the Telemetry
port. This is the smallest custom **agent-based data collector** on the binary:
one goroutine, bounded targets, stdlib only.

## Enable

```json
"httpcheck": {
  "enabled": true,
  "settings": {
    "interval": "30s",
    "timeout": "5s",
    "expect_status": "200",
    "targets": "ui=http://127.0.0.1:8181/,app=https://example.com/health"
  }
}
```

`targets` is a comma-separated list of `name=url` (or bare URLs; name becomes
the host). At most 32 targets. Timeout must be less than interval.

With no targets, Start returns unsupported (module disabled in practice).

## Metrics

| Name | Type | Attrs |
|---|---|---|
| `httpcheck.up` | gauge 0/1 | `target` |
| `httpcheck.latency_seconds` | gauge | `target` |
| `httpcheck.status_code` | gauge | `target` |
| `httpcheck.collection.success` / `.failure` | counter | `target` |

These leave the host via `export.native` and/or `export.otlp` like every other
collector.
