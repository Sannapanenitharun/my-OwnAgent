# otel-engine

OTLP/HTTP receiver for application telemetry on the same host. This is not
auto-instrumentation: apps must export OTLP themselves (or via a library).

## Listen

Default `127.0.0.1:4318`. Only local processes can send. Paths:

- `POST /v1/traces`
- `POST /v1/logs`
- `POST /v1/metrics`

Apps:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

gRPC `:4317` is not implemented. eBPF is not implemented.

## Bounds

| Setting | Default |
|---|---|
| `listen` | `127.0.0.1:4318` |
| `max.body_bytes` | 4 MiB |
| `max.queue` | 256 in-flight requests |

A full queue returns HTTP 429, increments `otel.receiver.dropped`, and records
diagnostic code `dropped`. Payloads are never held in an unbounded buffer.

Host resource attributes are attached by the OTLP **exporter**, not by this
module. The module only forwards through `Telemetry.IngestTraces`.

`export.otlp.endpoint` must not equal this listen address (validated at config
load) or traces would loop.
