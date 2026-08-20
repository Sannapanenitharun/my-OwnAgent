# obsagent-intake

Minimal HTTP sink for the agent's **native** exporter (`obsagent.v1` JSON).

This is a demo / development backend. It is not a production Telemetry Plane.

## Run (same machine or another host)

```bash
go run ./cmd/obsagent-intake -listen 0.0.0.0:8080 -api-key secret -store ./intake-data
```

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/logs` | gzip or plain JSON batch |
| POST | `/v1/metrics` | gzip or plain JSON batch |
| POST | `/v1/traces` | gzip or plain JSON batch |
| GET | `/healthz` | liveness |
| GET | `/` | received counts |

Auth: if `-api-key` / `INTAKE_API_KEY` is set, require header `X-API-Key`.

## Point the agent at it

```json
"export": {
  "native": {
    "endpoint": "http://INTAKE_HOST:8080",
    "compression": "gzip",
    "headers": { "X-API-Key": "secret" }
  }
}
```

Or:

```bash
export OBSAGENT_EXPORT_ENDPOINT=http://INTAKE_HOST:8080
export OBSAGENT_EXPORT_HEADERS='X-API-Key=secret'
```

On EC2, put the intake on a reachable host (another instance, ALB, laptop with
SSH tunnel). Do not point export at the agent's own `otel-engine` listen address.

## Schema

Bodies use `"schema":"obsagent.v1"` with `signal` of `logs` | `metrics` |
`traces`. See [ADR-0007](adr/0007-native-exporter.md).
