# ADR-0007: First-party HTTPS JSON exporter

- **Status:** Accepted
- **Date:** 2026-08-19
- **Stage:** export path
- **Supersedes:** none
- **Extends:** [ADR-0001](0001-ports-and-adapters.md), [ADR-0006](0006-otlp-adapter.md)

## Context

Datadog's Agent does not ship host logs and traces as OTLP. It collects on the
host, then a first-party writer POSTs compressed JSON (logs) or proprietary
protobuf (APM) to Datadog intake. OTLP on the Agent is an *ingest* option for
apps, not the export path.

ADR-0006 added OTLP so this agent could talk to existing collectors. That is
still useful. It is not how Datadog's own Agent leaves the box, and it is not
the product the operator asked for when they said they wanted their own
exporter.

## Decision

1. Add `internal/platform/native`. Only `cmd/observability-agent` constructs it.
2. When `export.native.endpoint` is set, wrap inproc and POST gzip JSON to
   `{endpoint}/v1/logs`, `/v1/metrics`, `/v1/traces`. Payload schema is
   `obsagent.v1` (message/status/source for logs; gauges/counters/histograms
   for metrics; decoded OTLP JSON spans or base64 raw for traces).
3. Collectors stay unaware. They keep calling `EmitLog` / gauges /
   `IngestTraces`.
4. OTLP remains optional. Both adapters may wrap the same inproc sink.
5. API keys travel as HTTP headers via config `headers` or
   `OBSAGENT_EXPORT_HEADERS`. There is no credential field on the config model
   beyond that existing header map.

## Consequences

Replacing this writer with a real Telemetry Plane is still a `buildPorts()`
change. Intake must accept `obsagent.v1` JSON (or sit behind a translator).
Protobuf inbound traces that are not JSON are forwarded as `raw` rather than
silently dropped.
