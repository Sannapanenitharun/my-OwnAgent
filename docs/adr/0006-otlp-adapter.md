# ADR-0006: OTLP/HTTP is the Telemetry Plane stand-in

- **Status:** Accepted
- **Date:** 2026-08-19
- **Stage:** export path (after Stage 3)
- **Supersedes:** none
- **Extends:** [ADR-0001](0001-ports-and-adapters.md)

## Context

ADR-0001 said the agent depends on the platform Telemetry Plane through a port,
and shipped `internal/platform/inproc` as a reference adapter that **terminates
telemetry in memory**. That was correct while collectors were being built. It
is not a product: an agent that collects host metrics and never leaves the box
cannot be installed on AWS as an observability agent.

The user-facing requirement is to ship metrics, logs and traces to **existing**
backends (Grafana Alloy, the OpenTelemetry Collector, Datadog OTLP intake, AWS
Distro for OpenTelemetry). Those backends speak OTLP.

## Decision

1. Extend `platform.Telemetry` additively with `EmitLog` and `IngestTraces`.
   Collectors keep emitting through the port. They do not know OTLP.
2. Add `internal/platform/otlp`, an OTLP/HTTP exporter. Only
   `cmd/observability-agent` constructs it. When `export.otlp.endpoint` is
   empty, the in-process adapter is used alone (tests, `--check`, local UI).
   When it is set, the exporter **wraps** inproc: the local UI still snapshots
   gauges, and the exporter POSTs `/v1/metrics`, `/v1/logs`, `/v1/traces`.
3. Encode OTLP protobuf in this package with the standard library. Third-party
   OTLP libraries are allowlisted **only** here; collectors stay stdlib-only.
4. Resource attributes (`host.id`, `cloud.provider`, `cloud.region`, …) are
   attached at the adapter, from IMDS when resolved. Unresolved fields are
   omitted. Hostnames are never used as `host.id`.

## Consequences

Replacing this adapter with a real Telemetry Plane is still a change to
`buildPorts()` and `internal/platform` only. Modules do not import OTLP.

The exporter bounds queues and drops under back-pressure. It retries transient
HTTP failures with jitter; 4xx (except 429) is not retried. The native exporter
also trips a circuit breaker after repeated failures and optionally writes
failed payloads to a disk spool (`OBSAGENT_EXPORT_SPOOL`, default
`/var/lib/observability-agent/spool` on Unix) for later replay.

gRPC `:4317` (receive and export) remains out of scope under the agent's
zero-third-party-deps constraint: a correct gRPC stack needs generated stubs
and a transport library. Reach gRPC backends through an OTLP collector, or
send OTLP/HTTP to this agent on `:4318`. Native CloudWatch/X-Ray exporters are
out of scope; reach those backends through an OTLP collector.
