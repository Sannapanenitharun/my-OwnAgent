// Package otlp is the OTLP/HTTP adapter for the platform Telemetry port.
//
// Collectors never import this package. The entrypoint constructs it and
// hands it to the agent as platform.Telemetry. Until the enterprise Telemetry
// Plane exists, this adapter is that plane: it translates the agent's
// instruments, log records and ingested traces into OTLP Export* requests
// and POSTs them to a collector (Grafana Alloy, the OpenTelemetry Collector,
// Datadog's OTLP intake, ADOT).
//
// Encoding is implemented here with the standard library. The OTLP protobuf
// schema is encoded by hand so the rest of the agent keeps an empty supply
// chain. See docs/adr/0006-otlp-adapter.md.
package otlp
