// Package native is the agent's first-party HTTPS JSON exporter.
//
// Collectors emit through platform.Telemetry. They never see this package.
// The entrypoint constructs the adapter when export.native.endpoint is set.
//
// That is the Datadog Agent pattern: collect on the host, batch, compress,
// POST the agent's own JSON to an intake — not OTLP. OTLP remains an optional
// interoperability adapter in internal/platform/otlp.
package native
