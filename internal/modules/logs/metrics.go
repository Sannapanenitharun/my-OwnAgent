package logs

const (
	MetricLines    = "logs.lines"    // attrs: source
	MetricDropped  = "logs.dropped"  // attrs: source, reason
	MetricRedacted = "logs.redacted" // attrs: source
	// MetricLeveled counts lines whose severity was read from the line rather
	// than defaulted. The gap between this and logs.lines is how much of a
	// host's output carries no level at all. Attrs: source, severity.
	MetricLeveled = "logs.leveled" // attrs: source, severity
	// MetricCorrelated counts lines that carried a trace context. It is the
	// measure of whether correlation is actually working: a host where this
	// stays at zero has logs and spans that can never be joined.
	MetricCorrelated         = "logs.correlated"         // attrs: source
	MetricTruncated          = "logs.truncated"          // attrs: source
	MetricCollectionSuccess  = "logs.collection.success" // attrs: source
	MetricCollectionFailure  = "logs.collection.failure" // attrs: source
	MetricCollectionDuration = "logs.collection.duration_seconds"
	MetricModuleHealth       = "logs.module.health"
)
