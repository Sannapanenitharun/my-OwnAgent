package logs

const (
	MetricLines              = "logs.lines"              // attrs: source
	MetricDropped            = "logs.dropped"            // attrs: source, reason
	MetricRedacted           = "logs.redacted"           // attrs: source
	MetricTruncated          = "logs.truncated"          // attrs: source
	MetricCollectionSuccess  = "logs.collection.success" // attrs: source
	MetricCollectionFailure  = "logs.collection.failure" // attrs: source
	MetricCollectionDuration = "logs.collection.duration_seconds"
	MetricModuleHealth       = "logs.module.health"
)
