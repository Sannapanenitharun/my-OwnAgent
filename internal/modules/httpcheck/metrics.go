package httpcheck

const (
	MetricUp                 = "httpcheck.up"                 // 1=ok, 0=fail; attrs: target
	MetricLatency            = "httpcheck.latency_seconds"    // attrs: target
	MetricStatusCode         = "httpcheck.status_code"        // attrs: target
	MetricCollectionSuccess  = "httpcheck.collection.success" // attrs: target
	MetricCollectionFailure  = "httpcheck.collection.failure" // attrs: target
	MetricCollectionDuration = "httpcheck.collection.duration_seconds"
)

const AttrTarget = "target"
