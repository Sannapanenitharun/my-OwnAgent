// Package diagnostics defines the agent's structured diagnostic record.
//
// A diagnostic explains why something is not working, or is working in a
// reduced mode. Diagnostics are the mechanism by which the agent refuses to
// fake platform support: an unsupported collector emits an Unsupported
// diagnostic and reports degraded health rather than returning synthetic data.
//
// Security: a Record carries a bounded set of structured attributes and no
// free-form payload from collected data. Diagnostics must never embed collected
// content — in particular never a credential, a log line, a command line or an
// environment variable — because diagnostics are emitted on failure paths that
// predate the secret scrubber in the pipeline.
package diagnostics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity classifies a diagnostic.
type Severity int

const (
	// Info records a normal, notable condition.
	Info Severity = iota
	// Warn records a condition that reduces fidelity but not function.
	Warn
	// Error records a condition that prevents a function from working.
	Error
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return "unknown"
	}
}

// Code is a stable, machine-readable diagnostic identifier. Codes are part of
// the agent's operator-facing contract: runbooks key off them, so they must not
// be renamed once released.
type Code string

const (
	// CodeUnsupported reports functionality unavailable on this platform,
	// kernel or deployment. It is not a failure; it is an honest capability
	// boundary.
	CodeUnsupported Code = "unsupported"
	// CodePermissionDenied reports that the agent lacks a required privilege.
	CodePermissionDenied Code = "permission_denied"
	// CodeUnresolvedIdentity reports that an entity identifier could not be
	// resolved and no identifier was invented.
	CodeUnresolvedIdentity Code = "unresolved_identity"
	// CodeStartFailed reports that a module failed to start.
	CodeStartFailed Code = "start_failed"
	// CodeStopFailed reports that a module failed to stop cleanly.
	CodeStopFailed Code = "stop_failed"
	// CodePanic reports a recovered panic in module code.
	CodePanic Code = "panic"
	// CodeCrashLoop reports that a module exceeded its restart budget and has
	// been quarantined.
	CodeCrashLoop Code = "crash_loop"
	// CodeDependencyUnavailable reports that a module could not start because
	// a dependency is not running.
	CodeDependencyUnavailable Code = "dependency_unavailable"
	// CodeConfigInvalid reports that a configuration was rejected.
	CodeConfigInvalid Code = "config_invalid"
	// CodeConfigRolledBack reports that a configuration apply was reverted.
	CodeConfigRolledBack Code = "config_rolled_back"
	// CodeShutdownTimeout reports that a module did not stop within its
	// deadline.
	CodeShutdownTimeout Code = "shutdown_timeout"
	// CodeHealthTimeout reports that a health probe exceeded its deadline.
	CodeHealthTimeout Code = "health_timeout"
	// CodeDropped reports that telemetry was shed to a bound rather than
	// retained or exported.
	CodeDropped Code = "dropped"
)

// Record is a single diagnostic.
type Record struct {
	// Code is the stable identifier for this condition.
	Code Code
	// Severity classifies the condition.
	Severity Severity
	// Source names the emitting component, typically a module ID.
	Source string
	// Message is a short, operator-readable explanation. It must not embed
	// collected data.
	Message string
	// Remediation is an optional operator action.
	Remediation string
	// Attrs are bounded structured attributes.
	Attrs map[string]string
	// Timestamp is when the condition was observed.
	Timestamp time.Time
}

// String renders a Record for operator-facing logs.
func (r Record) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s source=%s: %s", r.Severity, r.Code, r.Source, r.Message)
	if len(r.Attrs) > 0 {
		keys := make([]string, 0, len(r.Attrs))
		for k := range r.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, r.Attrs[k])
		}
	}
	if r.Remediation != "" {
		fmt.Fprintf(&b, " remediation=%q", r.Remediation)
	}
	return b.String()
}

// Unsupported builds the canonical unsupported diagnostic.
func Unsupported(source, message string) Record {
	return Record{
		Code:        CodeUnsupported,
		Severity:    Warn,
		Source:      source,
		Message:     message,
		Remediation: "no action required; this functionality is unavailable in this environment",
	}
}

// Sink accepts diagnostics. Components depend on this interface rather than on
// *Recorder so that the supervisor can hand each module a scoped sink.
type Sink interface {
	Record(Record)
}

// Scoped returns a Sink that stamps Source on every record it forwards.
//
// Modules are given a scoped sink rather than the raw recorder so that a module
// cannot attribute a diagnostic to another module, accidentally or otherwise.
func Scoped(source string, sink Sink) Sink {
	return scopedSink{source: source, sink: sink}
}

type scopedSink struct {
	source string
	sink   Sink
}

func (s scopedSink) Record(rec Record) {
	rec.Source = s.source
	s.sink.Record(rec)
}

// Recorder collects diagnostics with a bounded retention window.
//
// The bound matters: diagnostics are emitted on failure paths, and a failing
// module can emit at high frequency. An unbounded recorder would convert a
// module fault into an agent memory fault.
type Recorder struct {
	max int

	mu      sync.RWMutex
	records []Record
	// dropped counts records shed to the retention bound.
	dropped int64
	now     func() time.Time
}

// NewRecorder returns a Recorder retaining at most max records. A non-positive
// max selects a default.
func NewRecorder(max int) *Recorder {
	if max <= 0 {
		max = 256
	}
	return &Recorder{max: max, now: time.Now}
}

// SetClock overrides the timestamp source. It is intended for tests.
func (r *Recorder) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Record stores a diagnostic, stamping the timestamp if unset.
func (r *Recorder) Record(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.Timestamp.IsZero() {
		rec.Timestamp = r.now()
	}
	if len(r.records) >= r.max {
		// Drop oldest. Retaining the newest is correct here: during an
		// incident the most recent diagnostics describe the current state.
		copy(r.records, r.records[1:])
		r.records = r.records[:len(r.records)-1]
		r.dropped++
	}
	r.records = append(r.records, rec)
}

// Records returns a copy of the retained diagnostics, oldest first.
func (r *Recorder) Records() []Record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Record, len(r.records))
	copy(out, r.records)
	return out
}

// BySource returns retained diagnostics emitted by a single source.
func (r *Recorder) BySource(source string) []Record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Record
	for _, rec := range r.records {
		if rec.Source == source {
			out = append(out, rec)
		}
	}
	return out
}

// Dropped reports how many diagnostics were shed to the retention bound.
func (r *Recorder) Dropped() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dropped
}
