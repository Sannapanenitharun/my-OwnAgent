package native

// Trace sampling.
//
// Nothing in the pipeline declined anything. That is fine at the volumes this
// agent produces by itself, and untenable the moment an application is
// instrumented: one busy service can emit more spans in an hour than the agent
// has produced telemetry in its life, and every stage downstream -- the batch,
// the spool, the intake's ring -- would absorb it by dropping whatever arrived
// last. Sampling is the difference between choosing what to keep and finding
// out afterwards what survived.
//
// Two properties matter more than the rate itself:
//
// CONSISTENT. The decision is a function of the trace ID alone, so every span
// of a trace decides the same way -- on this host, on another host, and on a
// later cycle. Sampling per span would keep a scatter of spans from many
// traces, which is the one outcome worse than keeping none: a trace missing
// its middle looks like a broken system rather than a sampled one.
//
// STABLE. The hash is fixed here, not seeded per process. An agent restart
// must not change which traces it keeps, or a trace spanning the restart is
// half recorded.

// sampleAll is the rate at which nothing is dropped and no hashing is done.
const sampleAll = 1.0

// keepTrace reports whether a trace survives sampling at the given rate.
//
// rate >= 1 keeps everything, rate <= 0 keeps nothing, and in between the
// trace is kept when its hash falls in the first `rate` of the space. An
// unparseable or empty ID is KEPT: a span the agent cannot identify is not a
// span it should silently discard, and there are few enough of them that
// keeping them cannot dominate the budget.
func keepTrace(traceID string, rate float64) bool {
	if rate >= sampleAll {
		return true
	}
	if rate <= 0 {
		return false
	}
	if traceID == "" {
		return true
	}
	return float64(traceHash(traceID)%hashSpace)/float64(hashSpace) < rate
}

// hashSpace is the resolution of the sampling decision. 2^24 is far finer than
// any rate an operator would set and keeps the arithmetic in exact float64.
const hashSpace = 1 << 24

// traceHash is FNV-1a over the ID's bytes, lowercased so the same trace hashes
// alike whichever case the exporter wrote it in, followed by an avalanche mix.
//
// FNV rather than anything cryptographic because this is a bucketing decision,
// not a security boundary. The finalizer is not optional, though, and this was
// wrong without it: FNV-1a's LOW bits barely move when inputs share a long
// prefix and differ only near the end, which is exactly what a batch of trace
// IDs from one generator looks like. Taking the low bits of the raw hash sent
// whole runs of such IDs to the same side of the threshold -- forty sequential
// IDs all sampled out together, which reads as "sampling is broken" rather
// than "these forty lost the coin toss".
//
// The finalizer is splitmix64's, which spreads every input bit across the
// whole word before the low bits are read.
func traceHash(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= prime64
	}
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

// sampleSpans filters a decoded batch, dropping whole traces. It returns the
// kept spans and how many were dropped, so the decision is reportable rather
// than invisible -- an operator debugging a missing trace needs to be able to
// tell "sampled out" from "never arrived".
func sampleSpans(spans []spanJSON, rate float64) ([]spanJSON, int) {
	if rate >= sampleAll || len(spans) == 0 {
		return spans, 0
	}
	// One decision per trace, cached, so a batch carrying two hundred spans of
	// one trace hashes once.
	decided := make(map[string]bool, 8)
	kept := spans[:0:0]
	for _, sp := range spans {
		keep, seen := decided[sp.TraceID]
		if !seen {
			keep = keepTrace(sp.TraceID, rate)
			decided[sp.TraceID] = keep
		}
		if keep {
			kept = append(kept, sp)
		}
	}
	return kept, len(spans) - len(kept)
}
