package logs

import (
	"regexp"
	"strings"
	"time"
)

// Multi-line aggregation.
//
// THE PROBLEM. A file tailer reads lines, but a log RECORD is not always a
// line. A Java stack trace is one event written as forty lines; shipped
// line-by-line it becomes forty records, thirty-nine of which say
// "at com.foo.Bar(Bar.java:42)" and none of which can be read without the
// others. Both commercial agents solve this and we did not, which made it the
// largest correctness gap in the collector: not a missing surface, but damage
// to surfaces already collected.
//
// THE DANGER, which is why this is gated rather than simply switched on. The
// aggregation rule is "a line that starts a record begins a new one; anything
// else continues the previous". Applied to a file whose lines do not start
// with anything recognisable, EVERY line is a continuation and the whole file
// collapses into one unbounded record. That failure is worse than the problem
// it fixes, because it destroys data rather than fragmenting it.
//
// THE GATE. So detection runs first, per file, and mirrors what Datadog
// documents: sample the first `detectSamples` lines or `detectWindow`,
// whichever comes first, emitting them as single lines meanwhile; enable
// aggregation only if at least `detectThresholdPct` of the sampled lines begin
// with a recognisable record start. A file that fails detection is never
// aggregated, and the decision is made once.
//
// This means the pathological case cannot arise: a file with no timestamps
// scores 0% and is left alone forever.
type multiline struct {
	states map[string]*mlFile
	now    func() time.Time
}

type mlFile struct {
	// Detection, decided once.
	decided   bool
	aggregate bool
	sampled   int
	matched   int
	firstSeen time.Time

	// The record being accumulated, if any.
	pending  *Record
	buf      strings.Builder
	lines    int
	lastAdd  time.Time
	patternV string // the pattern this pending was started under
}

const (
	// detectSamples and detectWindow bound the detection phase. Datadog
	// documents "at most 30 seconds or the first 500 logs, whichever comes
	// first" and there is no reason to differ: it is long enough to see a
	// file's shape and short enough that aggregation starts while the
	// operator is still watching.
	detectSamples = 500
	detectWindow  = 30 * time.Second

	// detectThresholdPct is how much of a file must look like timestamped
	// records before aggregation is trusted. Half is deliberately permissive
	// on the aggregate side: a file of stack traces can easily be more
	// continuation lines than start lines, and demanding a majority of STARTS
	// would refuse exactly the files that need this most.
	detectThresholdPct = 50

	// maxMultilineLines and maxMultilineBytes bound one accumulated record.
	// Hitting either flushes what has been gathered and starts a fresh record
	// rather than discarding the overflow -- a truncated record loses data, a
	// split one only loses the fact that it was contiguous.
	maxMultilineLines = 500
	maxMultilineBytes = 256 << 10

	// maxMultilineFiles bounds how many files carry aggregation state.
	maxMultilineFiles = 1024
)

func newMultiline() *multiline {
	return &multiline{states: map[string]*mlFile{}, now: time.Now}
}

// Process folds a batch of records, aggregating those that belong to the file
// source. Records from every other source pass through untouched: a journald
// entry is already a whole message, and the login, lastlog and archive readers
// synthesise their lines rather than reading them.
func (m *multiline) Process(recs []Record, s Settings) []Record {
	mode := s.Multiline
	if mode == MultilineOff {
		// Anything still held from before the setting changed must not be
		// stranded in memory.
		return append(m.flushAll(), recs...)
	}
	out := make([]Record, 0, len(recs))
	for _, rec := range recs {
		if rec.Source != SourceFiles || rec.File == "" {
			out = append(out, rec)
			continue
		}
		out = append(out, m.add(rec, s)...)
	}
	return out
}

func (m *multiline) add(rec Record, s Settings) []Record {
	st := m.states[rec.File]
	if st == nil {
		st = &mlFile{firstSeen: m.now()}
		m.states[rec.File] = st
	}

	starts := recordStarts(rec.Body, s)

	// Detection phase: count, and emit unchanged. Datadog does the same --
	// "during the initial detection process, the logs are sent as single
	// lines" -- and the alternative, buffering until a verdict, would delay
	// every line on every new file by up to the whole detection window.
	if !st.decided {
		st.sampled++
		if starts {
			st.matched++
		}
		if st.sampled >= detectSamples || m.now().Sub(st.firstSeen) >= detectWindow {
			st.decided = true
			st.aggregate = st.matched*100 >= st.sampled*detectThresholdPct
		}
		return []Record{rec}
	}
	if !st.aggregate {
		return []Record{rec}
	}

	var out []Record

	// An explicit pattern that has been edited invalidates whatever is held
	// under the old one; flushing it is more honest than appending to it.
	if st.pending != nil && st.patternV != s.MultilinePattern {
		out = append(out, m.flushFile(rec.File)...)
	}

	if starts || st.pending == nil {
		out = append(out, m.flushFile(rec.File)...)
		st = m.states[rec.File]
		clone := rec
		st.pending = &clone
		st.buf.Reset()
		st.buf.WriteString(rec.Body)
		st.lines = 1
		st.lastAdd = m.now()
		st.patternV = s.MultilinePattern
		return out
	}

	// A continuation. The newline is kept so a stack trace still reads as one
	// when it is rendered.
	if st.lines >= maxMultilineLines || st.buf.Len()+len(rec.Body)+1 > maxMultilineBytes {
		out = append(out, m.flushFile(rec.File)...)
		st = m.states[rec.File]
		clone := rec
		st.pending = &clone
		st.buf.Reset()
		st.buf.WriteString(rec.Body)
		st.lines = 1
		st.lastAdd = m.now()
		st.patternV = s.MultilinePattern
		return out
	}
	st.buf.WriteByte('\n')
	st.buf.WriteString(rec.Body)
	st.lines++
	st.lastAdd = m.now()
	return out
}

// FlushIdle releases records whose continuation never arrived.
//
// It is called at the top of each collection cycle rather than on a timer of
// its own: the last record of a quiet file would otherwise sit in memory
// indefinitely, which turns "the log is late" into "the log is missing".
func (m *multiline) FlushIdle(s Settings) []Record {
	if s.Multiline == MultilineOff {
		return m.flushAll()
	}
	timeout := s.MultilineTimeout
	if timeout <= 0 {
		timeout = defaultMultilineTimeout
	}
	now := m.now()
	var out []Record
	for path, st := range m.states {
		if st.pending == nil {
			continue
		}
		if now.Sub(st.lastAdd) >= timeout {
			out = append(out, m.flushFile(path)...)
		}
	}
	m.sweep()
	return out
}

func (m *multiline) flushFile(path string) []Record {
	st := m.states[path]
	if st == nil || st.pending == nil {
		return nil
	}
	rec := *st.pending
	rec.Body = st.buf.String()
	st.pending = nil
	st.buf.Reset()
	st.lines = 0
	return []Record{rec}
}

func (m *multiline) flushAll() []Record {
	var out []Record
	for path := range m.states {
		out = append(out, m.flushFile(path)...)
	}
	return out
}

// sweep bounds the state map.
//
// One entry is kept per file path ever seen, and a host that rotates through
// dated filenames produces a new path every day. Entries are small, but
// unbounded is unbounded, so once there are more than maxMultilineFiles the
// ones holding nothing are dropped. Only the detection verdict is lost, and
// re-deciding it costs a few hundred lines of counting.
func (m *multiline) sweep() {
	if len(m.states) <= maxMultilineFiles {
		return
	}
	for path, st := range m.states {
		if st.pending == nil {
			delete(m.states, path)
		}
	}
}

// recordStarts reports whether a line begins a new record.
func recordStarts(line string, s Settings) bool {
	if s.Multiline == MultilinePattern {
		re := compiledMultilinePattern(s.MultilinePattern)
		if re == nil {
			return false
		}
		// Datadog is explicit that "patterns cannot be matched mid-line", and
		// the same rule holds here: an anchored match is the difference
		// between "this line starts a record" and "this line mentions a date".
		loc := re.FindStringIndex(line)
		return loc != nil && loc[0] == 0
	}
	return startsWithTimestamp(line)
}

// compiledMultilinePattern caches the last compiled pattern. Settings are
// re-read every cycle and recompiling a regex per line would dominate the cost
// of reading the file.
var (
	lastPatternSrc string
	lastPatternRe  *regexp.Regexp
	lastPatternBad bool
)

func compiledMultilinePattern(src string) *regexp.Regexp {
	if src == "" {
		return nil
	}
	if src == lastPatternSrc {
		if lastPatternBad {
			return nil
		}
		return lastPatternRe
	}
	re, err := regexp.Compile(src)
	lastPatternSrc = src
	lastPatternRe, lastPatternBad = re, err != nil
	if err != nil {
		return nil
	}
	return re
}

// matchesInclude reports whether a line survives an include pattern. An empty
// pattern includes everything, which is what makes the filter optional.
func matchesInclude(line, pattern string) bool {
	if pattern == "" {
		return true
	}
	re := compiledFilter(pattern)
	if re == nil {
		// A pattern that will not compile is rejected at config load, so
		// reaching here means the setting was changed underneath us. Passing
		// the line through is the safe failure: dropping every line because a
		// regex is broken loses data that cannot be recovered.
		return true
	}
	return re.MatchString(line)
}

// matchesExclude reports whether a line should be dropped.
func matchesExclude(line, pattern string) bool {
	if pattern == "" {
		return false
	}
	re := compiledFilter(pattern)
	if re == nil {
		return false
	}
	return re.MatchString(line)
}

// compiledFilter caches compiled include/exclude expressions. The cache is
// keyed by source text and holds both, because the two are almost always used
// together and a single-entry cache would thrash between them.
var filterCache = map[string]*regexp.Regexp{}

func compiledFilter(src string) *regexp.Regexp {
	if re, ok := filterCache[src]; ok {
		return re
	}
	re, err := regexp.Compile(src)
	if err != nil {
		re = nil
	}
	// Bounded: the set of configured patterns is small and changes only when
	// an operator edits the config, but a nil entry still records the failure
	// so a broken pattern is not recompiled once per line.
	if len(filterCache) < 64 {
		filterCache[src] = re
	}
	return re
}
