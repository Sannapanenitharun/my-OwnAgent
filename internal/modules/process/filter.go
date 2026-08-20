package process

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxExecutableNameLen bounds the `executable` attribute's VALUE length.
//
// A cap on the number of distinct values is not enough on its own: a process can
// name itself anything, and on Windows that name can be 260 characters. Emitting
// it verbatim lets an observed process choose how much storage each of its
// series costs downstream.
const maxExecutableNameLen = 64

// sanitiseName makes a kernel-supplied process name safe to use as a telemetry
// attribute value.
//
// PROCESS NAMES ARE ATTACKER-CONTROLLED. A process chooses its own name, and on
// Linux it can rewrite it at any time by writing to its own argv[0] or calling
// prctl(PR_SET_NAME). A name may therefore contain newlines, ANSI escapes, NUL
// bytes, or 260 characters of padding, and it arrives at an agent that is about
// to put it into logs, dashboards and a metrics store.
//
// Three things are done, in order:
//
//  1. Control characters — including the newline that would forge a second log
//     line, and the escape that would reprogram a terminal reading it — are
//     replaced with '_'. They are replaced rather than stripped so that two
//     names differing only in control characters do not collide into one.
//  2. The result is truncated to a fixed length.
//  3. An empty or entirely-invalid name becomes the sentinel "unknown", which is
//     a bounded value the operator can see and act on.
//
// The second return value reports whether anything was changed, so the caller
// can count how often it happens: a sudden rise is itself a signal worth having.
func sanitiseName(name string) (string, bool) {
	if name == "" {
		return "unknown", true
	}

	// Fast path. The overwhelming majority of process names are already clean
	// ASCII, and this function runs once per process per cycle — fifty thousand
	// times on a large host. Scanning for a reason to rewrite, and returning the
	// original when there is none, removes an allocation per process.
	if len(name) <= maxExecutableNameLen {
		plain := true
		for i := 0; i < len(name); i++ {
			// Non-ASCII falls through to the slow path rather than being
			// rejected: a name may legitimately be UTF-8, and the slow path
			// preserves it. Only the common case is optimised.
			if c := name[i]; c < 0x20 || c == 0x7f || c >= utf8.RuneSelf {
				plain = false
				break
			}
		}
		if plain && strings.TrimSpace(name) != "" {
			return name, false
		}
	}

	clean := name
	modified := false

	if !utf8.ValidString(clean) {
		// Invalid UTF-8 would be rejected or mangled unpredictably by whatever
		// consumes it downstream. Coercing it here makes the outcome the
		// agent's decision rather than a surprise three systems away.
		clean = strings.ToValidUTF8(clean, "_")
		modified = true
	}

	var b strings.Builder
	for _, r := range clean {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r):
			b.WriteByte('_')
			modified = true
		default:
			b.WriteRune(r)
		}
	}
	clean = b.String()

	// Truncated on a rune boundary: cutting a multi-byte rune in half would
	// produce exactly the invalid UTF-8 the step above just removed.
	if len(clean) > maxExecutableNameLen {
		cut := maxExecutableNameLen
		for cut > 0 && !utf8.RuneStart(clean[cut]) {
			cut--
		}
		clean = clean[:cut]
		modified = true
	}

	if strings.TrimSpace(clean) == "" {
		return "unknown", true
	}
	return clean, modified
}

// matchesAny reports whether name contains any of the substrings,
// case-insensitively.
//
// Substring rather than exact match, because the names that need matching are
// generated: "postgres: writer process", "java" versus "java.exe". Requiring
// operators to enumerate what they cannot predict produces filters that silently
// match nothing.
func matchesAny(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func inRanges(pid PID, ranges []pidRange) bool {
	for _, r := range ranges {
		if r.contains(pid) {
			return true
		}
	}
	return false
}

func inUsers(uid U64, users []uint64) bool {
	if !uid.OK {
		return false
	}
	for _, u := range users {
		if u == uid.V {
			return true
		}
	}
	return false
}

// acceptPID is the CHEAP pre-filter, evaluated before any per-process read.
//
// It can only use the PID, because that is all that is known before the read —
// which is precisely why it is worth having: on a host with include.pids
// configured, it turns fifty thousand file reads into a handful.
func (s Settings) acceptPID(pid PID) bool {
	if len(s.ExcludePIDs) > 0 && inRanges(pid, s.ExcludePIDs) {
		return false
	}
	if len(s.IncludePIDs) > 0 && !inRanges(pid, s.IncludePIDs) {
		return false
	}
	return true
}

// explicitlyIncluded reports whether the operator named this process. Such
// processes rank above everything else during selection, so that a host over its
// cap never sheds the processes it was configured to watch.
func (s Settings) explicitlyIncluded(o *observation) bool {
	if len(s.IncludeNames) > 0 && matchesAny(o.Name, s.IncludeNames) {
		return true
	}
	if len(s.IncludePIDs) > 0 && inRanges(o.PID, s.IncludePIDs) {
		return true
	}
	if len(s.IncludeUsers) > 0 && inUsers(o.UID, s.IncludeUsers) {
		return true
	}
	return false
}

// admit applies the full filter set to one observation.
//
// Ordering is by cost: the string comparisons run before the derived-value
// comparisons only because both are cheap here — the genuinely expensive reads
// have already been deferred past this point by the collection cycle.
func (s Settings) admit(o *observation) bool {
	if matchesAny(o.Name, s.ExcludeNames) {
		return false
	}
	if len(s.IncludeNames) > 0 && !matchesAny(o.Name, s.IncludeNames) {
		return false
	}
	if len(s.ExcludeStates) > 0 && s.ExcludeStates[o.State] {
		return false
	}
	if len(s.IncludeStates) > 0 && !s.IncludeStates[o.State] {
		return false
	}
	if len(s.ExcludeUsers) > 0 && inUsers(o.UID, s.ExcludeUsers) {
		return false
	}
	if len(s.IncludeUsers) > 0 && !inUsers(o.UID, s.IncludeUsers) {
		return false
	}

	// Threshold filters are applied only when the value is KNOWN. A process
	// whose CPU could not be read must not be silently dropped by a min.cpu
	// filter — that would make an unreadable process indistinguishable from an
	// idle one.
	if s.MinCPU > 0 && o.HasCPU && o.CPUUtilization < s.MinCPU {
		return false
	}
	if s.MinMemory > 0 && o.RSSBytes.OK && o.RSSBytes.V < s.MinMemory {
		return false
	}
	return true
}

// criticalPID reports whether a PID belongs to the kernel or to init.
//
// Every supported platform puts them in the lowest few slots: 0 and 1 and 2 on
// Linux (swapper, init, kthreadd), 0 and 1 on Darwin (kernel_task, launchd), 0
// and 4 on Windows (Idle, System). Ranking them above ordinary processes means a
// host at its cap never sheds the processes whose absence would be alarming.
func criticalPID(p PID) bool { return p <= 4 }

// selectionRank orders processes for the max_processes cap. Lower is kept first.
func (s Settings) selectionRank(o *observation) int {
	switch {
	case s.explicitlyIncluded(o):
		return 0
	case criticalPID(o.PID):
		return 1
	default:
		return 2
	}
}

// selectProcesses applies the max_processes cap DETERMINISTICALLY.
//
// The ordering is: configured processes, then kernel and init, then by CPU, then
// by memory, then by name and PID. The final two keys exist so that the result
// is total: without them, a host with a thousand identical idle processes would
// report a different subset every cycle, producing a churn of half-populated
// series that is worse than reporting nothing at all.
//
// Nothing is sampled and nothing is dropped silently: the count that did not fit
// is returned so the caller can emit it.
func (s Settings) selectProcesses(in []*observation) (kept []*observation, dropped int) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if ra, rb := s.selectionRank(a), s.selectionRank(b); ra != rb {
			return ra < rb
		}
		if a.HasCPU != b.HasCPU {
			return a.HasCPU // a known value ranks above an unknown one
		}
		if a.HasCPU && a.CPUUtilization != b.CPUUtilization {
			return a.CPUUtilization > b.CPUUtilization
		}
		if a.RSSBytes.OK != b.RSSBytes.OK {
			return a.RSSBytes.OK
		}
		if a.RSSBytes.OK && a.RSSBytes.V != b.RSSBytes.V {
			return a.RSSBytes.V > b.RSSBytes.V
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.PID < b.PID
	})

	if s.MaxProcesses > 0 && len(in) > s.MaxProcesses {
		return in[:s.MaxProcesses], len(in) - s.MaxProcesses
	}
	return in, 0
}

// selectExecutables applies the max_executables cap to the rollup.
//
// This is the cap that actually bounds series count, so it is applied to the
// aggregated result rather than to the input: selecting processes first and
// hoping the executable count follows would leave the series count at the mercy
// of how many distinct programs happened to be running.
//
// Ordering is by instance count, then CPU, then memory, then name. Instance
// count leads because an executable running five hundred copies is the one an
// operator most wants to see, regardless of whether any single copy is busy.
func selectExecutables(in []*rollup, max int) (kept []*rollup, dropped int) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Instances != b.Instances {
			return a.Instances > b.Instances
		}
		if a.CPUUtilization != b.CPUUtilization {
			return a.CPUUtilization > b.CPUUtilization
		}
		if a.RSSBytes != b.RSSBytes {
			return a.RSSBytes > b.RSSBytes
		}
		return a.Name < b.Name
	})

	if max > 0 && len(in) > max {
		return in[:max], len(in) - max
	}
	return in, 0
}
