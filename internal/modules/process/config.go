package process

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// Settings is the process module's configuration.
//
// It is decoded from config.ModuleConfig.Settings, which the Stage 1 contract
// defines as map[string]string. A nested structure would read better for the
// include/exclude blocks, but the configuration contract is frozen and a flat
// namespaced key space is expressive enough. That finding, and the smallest
// compatible extension should a later module need real nesting, is recorded in
// docs/review/process-module-readiness.md.
//
// Unknown keys are REJECTED. A misspelled cap that is silently ignored is how an
// operator concludes they have bounded an agent's cost when they have not — and
// on this module, an ignored cap is the difference between a bounded series
// count and a cardinality incident.
type Settings struct {
	Interval          time.Duration
	CollectionTimeout time.Duration

	// Resource limits. Every one of these has a finite default: there is no
	// configuration of this module in which collection is unbounded.
	MaxProcesses      int
	MaxExecutables    int
	MaxEventsPerCycle int
	MaxTracked        int
	ExitRetention     time.Duration

	IncludeNames  []string
	ExcludeNames  []string
	IncludePIDs   []pidRange
	ExcludePIDs   []pidRange
	IncludeUsers  []uint64
	ExcludeUsers  []uint64
	IncludeStates map[State]bool
	ExcludeStates map[State]bool

	MinCPU    float64
	MinMemory uint64

	Collect map[Feature]bool

	EventsEnabled bool
	TopN          int

	DisabledMetrics map[string]bool

	// UnreadableRatioDegraded is the fraction of enumerated processes that may
	// fail to read before the module reports Degraded.
	UnreadableRatioDegraded float64
	// DeniedCountsAsFailure decides whether permission denials feed the health
	// ratio. It defaults to FALSE: on Windows an unelevated agent is denied
	// every other user's process, and on Linux /proc/PID/io is owner-only, so
	// counting denials as failures would report a correctly-configured
	// least-privilege agent as permanently degraded.
	DeniedCountsAsFailure bool
}

// pidRange is an inclusive PID range.
type pidRange struct{ Lo, Hi PID }

func (r pidRange) contains(p PID) bool { return p >= r.Lo && p <= r.Hi }

// DefaultSettings returns the built-in configuration.
//
// The defaults are chosen to be safe on the largest host the module claims to
// support, not on a developer laptop: a 30-second interval, a thousand processes
// carried through to detailed collection, and a hard executable cap that holds
// the series count to a few hundred even on a host running a thousand distinct
// programs.
func DefaultSettings() Settings {
	return Settings{
		// 30 seconds, not 10. Process tables are large and mostly static; the
		// interesting per-process signals (a leak, a runaway) develop over
		// minutes. Collecting three times as often would triple the cost for
		// detail nobody alerts on.
		Interval:          30 * time.Second,
		CollectionTimeout: 2 * time.Second,

		MaxProcesses:      1000,
		MaxExecutables:    128,
		MaxEventsPerCycle: 500,
		// Tracking state for sixteen thousand process instances costs roughly a
		// megabyte and covers every real host; beyond it, state is shed
		// deterministically and the shedding is counted.
		MaxTracked:    16384,
		ExitRetention: 60 * time.Second,

		IncludeStates: map[State]bool{},
		ExcludeStates: map[State]bool{},

		Collect: map[Feature]bool{
			FeatureCPU:     true,
			FeatureMemory:  true,
			FeatureThreads: true,
			FeatureState:   true,
			FeatureIO:      true,
			// Off by default: an extra directory scan per selected process, for
			// a signal most deployments never look at.
			FeatureOpenFiles: false,
			// Off by default: one readlink per selected process, and the result
			// is a filesystem path.
			FeatureExecutablePath: false,
			// OFF BY DEFAULT, AND THIS ONE IS NOT A COST DECISION. Command lines
			// routinely carry credentials passed as arguments. See README.md.
			FeatureCommandLine: false,
			FeatureUser:        false,
		},

		EventsEnabled: true,
		TopN:          0,

		DisabledMetrics: map[string]bool{},

		UnreadableRatioDegraded: 0.10,
		DeniedCountsAsFailure:   false,
	}
}

// Clone returns a deep copy, so that a prepared-but-not-committed configuration
// can never alias the live one.
func (s Settings) Clone() Settings {
	out := s
	out.IncludeNames = append([]string(nil), s.IncludeNames...)
	out.ExcludeNames = append([]string(nil), s.ExcludeNames...)
	out.IncludePIDs = append([]pidRange(nil), s.IncludePIDs...)
	out.ExcludePIDs = append([]pidRange(nil), s.ExcludePIDs...)
	out.IncludeUsers = append([]uint64(nil), s.IncludeUsers...)
	out.ExcludeUsers = append([]uint64(nil), s.ExcludeUsers...)
	out.IncludeStates = cloneMap(s.IncludeStates)
	out.ExcludeStates = cloneMap(s.ExcludeStates)
	out.Collect = cloneMap(s.Collect)
	out.DisabledMetrics = cloneMap(s.DisabledMetrics)
	return out
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Wants reports whether a feature should be collected: the operator asked for it
// AND the platform can supply it.
func (s Settings) Wants(f Feature, set Set) bool { return s.Collect[f] && set.Has(f) }

// settingKeys is the complete, closed set of accepted keys.
var settingKeys = func() map[string]bool {
	keys := map[string]bool{
		"interval":                 true,
		"collection.timeout":       true,
		"max_processes":            true,
		"max_executables":          true,
		"max_events_per_cycle":     true,
		"max_tracked":              true,
		"exit_retention":           true,
		"include.names":            true,
		"exclude.names":            true,
		"include.pids":             true,
		"exclude.pids":             true,
		"include.users":            true,
		"exclude.users":            true,
		"include.states":           true,
		"exclude.states":           true,
		"min.cpu":                  true,
		"min.memory":               true,
		"events.enabled":           true,
		"events.top_n":             true,
		"metrics.disabled":         true,
		"health.unreadable_ratio":  true,
		"health.denied_is_failure": true,
	}
	for _, f := range AllFeatures {
		if f == FeatureEnumeration {
			continue // enumeration is not optional; the module is useless without it
		}
		keys["collect."+f.String()] = true
	}
	return keys
}()

// ParseSettings decodes and validates a module fragment.
//
// It is total and side-effect free: it touches no OS resource and mutates
// nothing, which is what makes it safe to run against a candidate configuration
// during the prepare phase before deciding whether to commit. Every problem is
// reported, not just the first: an operator fixing a configuration one rejection
// at a time is an operator who reloads six times.
func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	var problems []string

	fail := func(key, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s: %s", key, fmt.Sprintf(format, args...)))
	}

	keys := make([]string, 0, len(mc.Settings))
	for k := range mc.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		raw := strings.TrimSpace(mc.Settings[key])
		if !settingKeys[key] {
			fail(key, "unknown setting")
			continue
		}

		switch {
		case key == "interval":
			d, err := duration(raw, time.Second, 24*time.Hour)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.Interval = d

		case key == "collection.timeout":
			d, err := duration(raw, 100*time.Millisecond, 5*time.Minute)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.CollectionTimeout = d

		case key == "exit_retention":
			d, err := duration(raw, 0, time.Hour)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.ExitRetention = d

		case key == "max_processes", key == "max_executables",
			key == "max_events_per_cycle", key == "max_tracked":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fail(key, "invalid integer %q", raw)
				continue
			}
			// The ceilings are not arbitrary. max_executables is the series
			// multiplier: at 4096 distinct executables the module would emit
			// roughly 32,000 series from one host, which is a cardinality
			// incident regardless of what the operator intended.
			if n < 1 || n > 100000 {
				fail(key, "must be between 1 and 100000, got %d", n)
				continue
			}
			switch key {
			case "max_processes":
				s.MaxProcesses = n
			case "max_executables":
				if n > 4096 {
					fail(key, "must be at most 4096; each executable is a set of series")
					continue
				}
				s.MaxExecutables = n
			case "max_events_per_cycle":
				s.MaxEventsPerCycle = n
			case "max_tracked":
				s.MaxTracked = n
			}

		case key == "include.names":
			s.IncludeNames = splitList(raw)
		case key == "exclude.names":
			s.ExcludeNames = splitList(raw)

		case key == "include.pids", key == "exclude.pids":
			ranges, err := parsePIDRanges(raw)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			if key == "include.pids" {
				s.IncludePIDs = ranges
			} else {
				s.ExcludePIDs = ranges
			}

		case key == "include.users", key == "exclude.users":
			var users []uint64
			bad := false
			for _, u := range splitList(raw) {
				v, err := strconv.ParseUint(u, 10, 32)
				if err != nil {
					// Numeric only, and deliberately so: resolving a user NAME
					// means reading the password database or querying a
					// directory service once per process.
					fail(key, "user filters are numeric UIDs; %q is not one", u)
					bad = true
					continue
				}
				users = append(users, v)
			}
			if bad {
				continue
			}
			if key == "include.users" {
				s.IncludeUsers = users
			} else {
				s.ExcludeUsers = users
			}

		case key == "include.states", key == "exclude.states":
			states := map[State]bool{}
			bad := false
			for _, name := range splitList(raw) {
				st, ok := stateByName(name)
				if !ok {
					fail(key, "unknown state %q", name)
					bad = true
					continue
				}
				states[st] = true
			}
			if bad {
				continue
			}
			if key == "include.states" {
				s.IncludeStates = states
			} else {
				s.ExcludeStates = states
			}

		case key == "min.cpu":
			f, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				fail(key, "invalid number %q", raw)
				continue
			}
			if f < 0 || f > 1 {
				fail(key, "is a fraction of total host CPU and must be between 0 and 1, got %v", f)
				continue
			}
			s.MinCPU = f

		case key == "min.memory":
			v, err := parseBytes(raw)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.MinMemory = v

		case key == "events.enabled":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.EventsEnabled = b

		case key == "events.top_n":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fail(key, "invalid integer %q", raw)
				continue
			}
			if n < 0 || n > 100 {
				fail(key, "must be between 0 and 100, got %d", n)
				continue
			}
			s.TopN = n

		case key == "health.unreadable_ratio":
			f, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				fail(key, "invalid number %q", raw)
				continue
			}
			if f < 0 || f > 1 {
				fail(key, "must be between 0 and 1, got %v", f)
				continue
			}
			s.UnreadableRatioDegraded = f

		case key == "health.denied_is_failure":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.DeniedCountsAsFailure = b

		case key == "metrics.disabled":
			s.DisabledMetrics = map[string]bool{}
			for _, name := range splitList(raw) {
				if !IsKnownMetric(name) {
					fail(key, "unknown metric %q", name)
					continue
				}
				s.DisabledMetrics[name] = true
			}

		case strings.HasPrefix(key, "collect."):
			f, ok := featureByName(strings.TrimPrefix(key, "collect."))
			if !ok {
				fail(key, "unknown feature")
				continue
			}
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.Collect[f] = b
		}
	}

	// Cross-field validation. These are the combinations that parse but cannot
	// work, and catching them here is the difference between a rejected reload
	// and a module that quietly collects nothing.
	if s.MaxTracked < s.MaxProcesses {
		problems = append(problems, fmt.Sprintf(
			"max_tracked (%d) must be at least max_processes (%d), or selected processes would lose their counter baselines every cycle",
			s.MaxTracked, s.MaxProcesses))
	}
	if s.CollectionTimeout >= s.Interval {
		problems = append(problems, fmt.Sprintf(
			"collection.timeout (%s) must be shorter than interval (%s), or a slow cycle would never finish before the next is due",
			s.CollectionTimeout, s.Interval))
	}

	if len(problems) > 0 {
		return Settings{}, fmt.Errorf("process: invalid configuration: %s", strings.Join(problems, "; "))
	}
	return s, nil
}

func duration(raw string, min, max time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	if d < min {
		return 0, fmt.Errorf("must be at least %s, got %s", min, d)
	}
	if d > max {
		return 0, fmt.Errorf("must be at most %s, got %s", max, d)
	}
	return d, nil
}

// parseBytes accepts a plain byte count or one with a binary suffix.
func parseBytes(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	mult := uint64(1)
	upper := strings.ToUpper(s)
	for suffix, m := range map[string]uint64{
		"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30,
		"K": 1 << 10, "M": 1 << 20, "G": 1 << 30,
	} {
		if strings.HasSuffix(upper, suffix) {
			// Longest match wins, so "MB" is not read as "B" then "M".
			if mult == 1 || len(suffix) > 1 {
				mult = m
				s = strings.TrimSpace(upper[:len(upper)-len(suffix)])
			}
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q", raw)
	}
	if v > (1<<64-1)/mult {
		return 0, fmt.Errorf("byte size %q overflows", raw)
	}
	return v * mult, nil
}

// parsePIDRanges parses "1-100,500,2000-3000".
func parsePIDRanges(raw string) ([]pidRange, error) {
	var out []pidRange
	for _, part := range splitList(raw) {
		lo, hi, found := strings.Cut(part, "-")
		l, err := strconv.ParseInt(strings.TrimSpace(lo), 10, 32)
		if err != nil || l < 0 {
			return nil, fmt.Errorf("invalid PID %q", lo)
		}
		if !found {
			out = append(out, pidRange{PID(l), PID(l)})
			continue
		}
		h, err := strconv.ParseInt(strings.TrimSpace(hi), 10, 32)
		if err != nil || h < l {
			return nil, fmt.Errorf("invalid PID range %q", part)
		}
		out = append(out, pidRange{PID(l), PID(h)})
	}
	return out, nil
}

// splitList parses a comma-separated list, dropping empty entries. An empty
// string means an empty list, which is how an operator clears a default.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stateByName(name string) (State, bool) {
	for _, st := range AllStates {
		if st.String() == name {
			return st, true
		}
	}
	return 0, false
}
