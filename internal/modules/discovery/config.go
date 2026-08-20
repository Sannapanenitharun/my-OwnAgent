package discovery

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/platform"
)

// ProcessMode decides which processes become discovery ENTITIES.
//
// This is the single most consequential setting in the module, because it is the
// one that decides whether a ten-thousand-process host produces a ten-thousand
// entity topology. The default is Structural, and the reasoning is worth stating
// in full because it is the Phase 4 analogue of Phase 3's executable rollup.
//
// A process that merely runs is not, on its own, part of the host's structure.
// It has no relationships, nothing points at it, and an operator navigating the
// topology will never arrive at it. Turning it into an entity costs a platform
// resolution, a topology slot, a fingerprint and an event — and buys an entry in
// a list nobody reads. The process module already reports every process, in
// detail, with bounded cardinality.
//
// What IS structural is a process that participates in a relationship: a
// service's main process, a container's process, a listener's owner, or one an
// operator named explicitly. Those are the processes the topology exists to
// connect, and there are tens of them on a host with ten thousand processes.
//
// So the default promotes a process to an entity when EVIDENCE CONNECTS IT TO
// SOMETHING, and counts the rest. The result is that entity count tracks the
// host's structure rather than its process table — which is exactly the property
// that made the process module safe at fifty thousand processes.
type ProcessMode int

const (
	// ProcessModeStructural promotes only processes that participate in a
	// relationship. This is the default.
	ProcessModeStructural ProcessMode = iota
	// ProcessModeAll promotes every enumerated process, still subject to the
	// entity caps. It is for small hosts and for debugging, and the cap is what
	// stops it becoming a cardinality incident on a large one.
	ProcessModeAll
	// ProcessModeNone promotes no processes. Relationships that would have
	// pointed at a process are not emitted, so this also disables endpoint
	// ownership and service membership — which is stated here because it is not
	// obvious from the name.
	ProcessModeNone
)

func (m ProcessMode) String() string {
	switch m {
	case ProcessModeAll:
		return "all"
	case ProcessModeNone:
		return "none"
	default:
		return "structural"
	}
}

func processModeByName(s string) (ProcessMode, bool) {
	switch s {
	case "structural":
		return ProcessModeStructural, true
	case "all":
		return ProcessModeAll, true
	case "none":
		return ProcessModeNone, true
	default:
		return 0, false
	}
}

// Settings is the discovery module's configuration.
//
// It is decoded from config.ModuleConfig.Settings, which the Stage 1 contract
// defines as map[string]string. The flat namespaced key space is a consequence
// of that frozen contract, not a preference; see the note in the process
// module's config.go and docs/review.
//
// Unknown keys are REJECTED. A misspelled cap that is silently ignored is how an
// operator concludes they have bounded an agent's cost when they have not.
type Settings struct {
	Interval          time.Duration
	CollectionTimeout time.Duration

	// ResyncInterval is how often the module re-emits its COMPLETE inventory
	// rather than just what changed.
	//
	// Incremental emission is what keeps a stable host quiet, but a change-only
	// stream that never resynchronises is an inventory that silently rots: one
	// dropped event and a consumer believes in an entity that no longer exists,
	// forever. The resync bounds that staleness to a known interval, and it is
	// the reason the incremental design is safe to run at all.
	ResyncInterval time.Duration

	// Resource limits. Every one has a finite default: there is no
	// configuration of this module in which discovery is unbounded.
	MaxEntities       int
	MaxPerKind        map[platform.EntityKind]int
	MaxRelationships  int
	MaxEventsPerCycle int

	// Domains enables or disables each source.
	Domains map[Domain]bool

	ProcessMode ProcessMode

	CorrelateEndpoints  bool
	MaxFDScans          int
	IncludeLoopback     bool
	IncludePseudoFS     bool
	IncludeVirtualIface bool

	IncludeServices  []string
	ExcludeServices  []string
	ExcludeMounts    []string
	IncludeProcesses []string

	EventsEnabled   bool
	DisabledMetrics map[string]bool

	// UnresolvedRatioDegraded is the fraction of entities that may fail to
	// resolve before the module reports Degraded.
	UnresolvedRatioDegraded float64
}

// defaultPerKind is the per-kind entity budget.
//
// Per-kind caps exist so that one noisy domain cannot consume the global budget
// and evict everything else. A build node that starts ten thousand containers is
// a real thing, and without a per-kind cap those containers would push out the
// services, filesystems and endpoints that an operator actually navigates by —
// leaving a topology that is technically within its limit and practically
// useless.
//
// The numbers are sized from what real hosts have, with headroom, not from what
// would fit: a host with more than 512 systemd units or 1024 listeners is
// unusual enough that reporting the top slice and counting the rest is the
// right answer.
func defaultPerKind() map[platform.EntityKind]int {
	return map[platform.EntityKind]int{
		platform.EntityKindService:          512,
		platform.EntityKindContainer:        512,
		platform.EntityKindNetworkEndpoint:  1024,
		platform.EntityKindNetworkInterface: 256,
		platform.EntityKindFilesystem:       256,
		platform.EntityKindProcess:          1024,
		// The singletons. A cap of one is not defensive programming; it is the
		// assertion that a host has exactly one runtime, one cloud platform and
		// one pod context, so a source that produced two would be reporting
		// something the module should not pass on.
		platform.EntityKindRuntime:       1,
		platform.EntityKindCloudInstance: 1,
		// Pods are NOT a singleton, and the distinction caught a real defect
		// during development: a Kubernetes node runs many pods, and the module
		// discovers every pod that owns a container it can see — not only the
		// one the agent itself is in.
		platform.EntityKindKubernetesPod: 256,
	}
}

// DefaultSettings returns the built-in configuration.
//
// The defaults are chosen for the largest host the module claims to support, and
// for the least surprising behaviour on the smallest.
func DefaultSettings() Settings {
	domains := make(map[Domain]bool, len(AllDomains))
	for _, d := range AllDomains {
		domains[d] = true
	}

	return Settings{
		// Five minutes, not thirty seconds. Topology changes on the timescale of
		// deployments, not of load. Discovering it six times a minute would cost
		// six times as much for a picture that is identical five times out of
		// six — and the module's whole argument is that it is affordable to run
		// continuously.
		Interval:          5 * time.Minute,
		CollectionTimeout: 10 * time.Second,
		// One hour of maximum staleness for a consumer that missed an event.
		// Twelve resyncs a day is a negligible cost and a strong guarantee.
		ResyncInterval: time.Hour,

		MaxEntities:       4096,
		MaxPerKind:        defaultPerKind(),
		MaxRelationships:  8192,
		MaxEventsPerCycle: 500,

		Domains:     domains,
		ProcessMode: ProcessModeStructural,

		// On by default, because endpoint→process ownership is among the most
		// valuable facts discovery produces: it is what turns "port 5432 is
		// open" into "postgres is listening". It is bounded by MaxFDScans
		// because on Linux establishing it costs a descriptor scan.
		CorrelateEndpoints: true,
		MaxFDScans:         1024,
		IncludeLoopback:    true,
		// Off by default: a container host mounts hundreds of pseudo
		// filesystems, one set per container, and none of them is storage.
		IncludePseudoFS: false,
		// Off by default for the same reason: veth pairs outnumber real
		// interfaces by two orders of magnitude on a container host.
		IncludeVirtualIface: false,

		EventsEnabled:           true,
		DisabledMetrics:         map[string]bool{},
		UnresolvedRatioDegraded: 0.5,
	}
}

// Clone returns a deep copy, so that a prepared-but-not-committed configuration
// can never alias the live one.
func (s Settings) Clone() Settings {
	out := s
	out.MaxPerKind = cloneMap(s.MaxPerKind)
	out.Domains = cloneMap(s.Domains)
	out.DisabledMetrics = cloneMap(s.DisabledMetrics)
	out.IncludeServices = append([]string(nil), s.IncludeServices...)
	out.ExcludeServices = append([]string(nil), s.ExcludeServices...)
	out.ExcludeMounts = append([]string(nil), s.ExcludeMounts...)
	out.IncludeProcesses = append([]string(nil), s.IncludeProcesses...)
	return out
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Wants reports whether a domain should be discovered: the operator asked for it
// AND the platform can supply it.
func (s Settings) Wants(d Domain, set Set) bool { return s.Domains[d] && set.Has(d) }

// capacity returns the entity caps as the topology wants them.
func (s Settings) capacity() capacity {
	return capacity{Total: s.MaxEntities, PerKind: s.MaxPerKind}
}

// settingKeys is the complete, closed set of accepted keys.
var settingKeys = func() map[string]bool {
	keys := map[string]bool{
		"interval":                   true,
		"collection.timeout":         true,
		"resync.interval":            true,
		"max_entities":               true,
		"max_relationships":          true,
		"max_events_per_cycle":       true,
		"processes.mode":             true,
		"endpoints.correlate":        true,
		"endpoints.max_fd_scans":     true,
		"endpoints.include_loopback": true,
		"filesystems.include_pseudo": true,
		"interfaces.include_virtual": true,
		"include.services":           true,
		"exclude.services":           true,
		"include.processes":          true,
		"exclude.mountpoints":        true,
		"events.enabled":             true,
		"metrics.disabled":           true,
		"health.unresolved_ratio":    true,
	}
	for _, d := range AllDomains {
		keys["discover."+d.String()] = true
	}
	for _, k := range platform.AllEntityKinds {
		keys["max_entities."+string(k)] = true
	}
	return keys
}()

// ParseSettings decodes and validates a module fragment.
//
// It is total and side-effect free: it touches no OS resource and mutates
// nothing, which is what makes it safe to run against a candidate configuration
// during the prepare phase before deciding whether to commit. Every problem is
// reported, not just the first — an operator fixing a configuration one
// rejection at a time is an operator who reloads six times.
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
			d, err := duration(raw, 10*time.Second, 24*time.Hour)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.Interval = d

		case key == "collection.timeout":
			d, err := duration(raw, time.Second, 5*time.Minute)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.CollectionTimeout = d

		case key == "resync.interval":
			d, err := duration(raw, time.Minute, 24*time.Hour)
			if err != nil {
				fail(key, "%s", err)
				continue
			}
			s.ResyncInterval = d

		case key == "max_entities", key == "max_relationships",
			key == "max_events_per_cycle", key == "endpoints.max_fd_scans":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fail(key, "invalid integer %q", raw)
				continue
			}
			if n < 1 || n > 1000000 {
				fail(key, "must be between 1 and 1000000, got %d", n)
				continue
			}
			switch key {
			case "max_entities":
				// The ceiling is not arbitrary. Each entity costs a platform
				// resolution on first sight and a topology slot for its life,
				// and 65536 of them is roughly 30 MB of resident state on a
				// customer's host — past the point where an inventory is worth
				// what it costs.
				if n > 65536 {
					fail(key, "must be at most 65536; each entity is retained state and a platform resolution")
					continue
				}
				s.MaxEntities = n
			case "max_relationships":
				s.MaxRelationships = n
			case "max_events_per_cycle":
				s.MaxEventsPerCycle = n
			case "endpoints.max_fd_scans":
				s.MaxFDScans = n
			}

		case strings.HasPrefix(key, "max_entities."):
			kind := platform.EntityKind(strings.TrimPrefix(key, "max_entities."))
			if !knownEntityKind(kind) {
				fail(key, "unknown entity kind")
				continue
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				fail(key, "invalid integer %q", raw)
				continue
			}
			if n < 0 || n > 65536 {
				fail(key, "must be between 0 and 65536, got %d", n)
				continue
			}
			s.MaxPerKind[kind] = n

		case key == "processes.mode":
			m, ok := processModeByName(raw)
			if !ok {
				fail(key, "must be one of structural, all, none; got %q", raw)
				continue
			}
			s.ProcessMode = m

		case strings.HasPrefix(key, "discover."):
			d, ok := domainByName(strings.TrimPrefix(key, "discover."))
			if !ok {
				fail(key, "unknown domain")
				continue
			}
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			s.Domains[d] = b

		case key == "endpoints.correlate", key == "endpoints.include_loopback",
			key == "filesystems.include_pseudo", key == "interfaces.include_virtual",
			key == "events.enabled":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fail(key, "invalid boolean %q", raw)
				continue
			}
			switch key {
			case "endpoints.correlate":
				s.CorrelateEndpoints = b
			case "endpoints.include_loopback":
				s.IncludeLoopback = b
			case "filesystems.include_pseudo":
				s.IncludePseudoFS = b
			case "interfaces.include_virtual":
				s.IncludeVirtualIface = b
			case "events.enabled":
				s.EventsEnabled = b
			}

		case key == "include.services":
			s.IncludeServices = splitList(raw)
		case key == "exclude.services":
			s.ExcludeServices = splitList(raw)
		case key == "include.processes":
			s.IncludeProcesses = splitList(raw)
		case key == "exclude.mountpoints":
			s.ExcludeMounts = splitList(raw)

		case key == "health.unresolved_ratio":
			f, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				fail(key, "invalid number %q", raw)
				continue
			}
			if f < 0 || f > 1 {
				fail(key, "must be between 0 and 1, got %v", f)
				continue
			}
			s.UnresolvedRatioDegraded = f

		case key == "metrics.disabled":
			s.DisabledMetrics = map[string]bool{}
			for _, name := range splitList(raw) {
				if !IsKnownMetric(name) {
					fail(key, "unknown metric %q", name)
					continue
				}
				s.DisabledMetrics[name] = true
			}
		}
	}

	// Cross-field validation. These are the combinations that parse but cannot
	// work, and catching them here is the difference between a rejected reload
	// and a module that quietly discovers nothing.
	if s.CollectionTimeout >= s.Interval {
		problems = append(problems, fmt.Sprintf(
			"collection.timeout (%s) must be shorter than interval (%s), or a slow cycle would never finish before the next is due",
			s.CollectionTimeout, s.Interval))
	}
	if s.ResyncInterval < s.Interval {
		problems = append(problems, fmt.Sprintf(
			"resync.interval (%s) must be at least interval (%s); a resync more frequent than discovery itself would emit the same snapshot repeatedly",
			s.ResyncInterval, s.Interval))
	}
	if s.ProcessMode != ProcessModeNone && !s.Domains[DomainProcess] {
		problems = append(problems, fmt.Sprintf(
			"processes.mode is %q but discover.process is false; set processes.mode=none to disable process entities, or enable the domain",
			s.ProcessMode))
	}

	if len(problems) > 0 {
		return Settings{}, fmt.Errorf("discovery: invalid configuration: %s", strings.Join(problems, "; "))
	}
	return s, nil
}

func knownEntityKind(k platform.EntityKind) bool {
	for _, known := range platform.AllEntityKinds {
		if known == k {
			return true
		}
	}
	return false
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

// matchesAny reports whether s contains any of the patterns, case-insensitively.
//
// Substring rather than exact match, because the names that need matching are
// generated: "postgresql@14-main.service", "docker-3aa1....scope". Requiring
// operators to enumerate what they cannot predict produces filters that silently
// match nothing.
func matchesAny(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	lower := strings.ToLower(s)
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

// admitService applies the service filters.
func (s Settings) admitService(name string) bool {
	if matchesAny(name, s.ExcludeServices) {
		return false
	}
	if len(s.IncludeServices) > 0 && !matchesAny(name, s.IncludeServices) {
		return false
	}
	return true
}

// admitMount applies the filesystem filters.
func (s Settings) admitMount(mountpoint string) bool {
	return !matchesAny(mountpoint, s.ExcludeMounts)
}
