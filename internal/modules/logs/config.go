package logs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// Source is one log origin. A platform that cannot provide a source reports
// it unsupported rather than emitting empty lines.
type Source string

const (
	SourceFiles    Source = "files"
	SourceJournald Source = "journald"
	SourceEventLog Source = "eventlog"
	// SourceLogins is the login accounting files, btmp and wtmp. It is its
	// own source rather than a path in the files list because the records are
	// fixed-size C structs: the file tailer would ship 384 bytes of NULs and
	// padding per login.
	SourceLogins Source = "logins"
	// SourceLastlog is /var/log/lastlog, which is a TABLE indexed by user ID
	// rather than a stream of events. It is separate from SourceLogins
	// because it answers a different question -- "which accounts have ever
	// been used" -- and because it is the one reader here that reports its
	// contents on first sight instead of starting at the end.
	SourceLastlog Source = "lastlog"
	// SourceArchives reports which binary history archives exist on the host
	// and what window each covers -- atop and sysstat. It reports COVERAGE,
	// not contents: see atop.go for why the payloads are left undecoded.
	SourceArchives Source = "archives"
)

func (s Source) String() string { return string(s) }

var AllSources = []Source{SourceFiles, SourceJournald, SourceEventLog, SourceLogins, SourceLastlog, SourceArchives}

const AttrSource = "source"

// Settings is decoded from config.ModuleConfig.Settings. Unknown keys are
// rejected.
type Settings struct {
	Interval          time.Duration
	CollectionTimeout time.Duration

	Paths   []string
	Exclude []string

	// ExcludeContains drops lines containing any of these substrings, before
	// they are exported. It exists because a single noisy neighbour can make
	// every other line on a host unreadable: one agent writing a syslog line
	// per metric sample per device per cycle buries everything else, and
	// filtering it in the viewer still pays to collect, ship and store it.
	//
	// Dropped lines are counted, never silently discarded.
	ExcludeContains []string

	// DetectSeverity reads the level out of each line instead of stamping
	// every record Info. On by default: a severity column that is always Info
	// makes filtering and alerting inert, and the level is already in the
	// line for klog, logfmt, JSON and syslog output. Turn it off if a format
	// on this host is being read wrongly -- the detector is conservative, but
	// "conservative" is not "infallible".
	DetectSeverity bool

	// DetectTrace reads trace context out of the line, so a log record can
	// name the request it belongs to. On by default: it is the join between
	// logs and spans, it costs one bounded scan of the head of each line, and
	// on a host where nothing is instrumented it simply never matches.
	DetectTrace bool

	MaxLineBytes int
	MaxBytesPerS int

	// MaxFiles caps how many files one collection cycle will open.
	//
	// IT IS A CAP ON THE WHOLE CYCLE, NOT PER PATTERN, and the patterns are
	// walked in order, so a low value does not thin the set evenly -- it
	// truncates it. Everything after the cut is never read at all.
	//
	// The default was 32 when the default path list had four entries. It now
	// has fifteen, and on a container host the docker glob alone can match
	// twenty: a real host measured 62 candidate files, which meant the last
	// nine patterns -- dmesg, the Apache-convention logs, sar reports and the
	// SSM audit trail -- were silently never opened. The files that matter
	// most are still listed first, so the truncation was invisible.
	MaxFiles int
	MaxBatch int

	// DiscoverLogs finds log files by asking which ones processes hold open
	// for writing, instead of tailing only what an operator listed. Off by
	// default: it reads every process's descriptors, and an agent that starts
	// tailing files nobody asked for should be a choice rather than a
	// surprise.
	DiscoverLogs bool

	// DiscoverRoots bounds where discovery is willing to look. Empty selects
	// /var/log. This is a security boundary, not a filter -- see
	// discover_linux.go.
	DiscoverRoots []string

	// DiscoverInterval is how often the descriptor walk runs. Zero selects
	// 60s, which is what OneAgent uses and is far longer than the collection
	// interval on purpose: the set of open log files changes when processes
	// start, not when lines are written.
	DiscoverInterval time.Duration

	// MaxDiscovered caps how many files discovery will add. Zero selects 128.
	MaxDiscovered int

	// LoginFiles overrides which accounting files are read. Empty selects
	// /var/log/btmp and /var/log/wtmp.
	LoginFiles []string

	// LastlogFile overrides the last-login table. Empty selects
	// /var/log/lastlog.
	LastlogFile string

	// ArchivePaths overrides which binary history archives are surveyed.
	// Empty selects atop's and sysstat's directories.
	ArchivePaths []string

	EventLogs []string

	DisabledSources map[Source]bool
}

func DefaultSettings() Settings {
	return Settings{
		Interval:          2 * time.Second,
		DetectSeverity:    true,
		DetectTrace:       true,
		CollectionTimeout: 2 * time.Second,
		MaxLineBytes:      16 * 1024,
		MaxBytesPerS:      256 * 1024,
		MaxFiles:          128,
		MaxBatch:          256,
		EventLogs:         []string{"Application", "System"},
		DisabledSources:   map[Source]bool{},
	}
}

func (s Settings) Clone() Settings {
	out := s
	out.Paths = append([]string(nil), s.Paths...)
	out.Exclude = append([]string(nil), s.Exclude...)
	out.ExcludeContains = append([]string(nil), s.ExcludeContains...)
	out.EventLogs = append([]string(nil), s.EventLogs...)
	// DiscoverRoots and LoginFiles were absent here and aliased the original.
	// Neither is mutated today, so nothing was broken by it -- but a Clone
	// that copies four of six slices is a trap set for whoever adds the
	// mutation.
	out.DiscoverRoots = append([]string(nil), s.DiscoverRoots...)
	out.LoginFiles = append([]string(nil), s.LoginFiles...)
	out.ArchivePaths = append([]string(nil), s.ArchivePaths...)
	out.DisabledSources = make(map[Source]bool, len(s.DisabledSources))
	for k, v := range s.DisabledSources {
		out.DisabledSources[k] = v
	}
	return out
}

func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	if mc.Settings == nil {
		return s, nil
	}
	keys := make([]string, 0, len(mc.Settings))
	for k := range mc.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	known := map[string]bool{
		"interval": true, "collection.timeout": true,
		"paths": true, "exclude": true, "exclude.contains": true,
		"severity.detect": true,
		"trace.detect":    true,
		"max.line_bytes":  true, "max.bytes_per_s": true,
		"max.files": true, "max.batch": true,
		"event_logs":    true,
		"disable.files": true, "disable.journald": true, "disable.eventlog": true,
		"disable.logins": true, "login_files": true,
		"disable.lastlog": true, "lastlog_file": true,
		"disable.archives": true, "archive_paths": true,
		"discover":          true,
		"discover.roots":    true,
		"discover.interval": true,
		"discover.max":      true,
	}
	for _, k := range keys {
		if !known[k] {
			return Settings{}, fmt.Errorf("logs: unknown setting %q", k)
		}
	}

	var err error
	if v, ok := mc.Settings["interval"]; ok {
		s.Interval, err = time.ParseDuration(v)
		if err != nil || s.Interval <= 0 {
			return Settings{}, fmt.Errorf("logs: interval: %w", err)
		}
	}
	if v, ok := mc.Settings["collection.timeout"]; ok {
		s.CollectionTimeout, err = time.ParseDuration(v)
		if err != nil || s.CollectionTimeout <= 0 {
			return Settings{}, fmt.Errorf("logs: collection.timeout: %w", err)
		}
	}
	if v, ok := mc.Settings["paths"]; ok {
		s.Paths = splitList(v)
	}
	if v, ok := mc.Settings["exclude"]; ok {
		s.Exclude = splitList(v)
	}
	if v, ok := mc.Settings["severity.detect"]; ok {
		s.DetectSeverity = parseBool(v)
	}
	if v, ok := mc.Settings["trace.detect"]; ok {
		s.DetectTrace = parseBool(v)
	}
	if v, ok := mc.Settings["exclude.contains"]; ok {
		s.ExcludeContains = splitList(v)
	}
	if v, ok := mc.Settings["event_logs"]; ok {
		s.EventLogs = splitList(v)
	}
	if v, ok := mc.Settings["discover"]; ok {
		s.DiscoverLogs = parseBool(v)
	}
	if v, ok := mc.Settings["discover.roots"]; ok {
		s.DiscoverRoots = splitList(v)
	}
	if v, ok := mc.Settings["discover.interval"]; ok {
		s.DiscoverInterval, err = time.ParseDuration(v)
		if err != nil || s.DiscoverInterval <= 0 {
			return Settings{}, fmt.Errorf("logs: discover.interval: %w", err)
		}
	}
	if v, ok := mc.Settings["discover.max"]; ok {
		s.MaxDiscovered, err = strconv.Atoi(v)
		if err != nil || s.MaxDiscovered <= 0 {
			return Settings{}, fmt.Errorf("logs: discover.max must be a positive integer")
		}
	}
	if v, ok := mc.Settings["max.line_bytes"]; ok {
		s.MaxLineBytes, err = strconv.Atoi(v)
		if err != nil || s.MaxLineBytes <= 0 {
			return Settings{}, fmt.Errorf("logs: max.line_bytes must be a positive integer")
		}
	}
	if v, ok := mc.Settings["max.bytes_per_s"]; ok {
		s.MaxBytesPerS, err = strconv.Atoi(v)
		if err != nil || s.MaxBytesPerS <= 0 {
			return Settings{}, fmt.Errorf("logs: max.bytes_per_s must be a positive integer")
		}
	}
	if v, ok := mc.Settings["max.files"]; ok {
		s.MaxFiles, err = strconv.Atoi(v)
		if err != nil || s.MaxFiles <= 0 {
			return Settings{}, fmt.Errorf("logs: max.files must be a positive integer")
		}
	}
	if v, ok := mc.Settings["max.batch"]; ok {
		s.MaxBatch, err = strconv.Atoi(v)
		if err != nil || s.MaxBatch <= 0 {
			return Settings{}, fmt.Errorf("logs: max.batch must be a positive integer")
		}
	}
	if v, ok := mc.Settings["disable.files"]; ok {
		s.DisabledSources[SourceFiles] = parseBool(v)
	}
	if v, ok := mc.Settings["disable.journald"]; ok {
		s.DisabledSources[SourceJournald] = parseBool(v)
	}
	if v, ok := mc.Settings["disable.eventlog"]; ok {
		s.DisabledSources[SourceEventLog] = parseBool(v)
	}
	if v, ok := mc.Settings["disable.logins"]; ok {
		s.DisabledSources[SourceLogins] = parseBool(v)
	}
	if v, ok := mc.Settings["login_files"]; ok {
		s.LoginFiles = splitList(v)
	}
	if v, ok := mc.Settings["disable.lastlog"]; ok {
		s.DisabledSources[SourceLastlog] = parseBool(v)
	}
	if v, ok := mc.Settings["lastlog_file"]; ok {
		s.LastlogFile = strings.TrimSpace(v)
	}
	if v, ok := mc.Settings["disable.archives"]; ok {
		s.DisabledSources[SourceArchives] = parseBool(v)
	}
	if v, ok := mc.Settings["archive_paths"]; ok {
		s.ArchivePaths = splitList(v)
	}
	return s, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}
