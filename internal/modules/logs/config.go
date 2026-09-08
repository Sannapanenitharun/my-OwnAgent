package logs

import (
	"fmt"
	"net"
	"regexp"
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
	// SourceSyslog is the network listener. It is the only source here whose
	// input is chosen by a third party, and it is off unless an address is
	// configured.
	SourceSyslog Source = "syslog"
)

func (s Source) String() string { return string(s) }

// MultilineMode selects how physical lines are folded into records.
//
// Auto is the default. It is safe to default on because it does not aggregate
// until it has established, per file, that the file's lines actually start
// with timestamps -- see multiline.go. A file that fails that test is read
// exactly as it was before this existed.
type MultilineMode string

const (
	MultilineOff     MultilineMode = "off"
	MultilineAuto    MultilineMode = "auto"
	MultilinePattern MultilineMode = "pattern"
)

// defaultMultilineTimeout is how long a partially accumulated record waits for
// its continuation.
//
// It must exceed the collection interval, or a record split across a cycle
// boundary would be flushed before the rest of it was ever read. Five seconds
// against a two-second interval leaves room for the interval to be raised
// under memory pressure, which multiplies it by up to eight.
const defaultMultilineTimeout = 5 * time.Second

// SyslogProtocol selects which transports the receiver binds.
type SyslogProtocol string

const (
	SyslogUDP  SyslogProtocol = "udp"
	SyslogTCP  SyslogProtocol = "tcp"
	SyslogBoth SyslogProtocol = "both"
)

// StartPosition decides where a newly seen file is read from.
type StartPosition string

const (
	// StartEnd is the default and the safe one: a restart does not re-ship
	// history it has already sent.
	StartEnd StartPosition = "end"
	// StartBeginning reads a file from byte zero the first time it is seen.
	// It is for onboarding a host whose logs predate the agent, and it will
	// re-send everything if the agent restarts, because offsets are held in
	// memory only.
	StartBeginning StartPosition = "beginning"
)

// Encoding names the character encoding of a log file.
type Encoding string

const (
	// EncodingAuto reads the byte-order mark and falls back to UTF-8.
	EncodingAuto    Encoding = "auto"
	EncodingUTF8    Encoding = "utf-8"
	EncodingUTF16LE Encoding = "utf-16-le"
	EncodingUTF16BE Encoding = "utf-16-be"
)

var AllSources = []Source{SourceFiles, SourceJournald, SourceEventLog, SourceLogins, SourceLastlog, SourceArchives, SourceSyslog}

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

	// Multiline folds continuation lines into the record they belong to. See
	// MultilineMode.
	Multiline        MultilineMode
	MultilinePattern string
	MultilineTimeout time.Duration

	// StartPosition applies to newly seen files only; a file already being
	// followed keeps its offset.
	StartPosition StartPosition

	// Encoding of log files. Auto sniffs the byte-order mark, which is also
	// what keeps UTF-16 files from being mistaken for binary: their ASCII
	// text is half NUL bytes.
	Encoding Encoding

	// IncludeMatch and ExcludeMatch are regular expressions applied to each
	// line. Include, when set, keeps only lines that match; Exclude drops
	// lines that match. Include is evaluated first, so a line must survive
	// both.
	IncludeMatch string
	ExcludeMatch string

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

	// SyslogListen is the address the syslog receiver binds, "host:port".
	// EMPTY DISABLES IT, and that is the default: this port accepts
	// unauthenticated writes into the log pipeline from anyone who can reach
	// it. Prefer a loopback address unless the senders are genuinely remote.
	SyslogListen string

	// SyslogProtocol selects udp, tcp or both. Empty selects both.
	SyslogProtocol SyslogProtocol

	EventLogs []string

	DisabledSources map[Source]bool
}

func DefaultSettings() Settings {
	return Settings{
		Interval:          2 * time.Second,
		Multiline:         MultilineAuto,
		MultilineTimeout:  defaultMultilineTimeout,
		StartPosition:     StartEnd,
		SyslogProtocol:    SyslogBoth,
		Encoding:          EncodingAuto,
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
		"disable.syslog": true, "syslog.listen": true, "syslog.protocol": true,
		"multiline": true, "multiline.pattern": true, "multiline.timeout": true,
		"start_position": true, "encoding": true,
		"include.match": true, "exclude.match": true,
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
	if v, ok := mc.Settings["multiline"]; ok {
		switch MultilineMode(strings.ToLower(strings.TrimSpace(v))) {
		case MultilineOff:
			s.Multiline = MultilineOff
		case MultilineAuto:
			s.Multiline = MultilineAuto
		case MultilinePattern:
			s.Multiline = MultilinePattern
		default:
			return Settings{}, fmt.Errorf("logs: multiline must be off, auto or pattern")
		}
	}
	if v, ok := mc.Settings["multiline.pattern"]; ok {
		// Compiled here so a bad expression fails at load, where somebody is
		// watching, rather than silently matching nothing forever.
		if _, err := regexp.Compile(v); err != nil {
			return Settings{}, fmt.Errorf("logs: multiline.pattern: %w", err)
		}
		s.MultilinePattern = v
	}
	if s.Multiline == MultilinePattern && s.MultilinePattern == "" {
		return Settings{}, fmt.Errorf("logs: multiline is pattern but multiline.pattern is empty")
	}
	if v, ok := mc.Settings["multiline.timeout"]; ok {
		s.MultilineTimeout, err = time.ParseDuration(v)
		if err != nil || s.MultilineTimeout <= 0 {
			return Settings{}, fmt.Errorf("logs: multiline.timeout must be a positive duration")
		}
	}
	if v, ok := mc.Settings["start_position"]; ok {
		switch StartPosition(strings.ToLower(strings.TrimSpace(v))) {
		case StartEnd:
			s.StartPosition = StartEnd
		case StartBeginning:
			s.StartPosition = StartBeginning
		default:
			return Settings{}, fmt.Errorf("logs: start_position must be end or beginning")
		}
	}
	if v, ok := mc.Settings["encoding"]; ok {
		switch Encoding(strings.ToLower(strings.TrimSpace(v))) {
		case EncodingAuto:
			s.Encoding = EncodingAuto
		case EncodingUTF8:
			s.Encoding = EncodingUTF8
		case EncodingUTF16LE:
			s.Encoding = EncodingUTF16LE
		case EncodingUTF16BE:
			s.Encoding = EncodingUTF16BE
		default:
			return Settings{}, fmt.Errorf("logs: encoding must be auto, utf-8, utf-16-le or utf-16-be")
		}
	}
	if v, ok := mc.Settings["include.match"]; ok {
		if _, err := regexp.Compile(v); err != nil {
			return Settings{}, fmt.Errorf("logs: include.match: %w", err)
		}
		s.IncludeMatch = v
	}
	if v, ok := mc.Settings["exclude.match"]; ok {
		if _, err := regexp.Compile(v); err != nil {
			return Settings{}, fmt.Errorf("logs: exclude.match: %w", err)
		}
		s.ExcludeMatch = v
	}
	if v, ok := mc.Settings["disable.syslog"]; ok {
		s.DisabledSources[SourceSyslog] = parseBool(v)
	}
	if v, ok := mc.Settings["syslog.listen"]; ok {
		v = strings.TrimSpace(v)
		if v != "" {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return Settings{}, fmt.Errorf("logs: syslog.listen must be host:port: %w", err)
			}
		}
		s.SyslogListen = v
	}
	if v, ok := mc.Settings["syslog.protocol"]; ok {
		switch SyslogProtocol(strings.ToLower(strings.TrimSpace(v))) {
		case SyslogUDP:
			s.SyslogProtocol = SyslogUDP
		case SyslogTCP:
			s.SyslogProtocol = SyslogTCP
		case SyslogBoth:
			s.SyslogProtocol = SyslogBoth
		default:
			return Settings{}, fmt.Errorf("logs: syslog.protocol must be udp, tcp or both")
		}
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
