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
)

func (s Source) String() string { return string(s) }

var AllSources = []Source{SourceFiles, SourceJournald, SourceEventLog}

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

	MaxLineBytes int
	MaxBytesPerS int
	MaxFiles     int
	MaxBatch     int

	EventLogs []string

	DisabledSources map[Source]bool
}

func DefaultSettings() Settings {
	return Settings{
		Interval:          2 * time.Second,
		CollectionTimeout: 2 * time.Second,
		MaxLineBytes:      16 * 1024,
		MaxBytesPerS:      256 * 1024,
		MaxFiles:          32,
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
		"max.line_bytes": true, "max.bytes_per_s": true,
		"max.files": true, "max.batch": true,
		"event_logs":    true,
		"disable.files": true, "disable.journald": true, "disable.eventlog": true,
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
	if v, ok := mc.Settings["exclude.contains"]; ok {
		s.ExcludeContains = splitList(v)
	}
	if v, ok := mc.Settings["event_logs"]; ok {
		s.EventLogs = splitList(v)
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
