package httpcheck

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// Target is one HTTP endpoint to probe.
type Target struct {
	Name string
	URL  string
}

// Settings is decoded from config.ModuleConfig.Settings. Unknown keys are rejected.
type Settings struct {
	Interval     time.Duration
	Timeout      time.Duration
	Targets      []Target
	ExpectStatus int
}

func DefaultSettings() Settings {
	return Settings{
		Interval:     30 * time.Second,
		Timeout:      5 * time.Second,
		ExpectStatus: 200,
	}
}

func (s Settings) Clone() Settings {
	out := s
	out.Targets = append([]Target(nil), s.Targets...)
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
		"interval": true, "timeout": true, "targets": true, "expect_status": true,
	}
	for _, k := range keys {
		if !known[k] {
			return Settings{}, fmt.Errorf("httpcheck: unknown setting %q", k)
		}
	}

	var err error
	if v, ok := mc.Settings["interval"]; ok {
		s.Interval, err = time.ParseDuration(v)
		if err != nil || s.Interval <= 0 {
			return Settings{}, fmt.Errorf("httpcheck: interval must be a positive duration")
		}
	}
	if v, ok := mc.Settings["timeout"]; ok {
		s.Timeout, err = time.ParseDuration(v)
		if err != nil || s.Timeout <= 0 {
			return Settings{}, fmt.Errorf("httpcheck: timeout must be a positive duration")
		}
	}
	if v, ok := mc.Settings["expect_status"]; ok {
		s.ExpectStatus, err = strconv.Atoi(strings.TrimSpace(v))
		if err != nil || s.ExpectStatus < 100 || s.ExpectStatus > 599 {
			return Settings{}, fmt.Errorf("httpcheck: expect_status must be an HTTP status code")
		}
	}
	if v, ok := mc.Settings["targets"]; ok {
		s.Targets, err = parseTargets(v)
		if err != nil {
			return Settings{}, err
		}
	}
	if s.Timeout >= s.Interval {
		return Settings{}, fmt.Errorf("httpcheck: timeout must be less than interval")
	}
	return s, nil
}

// parseTargets accepts "name=url,name2=url2" or bare URLs (name derived from host).
func parseTargets(raw string) ([]Target, error) {
	var out []Target
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, u := "", part
		if i := strings.Index(part, "="); i > 0 && !strings.Contains(part[:i], "://") {
			name = strings.TrimSpace(part[:i])
			u = strings.TrimSpace(part[i+1:])
		}
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("httpcheck: invalid target URL %q", u)
		}
		if name == "" {
			name = parsed.Host
		}
		if seen[name] {
			return nil, fmt.Errorf("httpcheck: duplicate target name %q", name)
		}
		seen[name] = true
		out = append(out, Target{Name: name, URL: u})
	}
	if len(out) > 32 {
		return nil, fmt.Errorf("httpcheck: at most 32 targets")
	}
	return out, nil
}
