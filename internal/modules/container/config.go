package container

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

const (
	defaultInterval = 15 * time.Second
	defaultMax      = 256
)

// Settings is decoded from module settings.
type Settings struct {
	Interval time.Duration
	Max      int
}

func DefaultSettings() Settings {
	return Settings{Interval: defaultInterval, Max: defaultMax}
}

func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	for k := range mc.Settings {
		switch k {
		case "interval", "max_containers":
		default:
			return Settings{}, fmt.Errorf("container: unknown setting %q", k)
		}
	}
	if v, ok := mc.Settings["interval"]; ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d <= 0 {
			return Settings{}, fmt.Errorf("container: interval must be a positive duration")
		}
		s.Interval = d
	}
	if v, ok := mc.Settings["max_containers"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return Settings{}, fmt.Errorf("container: max_containers must be a positive integer")
		}
		s.Max = n
	}
	return s, nil
}
