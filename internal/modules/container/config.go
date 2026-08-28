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

	// PerContainer emits CPU and memory for each container, keyed by its
	// short ID, in addition to the runtime rollup.
	//
	// The rollup alone answers almost nothing operationally. Its only
	// attribute is the runtime, of which a host has one, so "21 containers are
	// using 5.3 GB between them" is the whole of it -- and the question an
	// operator actually has is which one.
	//
	// The reason it was only a rollup is real: a container ID is unbounded, and
	// a series per ID accumulates one dead series per container the host has
	// ever run. Two things changed. Series can now be retired, so a container
	// that stops running takes its series with it; and Max already bounds how
	// many are reported in a cycle. The ID is the same join key the log lines
	// carry, so the view resolves it to a name exactly as it does there.
	PerContainer bool
}

func DefaultSettings() Settings {
	return Settings{Interval: defaultInterval, Max: defaultMax, PerContainer: true}
}

func ParseSettings(mc config.ModuleConfig) (Settings, error) {
	s := DefaultSettings()
	for k := range mc.Settings {
		switch k {
		case "interval", "max_containers", "per_container":
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
	if v, ok := mc.Settings["per_container"]; ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return Settings{}, fmt.Errorf("container: per_container must be a boolean")
		}
		s.PerContainer = b
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
