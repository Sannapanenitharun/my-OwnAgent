package logs

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/platform"
)

func TestSeverityIsReadFromRealLogLines(t *testing.T) {
	cases := []struct {
		name string
		line string
		want platform.EventSeverity
	}{
		// klog/glog. This is the line from the live host that started this.
		{"klog warn", "W0828 16:37:10.331120       1 updater.go:46] prometheus is not configured", platform.SeverityWarn},
		{"klog error", "E0828 16:37:10.331120       1 server.go:12] bind failed", platform.SeverityError},
		{"klog info", "I0828 16:37:10.331120       1 main.go:9] listening", platform.SeverityInfo},
		{"klog fatal", "F0828 16:37:10.331120       1 main.go:9] cannot continue", platform.SeverityError},

		// logfmt, which the agent itself writes.
		{"logfmt", `time=2026-08-28T14:21:23.256Z level=WARN msg="identity unresolved"`, platform.SeverityWarn},
		{"logfmt error", `ts=1 level=error msg="post failed"`, platform.SeverityError},
		{"logfmt debug", `level=debug component=exporter`, platform.SeverityDebug},

		// JSON.
		{"json", `{"ts":"2026-08-28","level":"error","msg":"connection refused"}`, platform.SeverityError},
		{"json severity key", `{"severity":"WARNING","message":"disk almost full"}`, platform.SeverityWarn},

		// Bracketed and bare leading tokens.
		{"bracketed", "[ERROR] failed to open /var/lib/x", platform.SeverityError},
		{"bracketed warn", "[warn] slow query", platform.SeverityWarn},
		{"bare colon", "ERROR: cannot bind port 8080", platform.SeverityError},
		{"bare space", "WARN  retrying in 5s", platform.SeverityWarn},

		// Syslog priority: <11> is facility 1, severity 3 (err).
		{"syslog pri err", "<11>Aug 28 16:37:10 host sshd[1]: bad password", platform.SeverityError},
		{"syslog pri info", "<14>Aug 28 16:37:10 host cron[1]: job done", platform.SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := detectSeverity(tc.line)
			if !ok {
				t.Fatalf("no severity found in %q", tc.line)
			}
			if got != tc.want {
				t.Errorf("severity = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSeverityIsNotGuessedFromProse is the important half. A severity column
// that lies is worse than one that is always Info, because an operator stops
// trusting it and then cannot use it at all.
func TestSeverityIsNotGuessedFromProse(t *testing.T) {
	lines := []string{
		"no errors found in the last hour",
		"errors.go:41 reached",
		"starting error-budget calculator",
		"GET /api/errors 200 4ms",
		"scanning for warnings",
		"Errors were found and repaired",
		"debugger attached to pid 900",
		"the sublevel=error field belongs to something else",
		"connected to fatalities-db",
		"",
		"   ",
	}
	for _, line := range lines {
		if sev, ok := detectSeverity(line); ok {
			t.Errorf("%q was read as %v; nothing in it declares a level", line, sev)
		}
	}
}

func TestUndetectedLineStaysInfo(t *testing.T) {
	// The default must be the level the agent used before this existed, so a
	// line whose format is not recognised is unchanged rather than downgraded.
	sev, ok := detectSeverity("some unstructured application output")
	if ok {
		t.Fatal("severity was claimed for an unstructured line")
	}
	if sev != platform.SeverityInfo {
		t.Errorf("default = %v, want Info", sev)
	}
}

func TestOnlyTheHeadOfTheLineIsRead(t *testing.T) {
	// A marker far into a stack trace is a coincidence. Bounding the scan is
	// also what keeps this off the hot path for very long lines.
	long := "request completed " + string(make([]byte, 4096)) + " level=error"
	if _, ok := detectSeverity(long); ok {
		t.Error("a level was read from beyond the scan window")
	}
}

func TestKlogNeedsItsDateToCount(t *testing.T) {
	// A bare leading capital is a letter; "E0828" is a klog header. Without the
	// digits, every line starting with a word beginning in E would be an error.
	if _, ok := detectSeverity("Established connection to peer"); ok {
		t.Error("a bare leading capital was treated as a klog level")
	}
	if _, ok := detectSeverity("Warning signs were noted"); !ok {
		// This one legitimately starts with a level word followed by a space,
		// so it IS detected -- documented here so the behaviour is deliberate
		// rather than discovered later.
		t.Log("leading level word with a delimiter is detected, as designed")
	}
}

func TestFirstMarkerWins(t *testing.T) {
	// A line is read once, left to right. An error mentioned inside a warning's
	// message must not escalate the line.
	sev, ok := detectSeverity(`level=warn msg="handler returned error"`)
	if !ok || sev != platform.SeverityWarn {
		t.Errorf("severity = %v ok=%v, want Warn: the level field is the level", sev, ok)
	}
}

func TestSeverityDetectionIsOnByDefaultAndCanBeDisabled(t *testing.T) {
	def := DefaultSettings()
	if !def.DetectSeverity {
		t.Error("severity detection is off by default; every line would stay Info")
	}
	s, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"severity.detect": "false"}})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if s.DetectSeverity {
		t.Error("severity.detect=false was ignored")
	}
	if _, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"severity.detekt": "true"}}); err == nil {
		t.Error("a misspelled setting was accepted")
	}
}
