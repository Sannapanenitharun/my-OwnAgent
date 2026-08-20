package host

import (
	"strings"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

func frag(kv map[string]string) config.ModuleConfig {
	return config.ModuleConfig{Enabled: true, Settings: kv}
}

func TestDefaultSettingsAreValid(t *testing.T) {
	s, err := ParseSettings(frag(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.Interval(SourceCPU) != 10*time.Second {
		t.Fatalf("cpu interval = %v", s.Interval(SourceCPU))
	}
	// Intervals must not be uniform: collecting everything at the fastest
	// useful rate is the largest avoidable cost in an observability agent.
	if s.Interval(SourceOS) <= s.Interval(SourceCPU) {
		t.Fatal("OS metadata should be collected far less often than CPU")
	}
	if s.Interval(SourceFilesystem) <= s.Interval(SourceCPU) {
		t.Fatal("filesystem should be collected less often than CPU")
	}
}

func TestUnknownSettingIsRejected(t *testing.T) {
	// A silently ignored tuning key is how an operator concludes they have
	// reduced an agent's cost when they have not.
	_, err := ParseSettings(frag(map[string]string{"intervals.cpu": "30s"}))
	if err == nil {
		t.Fatal("a misspelled setting must be rejected")
	}
	if !strings.Contains(err.Error(), "unknown setting") {
		t.Fatalf("error = %v", err)
	}
}

func TestAllProblemsAreReportedAtOnce(t *testing.T) {
	_, err := ParseSettings(frag(map[string]string{
		"interval.cpu":     "nonsense",
		"network.max":      "0",
		"cpu.per_core":     "maybe",
		"metrics.disabled": "host.does.not.exist",
	}))
	if err == nil {
		t.Fatal("expected rejection")
	}
	for _, want := range []string{"interval.cpu", "network.max", "cpu.per_core", "metrics.disabled"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestIntervalFloorAndCeiling(t *testing.T) {
	// Sub-second polling of /proc costs more CPU than the thing it measures.
	if _, err := ParseSettings(frag(map[string]string{"interval.cpu": "100ms"})); err == nil {
		t.Error("a sub-second interval must be rejected")
	}
	if _, err := ParseSettings(frag(map[string]string{"interval.cpu": "48h"})); err == nil {
		t.Error("an absurdly long interval must be rejected")
	}
	if _, err := ParseSettings(frag(map[string]string{"interval.cpu": "1s"})); err != nil {
		t.Errorf("1s should be accepted: %v", err)
	}
}

func TestCollectionTimeoutBounds(t *testing.T) {
	for _, bad := range []string{"1ms", "5m"} {
		if _, err := ParseSettings(frag(map[string]string{"collection.timeout": bad})); err == nil {
			t.Errorf("collection.timeout %q should be rejected", bad)
		}
	}
	s, err := ParseSettings(frag(map[string]string{"collection.timeout": "2s"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.CollectionTimeout != 2*time.Second {
		t.Fatalf("timeout = %v", s.CollectionTimeout)
	}
}

func TestSeriesCapsAreBounded(t *testing.T) {
	for _, key := range []string{"cpu.max", "filesystem.max", "network.max", "disk.max"} {
		for _, bad := range []string{"0", "-1", "100000", "abc"} {
			if _, err := ParseSettings(frag(map[string]string{key: bad})); err == nil {
				t.Errorf("%s=%q should be rejected", key, bad)
			}
		}
	}
}

func TestExclusionListsParse(t *testing.T) {
	s, err := ParseSettings(frag(map[string]string{
		"network.exclude": "veth, docker ,br-",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.NetworkExclude) != 3 || s.NetworkExclude[1] != "docker" {
		t.Fatalf("exclusions = %q", s.NetworkExclude)
	}
}

func TestEmptyExclusionListClearsDefaults(t *testing.T) {
	// An operator who wants every interface must be able to say so.
	s, err := ParseSettings(frag(map[string]string{"network.exclude": ""}))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.NetworkExclude) != 0 {
		t.Fatalf("exclusions = %q, want empty", s.NetworkExclude)
	}
}

func TestDisablingAnUnknownMetricIsRejected(t *testing.T) {
	if _, err := ParseSettings(frag(map[string]string{"metrics.disabled": "host.cpu.utilisation"})); err == nil {
		t.Fatal("a misspelled metric name must be rejected, not silently leave the metric enabled")
	}
	if _, err := ParseSettings(frag(map[string]string{"metrics.disabled": MetricCPUUtilization})); err != nil {
		t.Fatalf("a real metric name must be accepted: %v", err)
	}
}

func TestDisablingAnUnknownSourceIsRejected(t *testing.T) {
	if _, err := ParseSettings(frag(map[string]string{"sources.disabled": "gpu"})); err == nil {
		t.Fatal("an unknown source must be rejected")
	}
	s, err := ParseSettings(frag(map[string]string{"sources.disabled": "disk,network"}))
	if err != nil {
		t.Fatal(err)
	}
	if !s.DisabledSources[SourceDisk] || !s.DisabledSources[SourceNetwork] {
		t.Fatal("disabled sources not recorded")
	}
	if s.DisabledSources[SourceCPU] {
		t.Fatal("cpu was disabled but was not listed")
	}
}

func TestSettingsCloneIsDeep(t *testing.T) {
	// A prepared-but-not-committed configuration must never alias the live one.
	s := DefaultSettings()
	c := s.Clone()
	c.Intervals[SourceCPU] = time.Hour
	c.NetworkExclude = append(c.NetworkExclude, "mutated")
	c.DisabledMetrics["x"] = true

	if s.Intervals[SourceCPU] == time.Hour {
		t.Error("interval map is shared with the clone")
	}
	if len(s.DisabledMetrics) != 0 {
		t.Error("disabled metric map is shared with the clone")
	}
	for _, e := range s.NetworkExclude {
		if e == "mutated" {
			t.Error("exclusion slice is shared with the clone")
		}
	}
}

func TestEveryDeclaredMetricIsKnown(t *testing.T) {
	// Guards against a metric being emitted that configuration cannot name,
	// which would make it impossible to disable.
	for _, name := range AllMetrics {
		if !IsKnownMetric(name) {
			t.Errorf("%q is in AllMetrics but not recognised", name)
		}
	}
	if IsKnownMetric("host.not.a.metric") {
		t.Error("an unknown name was recognised")
	}
}

func TestEverySourceHasADefaultInterval(t *testing.T) {
	d := defaultIntervals()
	for _, src := range AllSources {
		if d[src] <= 0 {
			t.Errorf("source %s has no default interval", src)
		}
	}
}

func TestEverySourceHasAName(t *testing.T) {
	seen := map[string]bool{}
	for _, src := range AllSources {
		name := src.String()
		if name == "unknown" {
			t.Errorf("source %d has no name", int(src))
		}
		if seen[name] {
			t.Errorf("duplicate source name %q", name)
		}
		seen[name] = true
		if got, ok := sourceByName(name); !ok || got != src {
			t.Errorf("sourceByName(%q) did not round-trip", name)
		}
	}
}
