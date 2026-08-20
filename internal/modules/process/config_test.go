package process

import (
	"strings"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

func mc(settings map[string]string) config.ModuleConfig {
	return config.ModuleConfig{Enabled: true, Settings: settings}
}

func TestDefaultSettingsAreBoundedEverywhere(t *testing.T) {
	// There must be no configuration of this module in which collection is
	// unbounded, and that starts with the defaults.
	s := DefaultSettings()
	checks := map[string]int{
		"MaxProcesses":      s.MaxProcesses,
		"MaxExecutables":    s.MaxExecutables,
		"MaxEventsPerCycle": s.MaxEventsPerCycle,
		"MaxTracked":        s.MaxTracked,
	}
	for name, v := range checks {
		if v <= 0 {
			t.Errorf("%s defaults to %d; every limit must be finite", name, v)
		}
	}
	if s.Interval <= 0 || s.CollectionTimeout <= 0 {
		t.Error("intervals default to non-positive values")
	}
}

func TestCommandLineCollectionIsOffByDefault(t *testing.T) {
	// This is a security default, not a cost one. Command lines routinely carry
	// credentials passed as arguments.
	if DefaultSettings().Collect[FeatureCommandLine] {
		t.Fatal("command-line collection is enabled by default")
	}
	for _, f := range []Feature{FeatureExecutablePath, FeatureUser, FeatureOpenFiles} {
		if DefaultSettings().Collect[f] {
			t.Errorf("%s is collected by default; it should be opt-in", f)
		}
	}
}

func TestUnknownSettingsAreRejected(t *testing.T) {
	// A misspelled cap that is silently ignored is how an operator concludes
	// they have bounded an agent's cost when they have not.
	_, err := ParseSettings(mc(map[string]string{"max_procceses": "10"}))
	if err == nil {
		t.Fatal("an unknown setting was accepted")
	}
	if !strings.Contains(err.Error(), "unknown setting") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestEveryProblemIsReportedNotJustTheFirst(t *testing.T) {
	// An operator fixing a configuration one rejection at a time is an operator
	// who reloads six times.
	_, err := ParseSettings(mc(map[string]string{
		"interval":         "nope",
		"max_processes":    "many",
		"min.cpu":          "5",
		"metrics.disabled": "process.nonexistent",
		"unknown.key":      "x",
	}))
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	for _, want := range []string{"interval", "max_processes", "min.cpu", "metrics.disabled", "unknown.key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestCrossFieldValidation(t *testing.T) {
	tests := []struct {
		desc     string
		settings map[string]string
		want     string
	}{
		{
			"tracked below processes",
			map[string]string{"max_tracked": "10", "max_processes": "100"},
			"max_tracked",
		},
		{
			"timeout not shorter than interval",
			map[string]string{"interval": "5s", "collection.timeout": "10s"},
			"collection.timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := ParseSettings(mc(tc.settings))
			if err == nil {
				t.Fatal("the combination was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

func TestMaxExecutablesHasASeriesAwareCeiling(t *testing.T) {
	// max_executables is the series multiplier. Letting it reach 100,000 would
	// permit a cardinality incident regardless of what the operator intended.
	if _, err := ParseSettings(mc(map[string]string{"max_executables": "5000"})); err == nil {
		t.Error("max_executables=5000 was accepted")
	}
	if _, err := ParseSettings(mc(map[string]string{"max_executables": "4096"})); err != nil {
		t.Errorf("max_executables=4096 was rejected: %v", err)
	}
}

func TestPIDRangeParsing(t *testing.T) {
	s, err := ParseSettings(mc(map[string]string{"include.pids": "1-100, 500 ,2000-3000"}))
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	want := []pidRange{{1, 100}, {500, 500}, {2000, 3000}}
	if len(s.IncludePIDs) != len(want) {
		t.Fatalf("got %v, want %v", s.IncludePIDs, want)
	}
	for i := range want {
		if s.IncludePIDs[i] != want[i] {
			t.Errorf("range %d = %v, want %v", i, s.IncludePIDs[i], want[i])
		}
	}

	for _, bad := range []string{"100-1", "a-b", "-5", "1-"} {
		if _, err := ParseSettings(mc(map[string]string{"include.pids": bad})); err == nil {
			t.Errorf("invalid PID range %q was accepted", bad)
		}
	}
}

func TestByteSizeParsing(t *testing.T) {
	tests := map[string]uint64{
		"1024": 1024, "1K": 1 << 10, "1KB": 1 << 10,
		"5M": 5 << 20, "5MB": 5 << 20, "2G": 2 << 30, "2GB": 2 << 30,
	}
	for in, want := range tests {
		s, err := ParseSettings(mc(map[string]string{"min.memory": in}))
		if err != nil {
			t.Errorf("min.memory=%q: %v", in, err)
			continue
		}
		if s.MinMemory != want {
			t.Errorf("min.memory=%q parsed as %d, want %d", in, s.MinMemory, want)
		}
	}
	for _, bad := range []string{"abc", "1TB!", "-5M"} {
		if _, err := ParseSettings(mc(map[string]string{"min.memory": bad})); err == nil {
			t.Errorf("invalid byte size %q was accepted", bad)
		}
	}
}

func TestUserFiltersAreNumericOnly(t *testing.T) {
	// Resolving a user NAME means reading the password database once per
	// process, which is both a cost and an information-disclosure surface.
	_, err := ParseSettings(mc(map[string]string{"include.users": "root"}))
	if err == nil {
		t.Fatal("a user name was accepted as a filter")
	}
	if !strings.Contains(err.Error(), "numeric") {
		t.Errorf("error does not explain why: %v", err)
	}
	if _, err := ParseSettings(mc(map[string]string{"include.users": "0,1000"})); err != nil {
		t.Errorf("numeric UIDs were rejected: %v", err)
	}
}

func TestDisabledMetricsMustNameRealMetrics(t *testing.T) {
	// A typo that silently leaves a metric enabled is indistinguishable from the
	// setting not working.
	if _, err := ParseSettings(mc(map[string]string{"metrics.disabled": "process.cpu.utilisation"})); err == nil {
		t.Error("a misspelled metric name was accepted")
	}
	s, err := ParseSettings(mc(map[string]string{"metrics.disabled": MetricMemoryVirtual}))
	if err != nil {
		t.Fatal(err)
	}
	if !s.DisabledMetrics[MetricMemoryVirtual] {
		t.Error("the metric was not recorded as disabled")
	}
}

func TestIntervalBounds(t *testing.T) {
	// A one-second floor is a guard rail: sub-second sweeps of /proc cost more
	// CPU than the thing they measure.
	for _, bad := range []string{"100ms", "48h", "0s"} {
		if _, err := ParseSettings(mc(map[string]string{"interval": bad})); err == nil {
			t.Errorf("interval %q was accepted", bad)
		}
	}
	if _, err := ParseSettings(mc(map[string]string{
		"interval": "5s", "collection.timeout": "1s"})); err != nil {
		t.Errorf("a valid interval was rejected: %v", err)
	}
}

func TestMinCPUIsAFraction(t *testing.T) {
	for _, bad := range []string{"-0.1", "1.5", "50"} {
		if _, err := ParseSettings(mc(map[string]string{"min.cpu": bad})); err == nil {
			t.Errorf("min.cpu=%q was accepted; it is a fraction of host CPU", bad)
		}
	}
	if _, err := ParseSettings(mc(map[string]string{"min.cpu": "0.05"})); err != nil {
		t.Errorf("min.cpu=0.05 was rejected: %v", err)
	}
}

func TestCloneDoesNotAliasTheLiveConfiguration(t *testing.T) {
	// A prepared-but-not-committed configuration that aliased the live one would
	// make prepare change behaviour, which is the one thing prepare must not do.
	s := DefaultSettings()
	s.IncludeNames = []string{"nginx"}
	s.Collect[FeatureIO] = true

	c := s.Clone()
	c.IncludeNames[0] = "redis"
	c.Collect[FeatureIO] = false
	c.DisabledMetrics[MetricCount] = true

	if s.IncludeNames[0] != "nginx" {
		t.Error("Clone aliased IncludeNames")
	}
	if !s.Collect[FeatureIO] {
		t.Error("Clone aliased Collect")
	}
	if s.DisabledMetrics[MetricCount] {
		t.Error("Clone aliased DisabledMetrics")
	}
}

func TestEmptyStringClearsAList(t *testing.T) {
	s, err := ParseSettings(mc(map[string]string{"exclude.names": ""}))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ExcludeNames) != 0 {
		t.Errorf("exclude.names = %v, want empty", s.ExcludeNames)
	}
}

func TestFeatureCollectionTogglesParse(t *testing.T) {
	s, err := ParseSettings(mc(map[string]string{
		"collect.command_line": "true",
		"collect.io":           "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Collect[FeatureCommandLine] {
		t.Error("collect.command_line=true was not applied")
	}
	if s.Collect[FeatureIO] {
		t.Error("collect.io=false was not applied")
	}
	// Enumeration is not optional.
	if _, err := ParseSettings(mc(map[string]string{"collect.enumeration": "false"})); err == nil {
		t.Error("collect.enumeration was accepted; the module is useless without it")
	}
}

func TestWantsRequiresBothOperatorIntentAndPlatformSupport(t *testing.T) {
	s := DefaultSettings()
	s.Collect[FeatureIO] = true

	withIO := Set{IO: newFakeDetail()}
	if !s.Wants(FeatureIO, withIO) {
		t.Error("a supported, enabled feature was not wanted")
	}
	if s.Wants(FeatureIO, Set{}) {
		t.Error("an unsupported feature was wanted because it was enabled")
	}

	s.Collect[FeatureIO] = false
	if s.Wants(FeatureIO, withIO) {
		t.Error("a disabled feature was wanted because it was supported")
	}
}

func TestDefaultIntervalIsNotOverEager(t *testing.T) {
	// Process tables are large and mostly static; the interesting signals
	// develop over minutes. A ten-second default would triple the cost for
	// detail nobody alerts on.
	if got := DefaultSettings().Interval; got < 30*time.Second {
		t.Errorf("default interval = %s; process collection should not be more eager than 30s", got)
	}
}
