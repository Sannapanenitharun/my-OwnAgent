package process

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Name sanitisation — the security control
// ---------------------------------------------------------------------------

// TestSanitiseNameNeutralisesHostileProcessNames covers the attack that makes
// process telemetry different from host telemetry: the observed thing chooses
// its own label.
func TestSanitiseNameNeutralisesHostileProcessNames(t *testing.T) {
	tests := []struct {
		desc     string
		in       string
		want     string
		modified bool
	}{
		{"ordinary", "nginx", "nginx", false},
		{"windows exe", "chrome.exe", "chrome.exe", false},
		{"unicode is preserved", "café", "café", false},

		{"newline forges a log line", "nginx\nFATAL: breach", "nginx_FATAL: breach", true},
		{"carriage return", "a\rb", "a_b", true},
		{"tab", "a\tb", "a_b", true},
		{"nul", "a\x00b", "a_b", true},
		{"ansi escape reprograms a terminal", "a\x1b[2Jb", "a_[2Jb", true},
		{"bell", "\a", "_", true},

		{"empty", "", "unknown", true},
		{"whitespace only", "   ", "unknown", true},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, modified := sanitiseName(tc.in)
			if got != tc.want {
				t.Errorf("sanitiseName(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if modified != tc.modified {
				t.Errorf("modified = %v, want %v", modified, tc.modified)
			}
		})
	}
}

func TestSanitiseNameBoundsLength(t *testing.T) {
	// A Windows executable name can be 260 characters. Emitting it verbatim
	// lets an observed process choose how much storage its series costs.
	long := strings.Repeat("x", 500)
	got, modified := sanitiseName(long)
	if len(got) > maxExecutableNameLen {
		t.Errorf("length = %d, want at most %d", len(got), maxExecutableNameLen)
	}
	if !modified {
		t.Error("truncation was not reported")
	}
}

func TestSanitiseNameTruncatesOnRuneBoundaries(t *testing.T) {
	// Cutting a multi-byte rune in half would produce exactly the invalid UTF-8
	// the control-character pass just removed.
	name := strings.Repeat("é", 100) // two bytes each
	got, _ := sanitiseName(name)
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
	if len(got) > maxExecutableNameLen {
		t.Errorf("length = %d, want at most %d", len(got), maxExecutableNameLen)
	}
}

func TestSanitiseNameHandlesInvalidUTF8(t *testing.T) {
	got, modified := sanitiseName("nginx\xff\xfe")
	if !utf8.ValidString(got) {
		t.Errorf("result is not valid UTF-8: %q", got)
	}
	if !modified {
		t.Error("invalid UTF-8 was not reported as modified")
	}
}

func TestSanitiseNameDoesNotCollapseDistinctNames(t *testing.T) {
	// Control characters are REPLACED rather than stripped, so two names that
	// differ only in them stay distinct — otherwise an attacker could make
	// unrelated processes share a series.
	a, _ := sanitiseName("a\nb")
	b, _ := sanitiseName("ab")
	if a == b {
		t.Errorf("names %q and %q collapsed into one", "a\\nb", "ab")
	}
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

func obsFor(pid PID, name string) *observation {
	return &observation{PID: pid, Name: name, State: StateSleeping, UID: KnownU64(1000)}
}

func TestNameFiltersAreSubstringAndCaseInsensitive(t *testing.T) {
	// The names that need matching are generated: "postgres: writer process",
	// "java" versus "java.exe". Exact matching produces filters that silently
	// match nothing.
	s := DefaultSettings()
	s.IncludeNames = []string{"POSTGRES"}

	if !s.admit(obsFor(1, "postgres: writer process")) {
		t.Error("case-insensitive substring include did not match")
	}
	if s.admit(obsFor(2, "nginx")) {
		t.Error("a non-matching process was admitted under an include filter")
	}
}

func TestExcludeBeatsInclude(t *testing.T) {
	s := DefaultSettings()
	s.IncludeNames = []string{"java"}
	s.ExcludeNames = []string{"javadoc"}
	if s.admit(obsFor(1, "javadoc")) {
		t.Error("exclude did not take precedence over include")
	}
	if !s.admit(obsFor(2, "java")) {
		t.Error("include stopped working")
	}
}

func TestPIDRangeFilterRunsBeforeAnyRead(t *testing.T) {
	s := DefaultSettings()
	s.IncludePIDs = []pidRange{{100, 200}, {500, 500}}

	for _, tc := range []struct {
		pid  PID
		want bool
	}{{99, false}, {100, true}, {150, true}, {200, true}, {201, false}, {500, true}, {501, false}} {
		if got := s.acceptPID(tc.pid); got != tc.want {
			t.Errorf("acceptPID(%d) = %v, want %v", tc.pid, got, tc.want)
		}
	}
}

func TestStateAndUserFilters(t *testing.T) {
	s := DefaultSettings()
	s.ExcludeStates = map[State]bool{StateZombie: true}

	zombie := obsFor(1, "defunct")
	zombie.State = StateZombie
	if s.admit(zombie) {
		t.Error("an excluded state was admitted")
	}

	s = DefaultSettings()
	s.IncludeUsers = []uint64{0}
	if s.admit(obsFor(1, "app")) {
		t.Error("a process owned by uid 1000 was admitted under include.users=0")
	}
	root := obsFor(2, "systemd")
	root.UID = KnownU64(0)
	if !s.admit(root) {
		t.Error("a root process was not admitted under include.users=0")
	}
}

func TestThresholdFiltersOnlyApplyToKnownValues(t *testing.T) {
	// A process whose CPU could not be read must not be dropped by a min.cpu
	// filter: that would make an unreadable process indistinguishable from an
	// idle one.
	s := DefaultSettings()
	s.MinCPU = 0.5
	s.MinMemory = 1 << 30

	unknown := obsFor(1, "opaque") // HasCPU false, RSSBytes not OK
	if !s.admit(unknown) {
		t.Error("a process with unknown CPU and memory was dropped by threshold filters")
	}

	idle := obsFor(2, "idle")
	idle.HasCPU = true
	idle.CPUUtilization = 0.01
	if s.admit(idle) {
		t.Error("a process below min.cpu was admitted")
	}

	busy := obsFor(3, "busy")
	busy.HasCPU = true
	busy.CPUUtilization = 0.9
	busy.RSSBytes = KnownU64(2 << 30)
	if !s.admit(busy) {
		t.Error("a process above both thresholds was dropped")
	}
}

// ---------------------------------------------------------------------------
// Bounded selection
// ---------------------------------------------------------------------------

func TestSelectionIsDeterministicAcrossCycles(t *testing.T) {
	// A host over its cap must report the SAME subset every cycle. Otherwise it
	// produces a churn of half-populated series that is worse than reporting
	// nothing.
	s := DefaultSettings()
	s.MaxProcesses = 10

	build := func() []*observation {
		var out []*observation
		for i := 0; i < 100; i++ {
			o := obsFor(PID(1000+i), "proc"+itoa(i%7))
			o.HasCPU = true
			o.CPUUtilization = float64(i%5) / 100
			o.RSSBytes = KnownU64(uint64(i % 3))
			out = append(out, o)
		}
		return out
	}

	first, dropped := s.selectProcesses(build())
	if dropped != 90 {
		t.Fatalf("dropped = %d, want 90", dropped)
	}
	for cycle := 0; cycle < 20; cycle++ {
		again, _ := s.selectProcesses(build())
		for i := range first {
			if first[i].PID != again[i].PID {
				t.Fatalf("cycle %d selected a different subset at index %d: %d vs %d",
					cycle, i, first[i].PID, again[i].PID)
			}
		}
	}
}

func TestSelectionKeepsConfiguredProcessesFirst(t *testing.T) {
	// A host at its cap must never shed the processes it was configured to
	// watch, however idle they are.
	s := DefaultSettings()
	s.MaxProcesses = 3
	s.IncludeNames = []string{"critical-service"}

	var in []*observation
	for i := 0; i < 50; i++ {
		o := obsFor(PID(2000+i), "noise")
		o.HasCPU = true
		o.CPUUtilization = 0.9 // far busier than the service we care about
		in = append(in, o)
	}
	idle := obsFor(9999, "critical-service")
	idle.HasCPU = true
	idle.CPUUtilization = 0
	in = append(in, idle)

	kept, _ := s.selectProcesses(in)
	if kept[0].Name != "critical-service" {
		t.Errorf("selection kept %q first; the configured process must rank above busier ones",
			kept[0].Name)
	}
}

func TestSelectionKeepsKernelAndInit(t *testing.T) {
	s := DefaultSettings()
	s.MaxProcesses = 2

	var in []*observation
	for i := 0; i < 20; i++ {
		o := obsFor(PID(3000+i), "noise")
		o.HasCPU = true
		o.CPUUtilization = 0.5
		in = append(in, o)
	}
	in = append(in, obsFor(1, "init"))

	kept, _ := s.selectProcesses(in)
	found := false
	for _, o := range kept {
		if o.PID == 1 {
			found = true
		}
	}
	if !found {
		t.Error("init was shed while ordinary processes were kept")
	}
}

func TestSelectionRanksKnownValuesAboveUnknown(t *testing.T) {
	s := DefaultSettings()
	s.MaxProcesses = 1

	unknown := obsFor(100, "aaa") // sorts first by name
	known := obsFor(200, "zzz")
	known.HasCPU = true
	known.CPUUtilization = 0.1

	kept, _ := s.selectProcesses([]*observation{unknown, known})
	if kept[0].PID != 200 {
		t.Error("an unknown CPU value outranked a known one")
	}
}

func TestExecutableSelectionPrefersInstanceCount(t *testing.T) {
	// An executable running five hundred copies is the one an operator most
	// wants to see, regardless of whether any single copy is busy.
	in := []*rollup{
		{Name: "busy-singleton", Instances: 1, CPUUtilization: 0.9},
		{Name: "many-workers", Instances: 500, CPUUtilization: 0.1},
		{Name: "idle", Instances: 2},
	}
	kept, dropped := selectExecutables(in, 1)
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	if kept[0].Name != "many-workers" {
		t.Errorf("kept %q, want many-workers", kept[0].Name)
	}
}

func TestSelectionWithoutACapKeepsEverything(t *testing.T) {
	s := DefaultSettings()
	s.MaxProcesses = 0
	in := make([]*observation, 100)
	for i := range in {
		in[i] = obsFor(PID(i+1), "p")
	}
	kept, dropped := s.selectProcesses(in)
	if len(kept) != 100 || dropped != 0 {
		t.Errorf("kept %d dropped %d, want 100/0", len(kept), dropped)
	}
}
