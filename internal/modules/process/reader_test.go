package process

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

// These exercise the REAL platform reader against the machine running the test.
// Unit tests with fakes prove the module's logic; only this proves the reader
// actually talks to the operating system correctly.

func platformCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPlatformSetDeclaresEveryFeatureHonestly(t *testing.T) {
	set := NewSet()
	for _, f := range AllFeatures {
		if set.Has(f) {
			continue
		}
		if set.UnsupportedReason(f) == "" {
			t.Errorf("feature %s is unavailable on %s with no recorded reason", f, runtime.GOOS)
		}
	}
	t.Logf("%s/%s supports %d of %d process features: %v",
		runtime.GOOS, runtime.GOARCH, len(set.Available()), len(AllFeatures), set.Available())
}

func TestRealEnumerationFindsThisProcess(t *testing.T) {
	set := NewSet()
	if !set.Has(FeatureEnumeration) {
		t.Skipf("process enumeration is unsupported on %s", runtime.GOOS)
	}

	listing, err := set.Lister.ListProcesses(platformCtx(t), ListOptions{})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}
	if len(listing.Processes) == 0 {
		t.Fatal("enumeration returned no processes at all")
	}

	self := PID(os.Getpid())
	var found *Info
	for i := range listing.Processes {
		if listing.Processes[i].PID == self {
			found = &listing.Processes[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("enumeration of %d processes did not include this test process (pid %d)",
			len(listing.Processes), self)
	}

	if found.Name == "" {
		t.Error("this process has no name")
	}
	if !found.HasStartRaw {
		t.Error("this process has no start stamp; PID reuse could not be detected")
	}
	if found.HasStartTime {
		// The test binary cannot have started in the future, nor before this
		// codebase existed.
		if found.StartTime.After(time.Now().Add(time.Minute)) {
			t.Errorf("start time %v is in the future", found.StartTime)
		}
		if found.StartTime.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("start time %v predates any plausible boot", found.StartTime)
		}
	}

	t.Logf("%s: %d processes, %d vanished, %d denied, %d unreadable",
		runtime.GOOS, len(listing.Processes), listing.Vanished, listing.Denied, listing.Unreadable)
	t.Logf("self: pid=%d ppid=%d name=%q state=%s rss=%v threads=%v cpu=%v start=%v",
		found.PID, found.PPID, found.Name, found.State,
		found.RSSBytes, found.Threads, found.CPUNanos(), found.StartTime)
}

func TestRealEnumerationValuesArePlausible(t *testing.T) {
	set := NewSet()
	if !set.Has(FeatureEnumeration) {
		t.Skipf("process enumeration is unsupported on %s", runtime.GOOS)
	}
	listing, err := set.Lister.ListProcesses(platformCtx(t), ListOptions{})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}

	var withRSS, withCPU, withThreads, withState int
	for _, p := range listing.Processes {
		if p.PID <= 0 {
			t.Errorf("process with non-positive PID %d", p.PID)
		}
		if p.RSSBytes.OK {
			withRSS++
			// No process on any supported platform legitimately has a resident
			// set of a petabyte; that value would mean a unit or offset bug.
			if p.RSSBytes.V > 1<<50 {
				t.Errorf("pid %d reports %d bytes RSS, which is implausible", p.PID, p.RSSBytes.V)
			}
		}
		if p.CPUNanos().OK {
			withCPU++
			if p.CPUNanos().V > uint64(10*365*24*time.Hour) {
				t.Errorf("pid %d reports %v of CPU time, which is implausible",
					p.PID, time.Duration(p.CPUNanos().V))
			}
		}
		if p.Threads.OK {
			withThreads++
			if p.Threads.V > 100000 {
				t.Errorf("pid %d reports %d threads, which is implausible", p.PID, p.Threads.V)
			}
		}
		if p.State != StateUnknown {
			withState++
		}
	}

	total := len(listing.Processes)
	t.Logf("of %d processes: %d with RSS, %d with CPU, %d with threads, %d with a known state",
		total, withRSS, withCPU, withThreads, withState)

	// If a platform CLAIMS a feature, it must actually deliver it for at least
	// some processes — otherwise the capability report is lying.
	if set.Has(FeatureMemory) && withRSS == 0 {
		t.Error("the platform claims memory support but reported RSS for no process")
	}
	if set.Has(FeatureThreads) && withThreads == 0 {
		t.Error("the platform claims thread support but reported threads for no process")
	}
	if set.Has(FeatureState) && withState == 0 {
		t.Error("the platform claims state support but reported a state for no process")
	}
	if !set.Has(FeatureState) && withState > 0 {
		t.Error("the platform reports process states while declaring the feature unsupported")
	}
}

func TestRealPreFilterIsHonoured(t *testing.T) {
	set := NewSet()
	if !set.Has(FeatureEnumeration) {
		t.Skip("unsupported")
	}
	self := PID(os.Getpid())
	listing, err := set.Lister.ListProcesses(platformCtx(t), ListOptions{
		Accept: func(p PID) bool { return p == self },
	})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}
	if len(listing.Processes) != 1 || listing.Processes[0].PID != self {
		t.Errorf("pre-filter returned %d processes, want exactly this one", len(listing.Processes))
	}
}

func TestRealDetailReadsOnOurselves(t *testing.T) {
	// The agent can always inspect its own process, on every platform, without
	// elevation. That is the least-privilege baseline.
	set := NewSet()
	self := PID(os.Getpid())
	ctx := platformCtx(t)

	if set.IO != nil {
		if io, err := set.IO.ReadIO(ctx, self); err != nil {
			t.Logf("ReadIO on self: %v (may be a privilege boundary)", err)
		} else {
			t.Logf("self I/O: read=%v write=%v ops=%v/%v",
				io.ReadBytes, io.WriteBytes, io.ReadOps, io.WriteOps)
		}
	}
	if set.Files != nil {
		n, err := set.Files.ReadOpenFiles(ctx, self)
		if err != nil {
			t.Errorf("ReadOpenFiles on our own process: %v", err)
		} else if !n.OK || n.V == 0 {
			t.Errorf("this process holds %v open files, which cannot be right", n)
		} else {
			t.Logf("self open files/handles: %d", n.V)
		}
	}
	if set.Path != nil {
		p, err := set.Path.ReadExecutablePath(ctx, self)
		if err != nil {
			t.Errorf("ReadExecutablePath on our own process: %v", err)
		} else if p == "" {
			t.Error("our own executable path came back empty")
		} else {
			t.Logf("self executable: %s", p)
		}
	}
	if set.Command != nil {
		args, err := set.Command.ReadCommandLine(ctx, self)
		if err != nil {
			t.Errorf("ReadCommandLine on our own process: %v", err)
		} else if len(args) == 0 {
			t.Error("our own command line came back empty")
		} else {
			if len(args) > maxCommandArgs {
				t.Errorf("command line returned %d args, above the %d cap", len(args), maxCommandArgs)
			}
			t.Logf("self command line: %d args, first %q", len(args), args[0])
		}
	}
}

func TestRealBootIdentityIsStable(t *testing.T) {
	set := NewSet()
	if set.Boot == nil {
		t.Skipf("boot identity is unsupported on %s", runtime.GOOS)
	}
	ctx := platformCtx(t)

	first, err := set.Boot.ReadBootIdentity(ctx)
	if err != nil {
		t.Fatalf("ReadBootIdentity: %v", err)
	}
	if first.ID == "" {
		t.Fatal("boot identity is empty")
	}
	// Read again: the value must not drift, or every process instance key would
	// change between cycles.
	second, err := set.Boot.ReadBootIdentity(ctx)
	if err != nil {
		t.Fatalf("second ReadBootIdentity: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("boot identity changed between reads: %q then %q", first.ID, second.ID)
	}
	if first.HasTime && first.Time.After(time.Now()) {
		t.Errorf("boot time %v is in the future", first.Time)
	}
	t.Logf("boot identity: %s (time %v)", first.ID, first.Time)
}

func TestRealModuleCollectsFromThisMachine(t *testing.T) {
	// End to end against the real operating system, with the real reader set.
	set := NewSet()
	if !set.Has(FeatureEnumeration) {
		t.Skipf("process enumeration is unsupported on %s", runtime.GOOS)
	}

	h := newHarness(t, set, nil)
	h.start()
	h.waitCycles(1)

	count, ok := h.gauge(MetricCount)
	if !ok {
		t.Fatalf("no process.count was emitted. %s", h.describe())
	}
	if count < 5 {
		t.Errorf("process.count = %v; no real machine runs fewer than five processes", count)
	}
	if _, ok := h.gauge(MetricInstances, nil...); ok {
		t.Error("process.instances was emitted with no executable attribute")
	}

	stats := h.mod.Statistics(context.Background())
	t.Logf("%s: cycles=%d discovered=%d executables=%.0f state_entries=%.0f denied=%d",
		runtime.GOOS,
		stats.Counters["cycles"], stats.Counters["processes_discovered"],
		stats.Gauges["executables"], stats.Gauges["state_entries"],
		stats.Counters["processes_denied"])

	rep := h.mod.Health(context.Background())
	t.Logf("health: %s — %s", rep.Status, rep.Message)
}

func TestRealCollectionIsStableAcrossCycles(t *testing.T) {
	// Two real cycles against the machine: PIDs churn, and the module must
	// produce CPU utilisation on the second pass without leaking state.
	set := NewSet()
	if !set.Has(FeatureEnumeration) {
		t.Skip("unsupported")
	}
	h := newHarness(t, set, nil)
	h.start()
	h.waitCycles(1)
	h.advance(31 * time.Second)

	stats := h.mod.Statistics(context.Background())
	entries := stats.Gauges["state_entries"]
	discovered := float64(stats.Counters["processes_discovered"])
	if entries > discovered+50 {
		t.Errorf("state entries (%v) far exceed discovered processes (%v)", entries, discovered)
	}
	// CPU utilisation needs two samples, so it can only appear now. On a
	// genuinely idle machine every process may round to zero and be omitted, so
	// this is reported rather than asserted.
	if set.Has(FeatureCPU) {
		t.Logf("process.cpu.utilization series after two cycles: %d",
			h.tel.SeriesCount(MetricCPUUtilization))
	}
}
