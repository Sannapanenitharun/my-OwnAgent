package host

import (
	"strconv"
	"testing"
)

func TestFirstObservationEmitsNoDelta(t *testing.T) {
	// Emitting the cumulative value as a delta is the classic "my server did
	// 4 TB of I/O in one scrape" artefact.
	c := newCounterState()
	if _, ok := c.delta("eth0|rx", 1_000_000); ok {
		t.Fatal("the first observation must not produce a delta")
	}
	d, ok := c.delta("eth0|rx", 1_000_500)
	if !ok || d != 500 {
		t.Fatalf("delta = %d, %v; want 500, true", d, ok)
	}
}

func TestCounterResetIsNotEmitted(t *testing.T) {
	// A device removed and re-added, or a rebooted host, sends the counter
	// backwards. Both a negative and a wrapped positive would be wrong.
	c := newCounterState()
	c.delta("sda|rb", 5000)
	if _, ok := c.delta("sda|rb", 100); ok {
		t.Fatal("a counter that went backwards must not produce a delta")
	}
	// The baseline is re-seeded, so the next increase is measured from there.
	d, ok := c.delta("sda|rb", 150)
	if !ok || d != 50 {
		t.Fatalf("delta after reset = %d, %v; want 50, true", d, ok)
	}
}

func TestVanishedKeysAreReaped(t *testing.T) {
	// Container and cloud hosts churn interfaces continuously; without reaping
	// this map is an unbounded leak.
	c := newCounterState()
	for cycle := 0; cycle < 3; cycle++ {
		c.beginCycle()
		for i := 0; i < 50; i++ {
			c.delta("veth"+strconv.Itoa(cycle*50+i), uint64(i))
		}
		c.endCycle()
	}
	if got := c.size(); got != 50 {
		t.Fatalf("retained %d baselines after three disjoint cycles, want 50", got)
	}
}

func TestSurvivingKeysKeepTheirBaseline(t *testing.T) {
	c := newCounterState()
	c.beginCycle()
	c.delta("eth0", 100)
	c.delta("eth1", 100)
	c.endCycle()

	c.beginCycle()
	d, ok := c.delta("eth0", 150)
	c.endCycle()

	if !ok || d != 50 {
		t.Fatalf("delta = %d, %v; a surviving key lost its baseline", d, ok)
	}
	if c.size() != 1 {
		t.Fatalf("retained %d baselines, want 1 after eth1 vanished", c.size())
	}
}

func TestCPUUtilisationNeedsTwoSamples(t *testing.T) {
	var s cpuState
	if _, _, _, _, _, _, ok := s.utilisation(CPUTimes{User: 100, Idle: 900}); ok {
		t.Fatal("utilisation was produced from a single sample")
	}
	busy, user, _, _, _, _, ok := s.utilisation(CPUTimes{User: 150, Idle: 1850})
	if !ok {
		t.Fatal("utilisation was not produced from the second sample")
	}
	// 1000 ticks passed, 50 of them in user.
	if busy < 0.049 || busy > 0.051 {
		t.Fatalf("busy = %v, want ~0.05", busy)
	}
	if user < 0.049 || user > 0.051 {
		t.Fatalf("user = %v, want ~0.05", user)
	}
}

func TestCPUUtilisationCountsIOWaitAsBusy(t *testing.T) {
	// A host blocked on storage is not available for work. Counting iowait as
	// idle hides the most common cause of a slow host.
	var s cpuState
	s.utilisation(CPUTimes{Idle: 0, IOWait: 0})
	busy, _, _, iowait, _, _, ok := s.utilisation(CPUTimes{Idle: 500, IOWait: 500})
	if !ok {
		t.Fatal("no utilisation produced")
	}
	if busy < 0.49 || busy > 0.51 {
		t.Fatalf("busy = %v, want ~0.5 with half the time in iowait", busy)
	}
	if iowait < 0.49 || iowait > 0.51 {
		t.Fatalf("iowait = %v, want ~0.5", iowait)
	}
}

func TestCPUUtilisationHandlesStalledCounters(t *testing.T) {
	// If no time passed, there is no ratio. Reporting 0% busy would claim an
	// idle host on evidence that says nothing.
	var s cpuState
	sample := CPUTimes{User: 100, Idle: 900}
	s.utilisation(sample)
	if _, _, _, _, _, _, ok := s.utilisation(sample); ok {
		t.Fatal("identical samples produced a utilisation")
	}
}

func TestCPUUtilisationHandlesCounterReset(t *testing.T) {
	var s cpuState
	s.utilisation(CPUTimes{User: 1000, Idle: 9000})
	if _, _, _, _, _, _, ok := s.utilisation(CPUTimes{User: 10, Idle: 90}); ok {
		t.Fatal("a counter reset produced a utilisation")
	}
	// The baseline was replaced, so the next sample works normally.
	if _, _, _, _, _, _, ok := s.utilisation(CPUTimes{User: 20, Idle: 180}); !ok {
		t.Fatal("utilisation did not resume after a reset")
	}
}

func TestCPUUtilisationIsUnitAgnostic(t *testing.T) {
	// The same ratio must fall out of Linux jiffies and Windows 100ns FILETIME
	// units, which is why the readers are not asked to normalise.
	var jiffies, filetime cpuState
	jiffies.utilisation(CPUTimes{User: 100, Idle: 300})
	jBusy, _, _, _, _, _, _ := jiffies.utilisation(CPUTimes{User: 200, Idle: 600})

	const scale = 100_000
	filetime.utilisation(CPUTimes{User: 100 * scale, Idle: 300 * scale})
	fBusy, _, _, _, _, _, _ := filetime.utilisation(CPUTimes{User: 200 * scale, Idle: 600 * scale})

	if jBusy != fBusy {
		t.Fatalf("unit-dependent result: %v vs %v", jBusy, fBusy)
	}
}

func BenchmarkCounterStateCycle(b *testing.B) {
	c := newCounterState()
	keys := make([]string, 64)
	for i := range keys {
		keys[i] = "eth" + strconv.Itoa(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.beginCycle()
		for j, k := range keys {
			c.delta(k, uint64(i*100+j))
		}
		c.endCycle()
	}
}
