package process

import (
	"testing"
	"time"
)

const (
	testBoot      = "boot-A"
	testRetention = time.Minute
	testMaxTrack  = 100000
)

func at(sec int) time.Time { return time.Unix(1700000000+int64(sec), 0) }

// reconcile is a terser wrapper for the tests.
func (s *store) rec(infos []Info, now time.Time) ([]*observation, []lifecycleChange, int) {
	return s.reconcile(infos, testBoot, now, 4, testMaxTrack, testRetention)
}

func changesOfKind(changes []lifecycleChange, kind string) []lifecycleChange {
	var out []lifecycleChange
	for _, c := range changes {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Instance identity
// ---------------------------------------------------------------------------

func TestInstanceKeyDistinguishesPIDReuse(t *testing.T) {
	a := InstanceKey{Boot: "b", PID: 1234, Start: 1000, HasStart: true}
	b := InstanceKey{Boot: "b", PID: 1234, Start: 2000, HasStart: true}
	if a.SameInstance(b) {
		t.Error("two instances of the same PID with different start times compared equal")
	}
	if !a.SameInstance(InstanceKey{Boot: "b", PID: 1234, Start: 1000, HasStart: true}) {
		t.Error("the same instance compared unequal")
	}
}

func TestInstanceKeyDistinguishesBoots(t *testing.T) {
	// A process started 500 jiffies after boot, and another started 500 jiffies
	// after the NEXT boot, must not share an identity.
	a := InstanceKey{Boot: "boot-1", PID: 1234, Start: 500, HasStart: true}
	b := InstanceKey{Boot: "boot-2", PID: 1234, Start: 500, HasStart: true}
	if a.SameInstance(b) {
		t.Error("instances from different boots compared equal")
	}
}

func TestInstanceKeyWithoutStartIsNeverConfident(t *testing.T) {
	a := InstanceKey{Boot: "b", PID: 1234, HasStart: false}
	b := InstanceKey{Boot: "b", PID: 1234, Start: 5, HasStart: true}
	if a.SameInstance(b) {
		t.Error("a keyless instance matched a keyed one")
	}
}

// TestPIDReuseProducesExitStartAndReplacement is the core correctness test of
// this module.
func TestPIDReuseProducesExitStartAndReplacement(t *testing.T) {
	s := newStore()

	// Cycle 1: PID 1234 is nginx, started at tick 1000.
	old := proc(1234, "nginx", 1000).withCPU(5_000_000_000)
	s.rec([]Info{old}, at(0))

	// Cycle 2: PID 1234 is now redis, started at tick 9000. Same PID, different
	// process — the classic trap.
	fresh := proc(1234, "redis", 9000).withCPU(1_000_000)
	obs, changes, _ := s.rec([]Info{fresh}, at(30))

	if got := len(changesOfKind(changes, EventExited)); got != 1 {
		t.Errorf("got %d exit events, want 1", got)
	}
	if got := len(changesOfKind(changes, EventStarted)); got != 1 {
		t.Errorf("got %d start events, want 1", got)
	}
	if got := len(changesOfKind(changes, EventReplaced)); got != 1 {
		t.Errorf("got %d replacement events, want 1", got)
	}
	if exit := changesOfKind(changes, EventExited)[0]; exit.Name != "nginx" {
		t.Errorf("exit event named %q, want nginx", exit.Name)
	}

	// And critically: the new process must NOT have inherited a CPU delta from
	// the old one. Its cumulative counter went backwards by five seconds.
	if obs[0].HasCPU {
		t.Errorf("the replacement process inherited a CPU baseline: utilisation = %v",
			obs[0].CPUUtilization)
	}
	if s.replacements != 1 {
		t.Errorf("replacements = %d, want 1", s.replacements)
	}
}

func TestPIDReuseDoesNotLeakStateEntries(t *testing.T) {
	s := newStore()
	for i := 0; i < 1000; i++ {
		// The same PID, a new instance every cycle.
		p := proc(1234, "churn", uint64(i))
		s.rec([]Info{p}, at(i))
	}
	if got := s.entries(); got != 1 {
		t.Errorf("state entries = %d after 1000 PID reuses, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle transitions
// ---------------------------------------------------------------------------

func TestDiscoveryAndExitAreReportedOnce(t *testing.T) {
	s := newStore()

	_, changes, _ := s.rec([]Info{proc(100, "a", 1), proc(200, "b", 2)}, at(0))
	if got := len(changesOfKind(changes, EventStarted)); got != 2 {
		t.Fatalf("got %d starts on discovery, want 2", got)
	}

	// Steady state: no events at all.
	_, changes, _ = s.rec([]Info{proc(100, "a", 1), proc(200, "b", 2)}, at(30))
	if len(changes) != 0 {
		t.Errorf("steady state produced %d events: %v", len(changes), changes)
	}

	// One exits.
	_, changes, _ = s.rec([]Info{proc(100, "a", 1)}, at(60))
	exits := changesOfKind(changes, EventExited)
	if len(exits) != 1 || exits[0].PID != 200 {
		t.Fatalf("got %v, want one exit for PID 200", changes)
	}
	if !exits[0].HasLifetime || exits[0].Lifetime != 60*time.Second {
		t.Errorf("lifetime = %v (has=%v), want 60s", exits[0].Lifetime, exits[0].HasLifetime)
	}

	// And it must not be reported again.
	_, changes, _ = s.rec([]Info{proc(100, "a", 1)}, at(90))
	if len(changes) != 0 {
		t.Errorf("the exit was reported twice: %v", changes)
	}
}

func TestRestartIsDistinguishedFromFirstAppearance(t *testing.T) {
	s := newStore()
	s.rec([]Info{proc(100, "nginx", 1)}, at(0))
	s.rec(nil, at(10)) // nginx exits

	_, changes, _ := s.rec([]Info{proc(101, "nginx", 500)}, at(20))
	starts := changesOfKind(changes, EventStarted)
	if len(starts) != 1 {
		t.Fatalf("got %d starts, want 1", len(starts))
	}
	if !starts[0].Restart {
		t.Error("a process reappearing inside the retention window was not marked as a restart")
	}

	// Outside the window it is just a new process.
	s2 := newStore()
	s2.rec([]Info{proc(100, "nginx", 1)}, at(0))
	s2.rec(nil, at(10))
	_, changes, _ = s2.rec([]Info{proc(101, "nginx", 500)}, at(1000))
	starts = changesOfKind(changes, EventStarted)
	if len(starts) != 1 || starts[0].Restart {
		t.Error("a process reappearing long after the window was marked as a restart")
	}
}

func TestExitedProcessStateIsReleasedImmediately(t *testing.T) {
	s := newStore()
	s.rec(procs(500, 10), at(0))
	if got := s.entries(); got != 500 {
		t.Fatalf("entries = %d, want 500", got)
	}
	s.rec(nil, at(30))
	if got := s.entries(); got != 0 {
		t.Errorf("entries = %d after every process exited, want 0", got)
	}
}

func TestLifetimeIsMeasuredFromFirstObservationNotProcessStart(t *testing.T) {
	// A process that predates the agent would otherwise report a lifetime that
	// is really the host's uptime.
	s := newStore()
	ancient := proc(100, "systemd", 1)
	ancient.StartTime = time.Unix(1, 0) // 1970
	s.rec([]Info{ancient}, at(0))
	_, changes, _ := s.rec(nil, at(30))

	exits := changesOfKind(changes, EventExited)
	if len(exits) != 1 {
		t.Fatal("no exit event")
	}
	if exits[0].Lifetime != 30*time.Second {
		t.Errorf("lifetime = %v, want 30s (time since the agent first saw it)", exits[0].Lifetime)
	}
}

// ---------------------------------------------------------------------------
// CPU delta semantics
// ---------------------------------------------------------------------------

func TestFirstObservationEmitsNoUtilisation(t *testing.T) {
	// A utilisation is a ratio of two samples; reporting the cumulative value
	// would claim a process had used a week of CPU in one interval.
	s := newStore()
	obs, _, _ := s.rec([]Info{proc(100, "a", 1).withCPU(999_000_000_000)}, at(0))
	if obs[0].HasCPU {
		t.Errorf("first observation reported utilisation %v", obs[0].CPUUtilization)
	}
}

func TestUtilisationIsAFractionOfTheWholeHost(t *testing.T) {
	s := newStore()
	s.rec([]Info{proc(100, "a", 1).withCPU(0)}, at(0))

	// 4 CPUs, 10 seconds elapsed = 40 CPU-seconds available. A process that
	// used 10 CPU-seconds used a quarter of the host.
	obs, _, _ := s.reconcile(
		[]Info{proc(100, "a", 1).withCPU(10 * uint64(time.Second))},
		testBoot, at(10), 4, testMaxTrack, testRetention)

	if !obs[0].HasCPU {
		t.Fatal("no utilisation on the second observation")
	}
	if got := obs[0].CPUUtilization; got < 0.24 || got > 0.26 {
		t.Errorf("utilisation = %v, want ~0.25", got)
	}
}

func TestUtilisationIsClampedToOne(t *testing.T) {
	// Scheduler accounting and a stepped clock can each produce a ratio above
	// one, and a process reported at 340% of the whole host costs an operator
	// real time to investigate.
	s := newStore()
	s.rec([]Info{proc(100, "a", 1).withCPU(0)}, at(0))
	obs, _, _ := s.reconcile(
		[]Info{proc(100, "a", 1).withCPU(1000 * uint64(time.Second))},
		testBoot, at(1), 4, testMaxTrack, testRetention)

	if got := obs[0].CPUUtilization; got != 1 {
		t.Errorf("utilisation = %v, want it clamped to 1", got)
	}
}

func TestBackwardsCPUCounterReseedsWithoutEmitting(t *testing.T) {
	s := newStore()
	s.rec([]Info{proc(100, "a", 1).withCPU(1000)}, at(0))
	obs, _, _ := s.rec([]Info{proc(100, "a", 1).withCPU(500)}, at(10))
	if obs[0].HasCPU {
		t.Error("a counter that went backwards produced a utilisation")
	}
	// Having re-seeded, the next sample works normally.
	obs, _, _ = s.reconcile([]Info{proc(100, "a", 1).withCPU(500 + uint64(time.Second))},
		testBoot, at(20), 1, testMaxTrack, testRetention)
	if !obs[0].HasCPU {
		t.Error("the baseline did not re-seed after a reset")
	}
}

func TestUnknownCPUProducesNoUtilisation(t *testing.T) {
	// Darwin reports no per-process CPU. It must produce nothing, not zero.
	s := newStore()
	noCPU := proc(100, "a", 1)
	noCPU.CPUUserNanos = U64{}
	noCPU.CPUSystemNanos = U64{}
	s.rec([]Info{noCPU}, at(0))
	obs, _, _ := s.rec([]Info{noCPU}, at(10))
	if obs[0].HasCPU {
		t.Error("a platform with no CPU data produced a utilisation")
	}
}

// ---------------------------------------------------------------------------
// IO delta semantics
// ---------------------------------------------------------------------------

func TestIODeltasSeedAndSuppressResets(t *testing.T) {
	s := newStore()
	obs, _, _ := s.rec([]Info{proc(100, "a", 1)}, at(0))

	s.applyIO(obs[0], IOCounters{ReadBytes: KnownU64(1000), WriteBytes: KnownU64(2000)})
	if obs[0].IOReadDelta.OK {
		t.Error("the first I/O observation emitted a delta equal to everything since process start")
	}

	obs, _, _ = s.rec([]Info{proc(100, "a", 1)}, at(30))
	s.applyIO(obs[0], IOCounters{ReadBytes: KnownU64(1500), WriteBytes: KnownU64(2500)})
	if obs[0].IOReadDelta != KnownU64(500) || obs[0].IOWriteDelta != KnownU64(500) {
		t.Errorf("deltas = %v/%v, want 500/500", obs[0].IOReadDelta, obs[0].IOWriteDelta)
	}

	obs, _, _ = s.rec([]Info{proc(100, "a", 1)}, at(60))
	s.applyIO(obs[0], IOCounters{ReadBytes: KnownU64(10), WriteBytes: KnownU64(10)})
	if obs[0].IOReadDelta.OK {
		t.Error("a counter reset emitted a wrapped delta")
	}
}

// ---------------------------------------------------------------------------
// Bounded state
// ---------------------------------------------------------------------------

func TestStateTableRespectsMaxTracked(t *testing.T) {
	s := newStore()
	s.reconcile(procs(5000, 20), testBoot, at(0), 4, 100, testRetention)
	if got := s.entries(); got > 100 {
		t.Errorf("state entries = %d, want at most 100", got)
	}
	if s.evictedByCapacity == 0 {
		t.Error("processes were shed for capacity without being counted")
	}
}

func TestStateAdmissionPrefersLowPIDs(t *testing.T) {
	// Low PIDs are the long-lived system services an operator cares about; high
	// PIDs are the churn. Under pressure the module should shed the churn.
	s := newStore()
	var infos []Info
	for i := 0; i < 100; i++ {
		infos = append(infos, proc(PID(9000-i), "p", uint64(i)))
	}
	s.reconcile(infos, testBoot, at(0), 4, 10, testRetention)

	if got := s.entries(); got != 10 {
		t.Fatalf("entries = %d, want 10", got)
	}
	// PIDs run 8901..9000, so the ten lowest are 8901..8910.
	for pid := range s.live {
		if pid > 8910 {
			t.Errorf("tracked PID %d; the ten lowest PIDs were 8901..8910", pid)
		}
	}
}

func TestUntrackedProcessesStillCountButGetNoDeltas(t *testing.T) {
	// A process that does not fit in the state table is still real: it must
	// appear in the observation list so process.count stays true.
	s := newStore()
	obs, _, _ := s.reconcile(procs(100, 5), testBoot, at(0), 4, 10, testRetention)
	if len(obs) != 100 {
		t.Fatalf("got %d observations, want all 100 processes", len(obs))
	}
	untracked := 0
	for _, o := range obs {
		if o.state == nil {
			untracked++
			if o.HasCPU {
				t.Error("an untracked process reported a CPU delta")
			}
		}
	}
	if untracked != 90 {
		t.Errorf("%d untracked observations, want 90", untracked)
	}
}

func TestRestartDetectionMapIsBounded(t *testing.T) {
	// A host running a million uniquely-named short-lived processes must not
	// accumulate a million retention entries.
	s := newStore()
	for cycle := 0; cycle < 20; cycle++ {
		infos := make([]Info, 0, 1000)
		for i := 0; i < 1000; i++ {
			infos = append(infos, proc(PID(10000+i), "unique"+itoa(cycle*1000+i), uint64(i)))
		}
		s.reconcile(infos, testBoot, at(cycle), 4, testMaxTrack, time.Hour)
	}
	if got := len(s.recentExits); got > 4096 {
		t.Errorf("restart-detection map holds %d entries, want at most 4096", got)
	}
}

func TestExitRetentionExpires(t *testing.T) {
	s := newStore()
	s.reconcile([]Info{proc(100, "gone", 1)}, testBoot, at(0), 4, testMaxTrack, 10*time.Second)
	s.reconcile(nil, testBoot, at(1), 4, testMaxTrack, 10*time.Second)
	if len(s.recentExits) != 1 {
		t.Fatalf("recentExits = %d, want 1", len(s.recentExits))
	}
	s.reconcile(nil, testBoot, at(100), 4, testMaxTrack, 10*time.Second)
	if len(s.recentExits) != 0 {
		t.Errorf("recentExits = %d after the retention window, want 0", len(s.recentExits))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
