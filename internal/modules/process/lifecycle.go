package process

import (
	"sort"
	"time"
)

// tracked is the per-instance state the module retains between cycles.
//
// Its size is the module's memory model: this struct, times the number of live
// processes, bounded by max_tracked. Every field here has to earn its place,
// because on a fifty-thousand-process host an extra eight bytes is another four
// hundred kilobytes of resident memory on a customer's machine.
type tracked struct {
	key  InstanceKey
	name string

	// Counter baselines. Cumulative values from the OS, converted to deltas on
	// each observation.
	lastCPUNanos U64
	lastSampleAt time.Time
	lastIORead   U64
	lastIOWrite  U64

	// entityID is the platform-resolved process entity, cached for the life of
	// the instance. entityTried stops the module re-asking the platform every
	// cycle for a process it has already failed to resolve.
	entityID    string
	entityTried bool

	firstSeen time.Time
	// cycle is the last collection cycle in which this instance was observed.
	// An integer comparison is cheaper than a time comparison and cannot be
	// confused by a clock step.
	cycle uint64
}

// observation is one process as the module sees it after reconciliation:
// identity, derived values, and whatever optional detail was collected.
type observation struct {
	PID  PID
	PPID PID
	// Name is the SANITISED executable name. Nothing downstream ever sees the
	// raw kernel string.
	Name  string
	State State
	UID   U64
	Key   InstanceKey

	StartTime    time.Time
	HasStartTime bool

	// CPUUtilization is the fraction of TOTAL HOST CPU this process used since
	// the previous observation, so 0.5 means half the machine. HasCPU is false
	// on a process's first observation, because a utilisation is a ratio of two
	// samples and one sample cannot produce one.
	CPUUtilization float64
	HasCPU         bool

	RSSBytes     U64
	VirtualBytes U64
	Threads      U64

	// Detail collected only for the selected set.
	OpenFiles      U64
	IOReadDelta    U64
	IOWriteDelta   U64
	ExecutablePath string
	CommandLine    []string

	// EntityID is the platform-resolved process entity, or empty. It appears on
	// events only; it is never a metric attribute.
	EntityID string

	// cpuCumulative carries the raw counter through admission so that a newly
	// tracked instance can seed its baseline in the same cycle it is
	// discovered. Without it every process needs THREE observations before
	// reporting CPU — one to be admitted, one to seed, one to produce a ratio —
	// which at the default interval is ninety seconds of silence per process.
	cpuCumulative U64

	state *tracked
}

// lifecycleChange is one transition worth telling an operator about.
type lifecycleChange struct {
	Kind        string
	PID         PID
	PPID        PID
	Name        string
	EntityID    string
	StartTime   time.Time
	HasStart    bool
	Lifetime    time.Duration
	HasLifetime bool
	// Restart marks a start whose executable exited within the retention
	// window — the difference between "a new thing appeared" and "the thing you
	// care about bounced".
	Restart bool
}

// store is the bounded process state table.
//
// Two properties are non-negotiable and are what the churn tests exist to prove:
// it never grows without bound, and it never carries an exited process forever.
type store struct {
	live map[PID]*tracked

	// recentExits maps an executable NAME to when an instance of it last
	// exited. It is keyed by name rather than by PID because its only purpose
	// is restart detection, and it is bounded by the executable cap rather than
	// by the process count — which is what stops a churn storm turning exit
	// retention into unbounded growth.
	recentExits map[string]time.Time

	cycle uint64

	// scratch backs the observations of the current cycle.
	//
	// Observations do not outlive the cycle that produced them, so allocating
	// one per process per cycle is pure garbage. Benchmarking made the cost
	// concrete: at fifty thousand processes it was 100,000 allocations and 17 MB
	// per cycle, which at the default GOGC would park the agent's heap in the
	// tens of megabytes on exactly the hosts least able to spare it.
	//
	// The slab is sized ONCE per cycle, before any pointer into it is handed
	// out. Growing it mid-loop would reallocate and silently invalidate every
	// pointer already returned — which is why the sizing is separate from the
	// filling rather than an append.
	scratch []observation

	// Counters, all monotonic, all bounded in width by being int64.
	evictedByCapacity int64
	replacements      int64
	started           int64
	exited            int64
}

func newStore() *store {
	return &store{
		live:        make(map[PID]*tracked),
		recentExits: make(map[string]time.Time),
	}
}

// entries reports how many instances are tracked.
func (s *store) entries() int { return len(s.live) }

// reconcile folds one enumeration into the state table.
//
// It is the heart of the module, and it does four things that each exist because
// of a specific way a process collector goes wrong:
//
//  1. DETECTS PID REUSE by comparing instance keys, not PIDs. A recycled PID
//     produces an exit, a start and a replacement — never a silent inheritance
//     of the previous process's counter baselines.
//
//  2. COMPUTES DELTAS against the instance, so a counter that goes backwards
//     (which it can, on a PID that was replaced between cycles without the
//     module observing the gap) re-seeds instead of emitting a wrapped value.
//
//  3. BOUNDS GROWTH. New instances are admitted in ascending PID order until
//     max_tracked is reached. Ascending PID is not arbitrary: low PIDs are the
//     long-lived system services an operator cares about, and the high PIDs are
//     the churn. Under pressure the module sheds the churn and keeps the
//     services.
//
//  4. EVICTS on exit, immediately, rather than on a timer. An exited process's
//     state is released in the same cycle its disappearance is noticed.
//
// now must come from the injected clock, and numCPU is used to normalise CPU
// utilisation against the whole host.
func (s *store) reconcile(
	infos []Info, boot string, now time.Time, numCPU int,
	maxTracked int, exitRetention time.Duration,
) (obs []*observation, changes []lifecycleChange, invalidNames int) {
	s.cycle++

	s.sizeScratch(len(infos))

	obs = make([]*observation, 0, len(infos))
	var pending []int // indices of processes that need a new tracked entry

	for i := range infos {
		info := &infos[i]
		name, modified := sanitiseName(info.Name)
		if modified {
			invalidNames++
		}
		key := instanceKey(boot, *info)

		o := &s.scratch[i]
		// Assigned wholesale rather than field by field, so a slot reused from
		// the previous cycle cannot carry a stale value into this one.
		*o = observation{
			PID:           info.PID,
			PPID:          info.PPID,
			Name:          name,
			State:         info.State,
			UID:           info.UID,
			Key:           key,
			StartTime:     info.StartTime,
			HasStartTime:  info.HasStartTime,
			RSSBytes:      info.RSSBytes,
			VirtualBytes:  info.VirtualBytes,
			Threads:       info.Threads,
			cpuCumulative: info.CPUNanos(),
		}
		obs = append(obs, o)

		existing, had := s.live[info.PID]
		switch {
		case had && existing.key.SameInstance(key):
			existing.cycle = s.cycle
			o.state = existing
			o.EntityID = existing.entityID
			s.applyCPU(o, info, existing, now, numCPU)

		case had:
			// PID REUSE. The PID is the same and the instance is not, so the
			// process this module has been tracking is gone and a different one
			// holds its slot. Both facts are reported.
			changes = append(changes, exitChange(existing, now))
			s.noteExit(existing, now, exitRetention)
			delete(s.live, info.PID)
			s.exited++
			s.replacements++

			t := s.admit(o, now, maxTracked)
			if t != nil {
				changes = append(changes,
					startChange(o, s.isRestart(name, now, exitRetention)),
					lifecycleChange{Kind: EventReplaced, PID: info.PID, Name: name})
				s.started++
			}

		default:
			pending = append(pending, len(obs)-1)
		}
	}

	// New instances are admitted in a deterministic order so that a host over
	// its state cap tracks the SAME processes every cycle rather than a
	// different slice each time.
	sort.Slice(pending, func(i, j int) bool { return obs[pending[i]].PID < obs[pending[j]].PID })
	for _, idx := range pending {
		o := obs[idx]
		if t := s.admit(o, now, maxTracked); t != nil {
			changes = append(changes, startChange(o, s.isRestart(o.Name, now, exitRetention)))
			s.started++
		}
	}

	// Anything not seen this cycle has exited.
	for pid, t := range s.live {
		if t.cycle == s.cycle {
			continue
		}
		changes = append(changes, exitChange(t, now))
		s.noteExit(t, now, exitRetention)
		delete(s.live, pid)
		s.exited++
	}

	s.pruneExits(now, exitRetention)
	return obs, changes, invalidNames
}

// sizeScratch prepares the observation slab for a cycle of n processes.
//
// It is a separate step, before any pointer into the slab is handed out,
// because growing it mid-loop would reallocate and silently invalidate every
// pointer already returned.
//
// Retaining the slab trades garbage for resident memory, and that trade only
// stays favourable if the retention is bounded. A host that briefly forks a
// hundred thousand processes must not leave the agent holding twenty megabytes
// of slab forever, so the slab is released when it is far larger than the
// current cycle needs. The hysteresis is wide — release only above four times
// the need — so that ordinary fluctuation does not cause a realloc every cycle.
func (s *store) sizeScratch(n int) {
	if c := cap(s.scratch); c > 1024 && c > n*4 {
		s.scratch = nil
	}
	if cap(s.scratch) < n {
		s.scratch = make([]observation, n)
	}
	s.scratch = s.scratch[:n]
}

// admit adds a new instance to the table if there is room.
//
// A process that does not fit is NOT dropped from the collection: it still
// appears in obs, still counts toward process.count and the state distribution,
// and still contributes its memory and thread figures to the rollup. What it
// loses is delta-based values and entity binding, because both require state
// across cycles. That degradation is precise and is counted.
func (s *store) admit(o *observation, now time.Time, maxTracked int) *tracked {
	if maxTracked > 0 && len(s.live) >= maxTracked {
		s.evictedByCapacity++
		return nil
	}
	t := &tracked{
		key:       o.Key,
		name:      o.Name,
		firstSeen: now,
		cycle:     s.cycle,
		// Seed the CPU baseline on admission. The observation itself still
		// reports no utilisation — one sample cannot produce a ratio — but the
		// NEXT one can, rather than spending a second cycle seeding.
		lastCPUNanos: o.cpuCumulative,
		lastSampleAt: now,
	}
	s.live[o.PID] = t
	o.state = t
	return t
}

// applyCPU converts cumulative CPU time into a utilisation.
//
// Utilisation is a ratio of deltas, so the first observation of an instance
// necessarily produces none — reporting the cumulative value would claim a
// process had used a week of CPU in one interval. Both the "no previous sample"
// and the "counters went backwards" cases re-seed and emit nothing, which is the
// same rule the host module applies to interface and device counters.
func (s *store) applyCPU(o *observation, info *Info, t *tracked, now time.Time, numCPU int) {
	cur := info.CPUNanos()
	prev := t.lastCPUNanos
	prevAt := t.lastSampleAt

	t.lastCPUNanos = cur
	t.lastSampleAt = now

	if !cur.OK || !prev.OK || prevAt.IsZero() || numCPU <= 0 {
		return
	}
	elapsed := now.Sub(prevAt)
	if elapsed <= 0 || cur.V < prev.V {
		return
	}
	used := float64(cur.V - prev.V)
	capacity := float64(elapsed.Nanoseconds()) * float64(numCPU)
	if capacity <= 0 {
		return
	}
	util := used / capacity
	// Clamped rather than trusted. Scheduler accounting and a stepped clock can
	// each produce a ratio slightly above one, and a process reported at 340%
	// of the whole host is an obviously wrong number that costs an operator
	// real time to investigate.
	if util > 1 {
		util = 1
	}
	o.CPUUtilization = util
	o.HasCPU = true
}

// applyIO converts cumulative I/O counters into deltas for one observation.
func (s *store) applyIO(o *observation, io IOCounters) {
	t := o.state
	if t == nil {
		return
	}
	o.IOReadDelta = counterDelta(&t.lastIORead, io.ReadBytes)
	o.IOWriteDelta = counterDelta(&t.lastIOWrite, io.WriteBytes)
}

// counterDelta returns the increase since the previous cumulative value,
// re-seeding without emitting on the first observation or on a reset.
func counterDelta(prev *U64, cur U64) U64 {
	if !cur.OK {
		return U64{}
	}
	had := *prev
	*prev = cur
	if !had.OK || cur.V < had.V {
		return U64{}
	}
	return KnownU64(cur.V - had.V)
}

func (s *store) noteExit(t *tracked, now time.Time, retention time.Duration) {
	if retention <= 0 {
		return
	}
	s.recentExits[t.name] = now
}

func (s *store) isRestart(name string, now time.Time, retention time.Duration) bool {
	if retention <= 0 {
		return false
	}
	at, ok := s.recentExits[name]
	return ok && now.Sub(at) <= retention
}

// pruneExits drops restart-detection entries past their retention window.
//
// This map is the one piece of state keyed by something other than a live
// process, so it is the one that could grow without bound if left alone — a host
// that runs a million uniquely-named short-lived processes would otherwise
// accumulate a million entries. It is bounded twice: by time here, and by a hard
// cap that sheds the oldest.
func (s *store) pruneExits(now time.Time, retention time.Duration) {
	for name, at := range s.recentExits {
		if now.Sub(at) > retention {
			delete(s.recentExits, name)
		}
	}
	const maxRecentExits = 4096
	if len(s.recentExits) <= maxRecentExits {
		return
	}
	type entry struct {
		name string
		at   time.Time
	}
	all := make([]entry, 0, len(s.recentExits))
	for name, at := range s.recentExits {
		all = append(all, entry{name, at})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].at.Equal(all[j].at) {
			return all[i].name < all[j].name
		}
		return all[i].at.Before(all[j].at)
	})
	for _, e := range all[:len(all)-maxRecentExits] {
		delete(s.recentExits, e.name)
	}
}

func startChange(o *observation, restart bool) lifecycleChange {
	return lifecycleChange{
		Kind:      EventStarted,
		PID:       o.PID,
		PPID:      o.PPID,
		Name:      o.Name,
		EntityID:  o.EntityID,
		StartTime: o.StartTime,
		HasStart:  o.HasStartTime,
		Restart:   restart,
	}
}

func exitChange(t *tracked, now time.Time) lifecycleChange {
	c := lifecycleChange{
		Kind:     EventExited,
		PID:      t.key.PID,
		Name:     t.name,
		EntityID: t.entityID,
	}
	if !t.firstSeen.IsZero() {
		// Lifetime is measured from when the AGENT first saw the process, not
		// from the process's own start time, and the distinction matters: a
		// process that predates the agent would otherwise report a lifetime
		// that is really the host's uptime.
		c.Lifetime = now.Sub(t.firstSeen)
		c.HasLifetime = c.Lifetime >= 0
	}
	return c
}
