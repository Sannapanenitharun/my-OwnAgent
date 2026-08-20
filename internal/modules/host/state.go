package host

// counterState converts the operating system's cumulative counters into the
// deltas the telemetry port's Counter instruments expect.
//
// Three cases have to be handled, and getting any of them wrong produces
// numbers that look plausible:
//
//   - FIRST OBSERVATION. There is no previous value, so there is no delta.
//     Emitting the raw cumulative value as a delta would report a spike equal
//     to everything since boot — the classic "my server did 4 TB of I/O in one
//     scrape" artefact. The first observation therefore emits nothing and only
//     seeds the baseline.
//
//   - COUNTER RESET. The device was removed and re-added, the interface was
//     recreated, or the host rebooted, so the counter went backwards. The delta
//     is not emitted and the baseline is re-seeded. Emitting a huge negative or
//     a wrapped positive would both be wrong.
//
//   - DISAPPEARANCE. An interface or device is gone. Its baseline is dropped so
//     that the map cannot grow without bound on a host that churns devices,
//     which is exactly what container and cloud hosts do.
type counterState struct {
	prev map[string]uint64
	// seen tracks which keys appeared in the current cycle, so vanished keys
	// can be reaped. It is reused across cycles to avoid allocating per cycle.
	seen map[string]struct{}
}

func newCounterState() *counterState {
	return &counterState{
		prev: make(map[string]uint64),
		seen: make(map[string]struct{}),
	}
}

// delta records a new cumulative value and returns the increase since the
// previous observation. ok is false when no delta may be emitted.
func (c *counterState) delta(key string, value uint64) (d uint64, ok bool) {
	c.seen[key] = struct{}{}
	prev, had := c.prev[key]
	c.prev[key] = value
	if !had {
		return 0, false
	}
	if value < prev {
		return 0, false
	}
	return value - prev, true
}

// beginCycle clears the per-cycle seen set.
func (c *counterState) beginCycle() {
	for k := range c.seen {
		delete(c.seen, k)
	}
}

// endCycle drops baselines for keys that did not appear this cycle.
func (c *counterState) endCycle() {
	for k := range c.prev {
		if _, ok := c.seen[k]; !ok {
			delete(c.prev, k)
		}
	}
}

// size reports how many baselines are retained. Tests use it to prove the map
// does not grow without bound.
func (c *counterState) size() int { return len(c.prev) }

// cpuState holds the previous aggregate and per-core CPU times so that
// utilisation can be computed as a ratio of deltas.
//
// Utilisation is a ratio, so the units of the underlying counters never need to
// be known — which is what lets Linux jiffies and Windows 100-nanosecond
// FILETIME units flow through the same code path.
type cpuState struct {
	prev    CPUTimes
	hasPrev bool

	prevCores    []CPUTimes
	hasPrevCores bool
}

// utilisation returns the fraction of time spent in each state since the
// previous sample. ok is false on the first sample or if the counters did not
// advance.
func (s *cpuState) utilisation(now CPUTimes) (busy, user, system, iowait, steal, irq float64, ok bool) {
	prev := s.prev
	hadPrev := s.hasPrev
	s.prev = now
	s.hasPrev = true

	if !hadPrev {
		return 0, 0, 0, 0, 0, 0, false
	}
	total := now.Total()
	prevTotal := prev.Total()
	if total <= prevTotal {
		// No time passed, or the counters were reset. Either way there is no
		// meaningful ratio; reporting 0% busy would claim an idle host.
		return 0, 0, 0, 0, 0, 0, false
	}
	span := float64(total - prevTotal)

	sub := func(a, b uint64) float64 {
		if a < b {
			return 0
		}
		return float64(a-b) / span
	}
	user = sub(now.User+now.Nice, prev.User+prev.Nice)
	system = sub(now.System, prev.System)
	iowait = sub(now.IOWait, prev.IOWait)
	steal = sub(now.Steal, prev.Steal)
	irq = sub(now.IRQ+now.SoftIRQ, prev.IRQ+prev.SoftIRQ)
	idle := sub(now.Idle, prev.Idle)

	busy = 1 - idle
	if busy < 0 {
		busy = 0
	}
	return busy, user, system, iowait, steal, irq, true
}
