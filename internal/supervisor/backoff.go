package supervisor

import (
	"math"
	"math/rand/v2"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// backoff computes restart delays.
//
// It is not safe for concurrent use. Each module owns its own backoff and it is
// only touched from the supervisor control loop, so no lock is paid on a path
// that runs once per failure.
type backoff struct {
	initial time.Duration
	max     time.Duration
	jitter  float64
	rng     *rand.Rand
}

func newBackoff(cfg config.RestartConfig, rng *rand.Rand) *backoff {
	return &backoff{
		initial: cfg.InitialBackoff.Std(),
		max:     cfg.MaxBackoff.Std(),
		jitter:  cfg.JitterFraction,
		rng:     rng,
	}
}

// delay returns the wait before restart attempt n, where n starts at 1.
//
// The curve is exponential from initial, capped at max, then randomised by
// +/- jitter. Jitter is not cosmetic: without it, every host in a fleet that
// lost the same backend retries in lockstep and the recovering backend is hit
// by a synchronised thundering herd at each backoff step.
func (b *backoff) delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := b.initial
	if d <= 0 {
		d = time.Second
	}

	// Compute in float64 and clamp, so a large attempt count cannot overflow
	// the int64 nanosecond representation into a negative delay.
	scaled := float64(d) * math.Pow(2, float64(attempt-1))
	maxD := float64(b.max)
	if maxD > 0 && scaled > maxD {
		scaled = maxD
	}
	if scaled > float64(math.MaxInt64/2) {
		scaled = float64(math.MaxInt64 / 2)
	}

	if b.jitter > 0 && b.rng != nil {
		// Uniform in [-jitter, +jitter] of the computed delay.
		factor := 1 + b.jitter*(2*b.rng.Float64()-1)
		scaled *= factor
	}
	if scaled < 0 {
		scaled = 0
	}
	return time.Duration(scaled)
}

// restartWindow implements sliding-window crash-loop detection.
//
// A fixed total restart cap would permanently quarantine a module that failed
// five times over six months of uptime. A sliding window quarantines only a
// module that is failing *now*, which is the condition that actually harms the
// host.
type restartWindow struct {
	max    int
	window time.Duration
	events []time.Time
}

func newRestartWindow(cfg config.RestartConfig) *restartWindow {
	return &restartWindow{max: cfg.MaxRestarts, window: cfg.Window.Std()}
}

// record registers a restart attempt at now and reports whether the module is
// still within its budget. A false result means the module is crash-looping.
func (w *restartWindow) record(now time.Time) bool {
	w.prune(now)
	w.events = append(w.events, now)
	return len(w.events) <= w.max
}

// prune drops events that have aged out of the window.
func (w *restartWindow) prune(now time.Time) {
	if w.window <= 0 {
		return
	}
	cutoff := now.Add(-w.window)
	i := 0
	for ; i < len(w.events); i++ {
		if w.events[i].After(cutoff) {
			break
		}
	}
	if i > 0 {
		w.events = append(w.events[:0], w.events[i:]...)
	}
}

// count returns the number of restarts currently inside the window.
func (w *restartWindow) count(now time.Time) int {
	w.prune(now)
	return len(w.events)
}

// reset clears the window. Called when an operator reloads configuration,
// which is the documented way to release a quarantined module.
func (w *restartWindow) reset() { w.events = w.events[:0] }
