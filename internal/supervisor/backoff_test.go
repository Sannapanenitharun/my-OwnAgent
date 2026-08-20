package supervisor

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

func restartCfg() config.RestartConfig {
	return config.RestartConfig{
		Enabled:        true,
		InitialBackoff: config.D(time.Second),
		MaxBackoff:     config.D(time.Minute),
		MaxRestarts:    5,
		Window:         config.D(10 * time.Minute),
	}
}

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	b := newBackoff(restartCfg(), nil)
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute,
	}
	for i, w := range want {
		if got := b.delay(i + 1); got != w {
			t.Errorf("delay(%d) = %v, want %v", i+1, got, w)
		}
	}
}

func TestBackoffNeverOverflowsToNegative(t *testing.T) {
	// 2^attempt grows past int64 nanoseconds quickly; a naive shift would wrap
	// and schedule a restart in the past, producing a hot restart loop.
	cfg := restartCfg()
	cfg.MaxBackoff = config.D(time.Duration(math.MaxInt64))
	b := newBackoff(cfg, nil)
	for _, attempt := range []int{60, 62, 64, 128, 1000, math.MaxInt32} {
		if got := b.delay(attempt); got < 0 {
			t.Fatalf("delay(%d) = %v, must never be negative", attempt, got)
		}
	}
}

func TestBackoffClampsNonPositiveAttempts(t *testing.T) {
	b := newBackoff(restartCfg(), nil)
	if got, want := b.delay(0), time.Second; got != want {
		t.Fatalf("delay(0) = %v, want %v", got, want)
	}
	if got, want := b.delay(-5), time.Second; got != want {
		t.Fatalf("delay(-5) = %v, want %v", got, want)
	}
}

func TestJitterStaysInsideItsBand(t *testing.T) {
	// Jitter breaks fleet-wide lockstep retries; it must not push a delay
	// outside the configured envelope.
	cfg := restartCfg()
	cfg.JitterFraction = 0.2
	b := newBackoff(cfg, rand.New(rand.NewPCG(7, 11)))

	base := 4 * time.Second // attempt 3
	lo := time.Duration(float64(base) * 0.8)
	hi := time.Duration(float64(base) * 1.2)

	sawSpread := false
	for i := 0; i < 2000; i++ {
		got := b.delay(3)
		if got < lo || got > hi {
			t.Fatalf("delay %v outside [%v, %v]", got, lo, hi)
		}
		if got != base {
			sawSpread = true
		}
	}
	if !sawSpread {
		t.Fatal("jitter produced no spread at all")
	}
}

func TestZeroJitterIsExact(t *testing.T) {
	cfg := restartCfg()
	cfg.JitterFraction = 0
	b := newBackoff(cfg, rand.New(rand.NewPCG(1, 2)))
	for i := 0; i < 100; i++ {
		if got := b.delay(2); got != 2*time.Second {
			t.Fatalf("delay(2) = %v, want exactly 2s with jitter disabled", got)
		}
	}
}

func TestRestartWindowAllowsUpToBudget(t *testing.T) {
	w := newRestartWindow(config.RestartConfig{MaxRestarts: 3, Window: config.D(time.Minute)})
	now := time.Now()
	for i := 1; i <= 3; i++ {
		if !w.record(now) {
			t.Fatalf("restart %d should be within budget", i)
		}
	}
	if w.record(now) {
		t.Fatal("the 4th restart should exhaust a budget of 3")
	}
}

func TestRestartWindowSlides(t *testing.T) {
	// A fixed total cap would quarantine a module that failed five times over
	// six months. Only failures happening *now* should count.
	w := newRestartWindow(config.RestartConfig{MaxRestarts: 2, Window: config.D(time.Minute)})
	base := time.Now()

	if !w.record(base) || !w.record(base.Add(time.Second)) {
		t.Fatal("first two restarts should be within budget")
	}
	if w.record(base.Add(2 * time.Second)) {
		t.Fatal("third restart inside the window should exhaust the budget")
	}
	// Far outside the window, the budget is available again.
	if !w.record(base.Add(time.Hour)) {
		t.Fatal("a restart long after the window should be permitted")
	}
	if got := w.count(base.Add(time.Hour)); got != 1 {
		t.Fatalf("window retains %d events, want 1 after ageing out", got)
	}
}

func TestRestartWindowReset(t *testing.T) {
	w := newRestartWindow(config.RestartConfig{MaxRestarts: 1, Window: config.D(time.Minute)})
	now := time.Now()
	w.record(now)
	if w.record(now) {
		t.Fatal("budget of 1 should be exhausted")
	}
	w.reset()
	if !w.record(now) {
		t.Fatal("reset should release the quarantine")
	}
}

func TestRestartWindowDoesNotGrowUnbounded(t *testing.T) {
	w := newRestartWindow(config.RestartConfig{MaxRestarts: 3, Window: config.D(time.Second)})
	base := time.Now()
	for i := 0; i < 10000; i++ {
		w.record(base.Add(time.Duration(i) * time.Second))
	}
	if got := len(w.events); got > 3 {
		t.Fatalf("window retained %d events; pruning is not bounding memory", got)
	}
}
