// Package clockfake provides a deterministic platform.Clock for tests.
//
// It lives in its own package so that no fake ever links into the production
// binary. Tests that exercise backoff, restart timing or periodic collection
// use this clock instead of sleeping, which keeps the suite fast and removes
// the timing flakiness that otherwise makes lifecycle tests unreliable.
package clockfake

import (
	"sort"
	"sync"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// Clock is a manually advanced platform.Clock. It is safe for concurrent use.
type Clock struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	waiters []*waiter
	seq     uint64
}

type waiter struct {
	deadline time.Time
	ch       chan time.Time
	// period is non-zero for tickers, which re-arm after firing.
	period time.Duration
	// stopped marks a ticker that will no longer re-arm.
	stopped bool
	seq     uint64
}

// New returns a Clock set to the given time. A zero start time is replaced with
// a fixed, non-zero instant so that callers can distinguish "unset" from "now".
func New(start time.Time) *Clock {
	if start.IsZero() {
		start = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	}
	c := &Clock{now: start}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.addLocked(&waiter{deadline: c.now.Add(d), ch: ch})
	return ch
}

func (c *Clock) NewTicker(d time.Duration) platform.Ticker {
	if d <= 0 {
		panic("clockfake: non-positive ticker interval")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &waiter{deadline: c.now.Add(d), ch: make(chan time.Time, 1), period: d}
	c.addLocked(w)
	return &ticker{c: c, w: w}
}

func (c *Clock) addLocked(w *waiter) {
	c.seq++
	w.seq = c.seq
	c.waiters = append(c.waiters, w)
	c.cond.Broadcast()
}

// Advance moves the clock forward and fires every waiter whose deadline has
// passed. Tickers re-arm; a ticker whose period is smaller than d fires once,
// matching the coalescing behaviour of time.Ticker on a slow consumer.
func (c *Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("clockfake: negative advance")
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now

	// Fire in deadline order so that dependent timers observe a consistent
	// sequence, breaking ties by registration order.
	due := make([]*waiter, 0, len(c.waiters))
	remaining := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.deadline.After(now) {
			due = append(due, w)
			if w.period > 0 && !w.stopped {
				// Re-arm relative to the deadline, skipping missed ticks.
				for !w.deadline.After(now) {
					w.deadline = w.deadline.Add(w.period)
				}
				remaining = append(remaining, w)
			}
			continue
		}
		remaining = append(remaining, w)
	}
	c.waiters = remaining
	c.mu.Unlock()

	sort.SliceStable(due, func(i, j int) bool {
		if due[i].deadline.Equal(due[j].deadline) {
			return due[i].seq < due[j].seq
		}
		return due[i].deadline.Before(due[j].deadline)
	})
	for _, w := range due {
		// Non-blocking: a buffered slot mirrors time.Ticker's drop-on-full
		// semantics and prevents Advance from deadlocking on a slow consumer.
		select {
		case w.ch <- now:
		default:
		}
	}
}

// BlockUntil waits until at least n waiters are registered. Tests use it to
// close the window between starting a goroutine and that goroutine arming its
// timer, which would otherwise be a race against Advance.
func (c *Clock) BlockUntil(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.waiters) < n {
		c.cond.Wait()
	}
}

// Waiters reports the number of currently armed timers.
func (c *Clock) Waiters() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

type ticker struct {
	c *Clock
	w *waiter
}

func (t *ticker) C() <-chan time.Time { return t.w.ch }

func (t *ticker) Stop() {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.w.stopped = true
	for i, w := range t.c.waiters {
		if w == t.w {
			t.c.waiters = append(t.c.waiters[:i], t.c.waiters[i+1:]...)
			break
		}
	}
}

var _ platform.Clock = (*Clock)(nil)
