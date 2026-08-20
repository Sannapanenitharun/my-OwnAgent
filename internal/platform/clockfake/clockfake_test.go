package clockfake

import (
	"sync"
	"testing"
	"time"
)

// The fake clock underpins every timing-sensitive test in the agent. If it is
// wrong, those tests are wrong in ways that look like product bugs, so it gets
// its own coverage.

func TestAfterFiresOnlyOnceDeadlinePassed(t *testing.T) {
	c := New(time.Time{})
	ch := c.After(10 * time.Second)

	c.Advance(9 * time.Second)
	select {
	case <-ch:
		t.Fatal("timer fired before its deadline")
	default:
	}

	c.Advance(time.Second)
	select {
	case got := <-ch:
		if want := c.Now(); !got.Equal(want) {
			t.Fatalf("fired at %v, want %v", got, want)
		}
	default:
		t.Fatal("timer did not fire at its deadline")
	}
}

func TestAfterFiresWhenAdvancePassesDeadline(t *testing.T) {
	c := New(time.Time{})
	ch := c.After(time.Second)
	c.Advance(time.Hour)
	select {
	case <-ch:
	default:
		t.Fatal("timer did not fire when the clock jumped past its deadline")
	}
}

func TestTickerRearms(t *testing.T) {
	c := New(time.Time{})
	tk := c.NewTicker(5 * time.Second)
	defer tk.Stop()

	for i := 0; i < 3; i++ {
		c.Advance(5 * time.Second)
		select {
		case <-tk.C():
		default:
			t.Fatalf("ticker did not fire on tick %d", i+1)
		}
	}
}

func TestTickerCoalescesMissedTicks(t *testing.T) {
	c := New(time.Time{})
	tk := c.NewTicker(time.Second)
	defer tk.Stop()

	// A slow consumer must see one tick, not ten, matching time.Ticker.
	c.Advance(10 * time.Second)
	got := 0
	for {
		select {
		case <-tk.C():
			got++
			continue
		default:
		}
		break
	}
	if got != 1 {
		t.Fatalf("got %d ticks after a 10x interval jump, want 1", got)
	}
}

func TestStoppedTickerDoesNotFire(t *testing.T) {
	c := New(time.Time{})
	tk := c.NewTicker(time.Second)
	tk.Stop()
	c.Advance(time.Minute)
	select {
	case <-tk.C():
		t.Fatal("stopped ticker fired")
	default:
	}
	if n := c.Waiters(); n != 0 {
		t.Fatalf("stopped ticker left %d waiters armed", n)
	}
}

func TestBlockUntilWaitsForRegistration(t *testing.T) {
	c := New(time.Time{})
	var wg sync.WaitGroup
	wg.Add(1)
	fired := make(chan struct{})

	go func() {
		defer wg.Done()
		ch := c.After(time.Second)
		<-ch
		close(fired)
	}()

	// Without BlockUntil this Advance would race the goroutine's After call.
	c.BlockUntil(1)
	c.Advance(time.Second)

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not observe the advance")
	}
	wg.Wait()
}

func TestConcurrentAdvanceAndRegister(t *testing.T) {
	c := New(time.Time{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); c.After(time.Second) }()
		go func() { defer wg.Done(); c.Advance(time.Millisecond) }()
	}
	wg.Wait()
	// The assertion is that -race reports nothing; reaching here suffices.
	if c.Now().IsZero() {
		t.Fatal("clock time was not advanced")
	}
}

func TestNegativeAdvancePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic on negative advance")
		}
	}()
	New(time.Time{}).Advance(-time.Second)
}
