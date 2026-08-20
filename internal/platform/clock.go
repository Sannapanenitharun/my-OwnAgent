package platform

import "time"

// SystemClock is the production Clock backed by the runtime timer wheel.
type SystemClock struct{}

// NewSystemClock returns a Clock backed by package time.
func NewSystemClock() Clock { return SystemClock{} }

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (SystemClock) NewTicker(d time.Duration) Ticker {
	return &systemTicker{t: time.NewTicker(d)}
}

type systemTicker struct{ t *time.Ticker }

func (s *systemTicker) C() <-chan time.Time { return s.t.C }
func (s *systemTicker) Stop()               { s.t.Stop() }
