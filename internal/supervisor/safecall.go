package supervisor

import (
	"context"
	"time"

	"github.com/obsagent/observability-agent/internal/guard"
)

// The supervisor's panic isolation and deadline handling live in internal/guard
// so that every component invoking module code — the supervisor, and from
// Stage 2 the collector modules — shares one implementation of two rules that
// are easy to get subtly wrong. The names below are kept so that the semantics
// established and tested in Stage 1 are unchanged.

// PanicError wraps a panic recovered from module code.
//
// Recovering module panics is what makes failure isolation real: without it, a
// nil map write in the process module takes down host, logs, network and
// discovery with it.
type PanicError = guard.PanicError

// safeCall runs fn, converting a panic into a *PanicError.
func safeCall(fn func() error) error { return guard.Safe(fn) }

// safeValue runs fn, returning the zero value of T and a *PanicError if fn
// panics.
func safeValue[T any](fn func() T) (T, error) { return guard.SafeValue(fn) }

// withTimeout runs fn under a deadline, returning as soon as fn completes or
// the deadline passes. The returned channel closes only when fn genuinely
// returns; callers holding a module's in-flight slot must wait for it. See
// package guard for why.
func withTimeout(ctx context.Context, d time.Duration, fn func(context.Context) error) (error, <-chan struct{}) {
	return guard.Call(ctx, d, fn)
}

// timedCall is withTimeout for callers that hold no module in-flight slot and
// therefore have nothing to release. Only the configuration reload path
// qualifies: it is serialised by its own mutex, and a module that hangs in
// PrepareConfig blocks nothing but that one reload.
func timedCall(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	err, _ := guard.Call(ctx, d, fn)
	return err
}

// valueWithTimeout is withTimeout for a function returning a value.
func valueWithTimeout[T any](ctx context.Context, d time.Duration, fn func(context.Context) T) (T, error, <-chan struct{}) {
	return guard.Value(ctx, d, fn)
}
