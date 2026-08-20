// Package guard runs untrusted in-process code safely: panics are recovered,
// and deadlines govern how long the caller waits without pretending to cancel
// work that Go cannot cancel.
//
// It exists because the same two mistakes are available to every component that
// invokes module code, and both were made — and fixed — during Stage 1:
//
//   - Cancelling the deadline context from inside the worker goroutine makes
//     both arms of the waiting select ready at once for any fast call, so the
//     runtime picks between them at random and a call that SUCCEEDED gets
//     reported as a timeout.
//
//   - Releasing the caller's in-flight slot when the deadline passes lets the
//     next scheduling tick dispatch a second concurrent call into code that is
//     still executing the first, accumulating a goroutine per tick.
//
// Both are encoded here once, with the reasoning, rather than re-derived by
// every caller. See docs/READINESS.md (Stage 1, defects 1 and 2).
package guard

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

// maxStackBytes caps a captured panic stack. An unbounded stack from a deeply
// recursive panic would itself become a memory event on a host the agent is
// supposed to protect.
const maxStackBytes = 8 << 10

// PanicError wraps a recovered panic.
//
// Note on content: Value is developer-authored panic text. Callers into module
// code must never construct a panic message from collected data (log lines,
// command lines, environment, headers), because panics surface on paths that
// run before the secret scrubber.
type PanicError struct {
	Value any
	Stack string
}

func (e *PanicError) Error() string { return fmt.Sprintf("panic: %v", e.Value) }

// Safe runs fn, converting a panic into a *PanicError.
func Safe(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = newPanicError(r)
		}
	}()
	return fn()
}

// SafeValue runs fn, returning the zero value of T and a *PanicError if fn
// panics.
func SafeValue[T any](fn func() T) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			v = zero
			err = newPanicError(r)
		}
	}()
	return fn(), nil
}

func newPanicError(r any) *PanicError {
	stack := debug.Stack()
	if len(stack) > maxStackBytes {
		stack = stack[:maxStackBytes]
	}
	return &PanicError{Value: r, Stack: string(stack)}
}

// Call runs fn on its own goroutine and returns as soon as fn completes or the
// deadline passes, whichever is first. Panics in fn become *PanicError.
//
// The second return value, settled, is closed only when fn GENUINELY returns —
// which may be long after the deadline. Callers that hold an in-flight slot for
// the callee must keep holding it until settled closes; see the package comment
// for what happens otherwise.
//
// Waiting for settled costs nothing in the common case, where fn returns before
// the deadline and settled is already closed.
func Call(ctx context.Context, d time.Duration, fn func(context.Context) error) (err error, settled <-chan struct{}) {
	cctx, cancel := context.WithTimeout(ctx, d)

	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		// The worker must NOT cancel cctx here; cancellation belongs to the
		// waiter alone. See the package comment.
		defer close(finished)
		done <- Safe(func() error { return fn(cctx) })
	}()

	select {
	case e := <-done:
		cancel()
		return e, finished

	case <-cctx.Done():
		// Re-check for a result before declaring a timeout: fn may have
		// completed in the same instant the deadline fired, and a real result
		// is always better evidence than the deadline.
		select {
		case e := <-done:
			cancel()
			return e, finished
		default:
		}
		// Leave cctx cancelled so fn observes it; cancel() here only releases
		// the timer, since the context is already done.
		cancel()
		return fmt.Errorf("timed out after %s: %w", d, cctx.Err()), finished
	}
}

// Value is Call for a function returning a value.
func Value[T any](ctx context.Context, d time.Duration, fn func(context.Context) T) (v T, err error, settled <-chan struct{}) {
	cctx, cancel := context.WithTimeout(ctx, d)

	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		got, gerr := SafeValue(func() T { return fn(cctx) })
		done <- result{v: got, err: gerr}
	}()

	select {
	case r := <-done:
		cancel()
		return r.v, r.err, finished
	case <-cctx.Done():
		select {
		case r := <-done:
			cancel()
			return r.v, r.err, finished
		default:
		}
		cancel()
		var zero T
		return zero, fmt.Errorf("timed out after %s: %w", d, cctx.Err()), finished
	}
}
