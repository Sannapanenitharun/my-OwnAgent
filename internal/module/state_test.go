package module

import (
	"errors"
	"fmt"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
)

func TestUnsupportedIsDistinguishableFromFailure(t *testing.T) {
	// This distinction is what lets one binary ship to every platform without
	// ever faking data: unsupported degrades, failure restarts.
	err := Unsupported("eBPF requires Linux")
	if !IsUnsupported(err) {
		t.Fatal("Unsupported() error is not recognised by IsUnsupported")
	}
	if !errors.Is(err, platform.ErrUnsupported) {
		t.Fatal("unsupported error does not wrap platform.ErrUnsupported")
	}
	if IsUnsupported(errors.New("connection refused")) {
		t.Fatal("an ordinary failure was misclassified as unsupported")
	}
}

func TestUnsupportedWrappingSurvivesFurtherWrapping(t *testing.T) {
	err := fmt.Errorf("starting collector: %w", Unsupported("no BTF"))
	if !IsUnsupported(err) {
		t.Fatal("unsupported classification lost through wrapping")
	}
}

func TestStateTransitions(t *testing.T) {
	legal := []struct{ from, to State }{
		{StateRegistered, StateStarting},
		{StateStarting, StateRunning},
		{StateStarting, StateUnsupported},
		{StateRunning, StateStopping},
		{StateRunning, StateFailed},
		{StateFailed, StateStarting},
		{StateFailed, StateCrashLooping},
		{StateCrashLooping, StateStarting},
		{StateStopping, StateStopped},
		{StateStopped, StateStarting},
		{StatePaused, StateResuming},
		{StateDisabled, StateStarting},
	}
	for _, tc := range legal {
		if !CanTransition(tc.from, tc.to) {
			t.Errorf("transition %v -> %v should be legal", tc.from, tc.to)
		}
	}

	illegal := []struct{ from, to State }{
		// Skipping Starting would skip the permission re-check.
		{StateStopped, StateRunning},
		{StateRegistered, StateRunning},
		// Unsupported is terminal; it must not silently become running.
		{StateUnsupported, StateRunning},
		{StateUnsupported, StateStarting},
		{StateRunning, StateRegistered},
		{StateCrashLooping, StateRunning},
	}
	for _, tc := range illegal {
		if CanTransition(tc.from, tc.to) {
			t.Errorf("transition %v -> %v should be illegal", tc.from, tc.to)
		}
	}
}

func TestSelfTransitionIsAlwaysLegal(t *testing.T) {
	for s := StateRegistered; s <= StateDisabled; s++ {
		if !CanTransition(s, s) {
			t.Errorf("self-transition on %v should be legal", s)
		}
	}
}

func TestTerminalStates(t *testing.T) {
	terminal := map[State]bool{
		StateCrashLooping: true, StateUnsupported: true,
		StateDisabled: true, StateStopped: true,
	}
	for s := StateRegistered; s <= StateDisabled; s++ {
		if got, want := s.Terminal(), terminal[s]; got != want {
			t.Errorf("%v.Terminal() = %v, want %v", s, got, want)
		}
	}
}

func TestActiveStatesHoldResources(t *testing.T) {
	active := map[State]bool{
		StateStarting: true, StateRunning: true, StatePausing: true,
		StatePaused: true, StateResuming: true, StateStopping: true,
	}
	for s := StateRegistered; s <= StateDisabled; s++ {
		if got, want := s.Active(), active[s]; got != want {
			t.Errorf("%v.Active() = %v, want %v", s, got, want)
		}
	}
}

func TestEveryStateHasAName(t *testing.T) {
	for s := StateRegistered; s <= StateDisabled; s++ {
		if s.String() == "invalid" {
			t.Errorf("state %d has no name", int(s))
		}
	}
}

func TestStaticConfigurableRefusesReload(t *testing.T) {
	// Refusing loudly is the honest answer: the operator learns the reload did
	// not take effect instead of believing it did.
	var sc StaticConfigurable
	err := sc.PrepareConfig(t.Context(), configFragment())
	if err == nil {
		t.Fatal("StaticConfigurable accepted a runtime reconfiguration")
	}
	if !IsUnsupported(err) {
		t.Fatalf("refusal should be classified unsupported, got %v", err)
	}
}
