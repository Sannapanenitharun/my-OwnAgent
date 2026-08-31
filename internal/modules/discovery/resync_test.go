package discovery

import (
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// resyncHarness builds a module with a topology of n entities and an emitter
// whose per-cycle budget is deliberately smaller, which is the condition on any
// host with more inventory than MaxEventsPerCycle.
func resyncHarness(t *testing.T, n, budget int) (*Module, *emitter, *inproc.Telemetry) {
	t.Helper()
	tel := inproc.NewTelemetry()
	m := &Module{topo: newTopology()}
	for i := 0; i < n; i++ {
		// Keys are laid out so the ones that sort LAST are a distinct kind.
		// That is the shape of the real bug: "process|..." sorts after
		// "container|...", so processes were the entities always cut.
		kind := "container"
		if i >= n/2 {
			kind = "process"
		}
		key := kind + "|" + pad(i)
		m.topo.entities[key] = &entity{key: key, kind: platform.EntityKind(kind)}
	}
	s := DefaultSettings()
	s.MaxEventsPerCycle = budget
	em := newEmitter(newInstruments(tel), s)
	return m, em, tel
}

func pad(i int) string {
	s := ""
	for _, d := range []int{100, 10, 1} {
		s += string(rune('0' + (i/d)%10))
	}
	return s
}

func emittedKeys(tel *inproc.Telemetry) map[string]int {
	out := map[string]int{}
	for _, ev := range tel.EventSnapshot() {
		if ev.Name != EventEntityDiscovered {
			continue
		}
		for _, a := range ev.Attrs {
			if a.Key == AttrEntityKind {
				out[a.Value]++
			}
		}
	}
	return out
}

// TestTruncatedResyncResumesRatherThanDropping is the defect.
//
// A resync emits every entity, and the budget can be smaller than the
// inventory. Truncating there was permanent, not merely late: snapshot() is
// sorted by key, so the SAME entities were cut on every resync and could never
// arrive -- while relationship deltas naming them still went out, leaving the
// receiver with edges pointing at nodes it had never been told about.
func TestTruncatedResyncResumesRatherThanDropping(t *testing.T) {
	const total, budget = 40, 12
	m, em, tel := resyncHarness(t, total, budget)
	now := time.Now()

	cycles, seen := 0, 0
	for {
		em.beginEvents()
		done := m.emitEntitySnapshotFrom(em, now)
		cycles++
		if done {
			break
		}
		if cycles > 20 {
			t.Fatal("snapshot never completed; the cursor is not advancing")
		}
	}
	counts := emittedKeys(tel)
	seen = counts["container"] + counts["process"]

	if seen != total {
		t.Errorf("emitted %d of %d entities across %d cycles", seen, total, cycles)
	}
	// The entities that sort last are the ones the old code starved.
	if counts["process"] != total/2 {
		t.Errorf("process entities emitted = %d, want %d: the late-sorting kind "+
			"is exactly the one that used to be cut every time", counts["process"], total/2)
	}
	if cycles < 2 {
		t.Error("the whole inventory fitted in one cycle; the test is not exercising truncation")
	}
}

// TestNoEntityIsEmittedTwice. The cursor must not overlap, or a receiver sees
// repeated discoveries and the budget is spent re-sending what already landed.
func TestNoEntityIsEmittedTwice(t *testing.T) {
	m, em, tel := resyncHarness(t, 30, 7)
	now := time.Now()
	for i := 0; i < 20; i++ {
		em.beginEvents()
		if m.emitEntitySnapshotFrom(em, now) {
			break
		}
	}
	n := 0
	for _, ev := range tel.EventSnapshot() {
		if ev.Name == EventEntityDiscovered {
			n++
		}
	}
	if n != 30 {
		t.Errorf("emitted %d events for 30 entities: the cursor overlaps or skips", n)
	}
}

// TestCursorClearsWhenTheSnapshotFits. A host whose inventory is under budget
// must not carry a cursor into the next resync.
func TestCursorClearsWhenTheSnapshotFits(t *testing.T) {
	m, em, _ := resyncHarness(t, 10, 500)
	em.beginEvents()
	if !m.emitEntitySnapshotFrom(em, time.Now()) {
		t.Fatal("a 10-entity inventory did not fit in a 500-event budget")
	}
	if m.resyncCursor != "" {
		t.Errorf("cursor = %q after a complete snapshot, want empty", m.resyncCursor)
	}
}

// TestBudgetOfZeroDoesNotSpin. A misconfigured budget must not produce a
// snapshot that can never finish and never advances.
func TestBudgetOfZeroDoesNotSpin(t *testing.T) {
	m, em, _ := resyncHarness(t, 5, 0) // 0 means unlimited, per emitEvent
	em.beginEvents()
	if !m.emitEntitySnapshotFrom(em, time.Now()) {
		t.Error("an unlimited budget failed to complete the snapshot")
	}
}
