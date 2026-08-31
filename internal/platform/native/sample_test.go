package native

import (
	"fmt"
	"testing"
)

func spansOfTrace(id string, n int) []spanJSON {
	out := make([]spanJSON, n)
	for i := range out {
		out[i] = spanJSON{TraceID: id, SpanID: fmt.Sprintf("%016x", i), Name: "op"}
	}
	return out
}

// TestSamplingKeepsWholeTraces is the property that matters more than the rate.
// Sampling per span would keep a scatter of spans from many traces, and a trace
// missing its middle looks like a broken system rather than a sampled one.
func TestSamplingKeepsWholeTraces(t *testing.T) {
	var all []spanJSON
	for i := 0; i < 40; i++ {
		all = append(all, spansOfTrace(fmt.Sprintf("%032x", i), 5)...)
	}
	kept, dropped := sampleSpans(all, 0.5)
	if dropped == 0 {
		t.Fatal("nothing was sampled out at rate 0.5")
	}

	counts := map[string]int{}
	for _, sp := range kept {
		counts[sp.TraceID]++
	}
	for id, n := range counts {
		if n != 5 {
			t.Errorf("trace %s kept %d of its 5 spans; traces must survive whole", id, n)
		}
	}
	if len(counts) == 0 {
		t.Error("every trace was dropped at rate 0.5")
	}
}

// TestTheDecisionIsStableAcrossCalls. An agent restart, a later cycle, or a
// second host must reach the same answer, or a trace spanning any of them is
// half recorded.
func TestTheDecisionIsStableAcrossCalls(t *testing.T) {
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("%032x", i*7919)
		first := keepTrace(id, 0.3)
		for j := 0; j < 5; j++ {
			if keepTrace(id, 0.3) != first {
				t.Fatalf("trace %s decided differently on repeat", id)
			}
		}
	}
}

// TestCaseDoesNotChangeTheDecision. Exporters differ on hex case, and the same
// trace arriving from two services must not be split by it.
func TestCaseDoesNotChangeTheDecision(t *testing.T) {
	lower := "4bf92f3577b34da6a3ce929d0e0e4736"
	upper := "4BF92F3577B34DA6A3CE929D0E0E4736"
	for _, rate := range []float64{0.1, 0.25, 0.5, 0.9} {
		if keepTrace(lower, rate) != keepTrace(upper, rate) {
			t.Errorf("rate %v: the same trace decided differently by case", rate)
		}
	}
}

func TestRateBoundaries(t *testing.T) {
	id := "4bf92f3577b34da6a3ce929d0e0e4736"
	if !keepTrace(id, 1) {
		t.Error("rate 1 dropped a trace")
	}
	if !keepTrace(id, 2) {
		t.Error("a rate above 1 dropped a trace")
	}
	if keepTrace(id, 0) {
		t.Error("rate 0 kept a trace")
	}
	if keepTrace(id, -1) {
		t.Error("a negative rate kept a trace")
	}
}

// TestUnidentifiedSpanIsKept. A span the agent cannot identify is not one it
// should silently discard, and there are too few to dominate any budget.
func TestUnidentifiedSpanIsKept(t *testing.T) {
	kept, dropped := sampleSpans([]spanJSON{{TraceID: "", Name: "anonymous"}}, 0.01)
	if len(kept) != 1 || dropped != 0 {
		t.Errorf("kept %d dropped %d, want the unidentified span kept", len(kept), dropped)
	}
}

// TestRateOneDoesNoWork. The default must not hash anything, because the
// overwhelmingly common configuration is "keep everything".
func TestRateOneDoesNoWork(t *testing.T) {
	in := spansOfTrace("abc", 3)
	kept, dropped := sampleSpans(in, sampleAll)
	if dropped != 0 || len(kept) != 3 {
		t.Errorf("kept %d dropped %d at rate 1", len(kept), dropped)
	}
	if &kept[0] != &in[0] {
		t.Error("rate 1 copied the batch instead of passing it through")
	}
}

// TestRateIsRoughlyHonoured. Not an exact assertion -- hashing is not a
// quota -- but a rate that produced 5% or 95% would be a bug, not variance.
func TestRateIsRoughlyHonoured(t *testing.T) {
	const n = 4000
	for _, rate := range []float64{0.1, 0.5, 0.9} {
		kept := 0
		for i := 0; i < n; i++ {
			if keepTrace(fmt.Sprintf("%032x", i*2654435761), rate) {
				kept++
			}
		}
		got := float64(kept) / n
		if got < rate-0.05 || got > rate+0.05 {
			t.Errorf("rate %v kept %.3f of traces, want within 0.05", rate, got)
		}
	}
}

// TestDroppedCountIsReported. An operator debugging a missing trace has to be
// able to tell "sampled out" from "never arrived".
func TestDroppedCountIsReported(t *testing.T) {
	var all []spanJSON
	for i := 0; i < 30; i++ {
		all = append(all, spansOfTrace(fmt.Sprintf("%032x", i), 2)...)
	}
	kept, dropped := sampleSpans(all, 0.5)
	if len(kept)+dropped != len(all) {
		t.Errorf("kept %d + dropped %d != %d received", len(kept), dropped, len(all))
	}
}
