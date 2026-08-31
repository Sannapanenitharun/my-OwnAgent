package container

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// A real /proc/net/dev, as rendered inside a container on a bridge network.
const procNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  999999    1234    0    0    0     0          0         0   999999    1234    0    0    0     0       0          0
  eth0: 8765432   65432    0    0    0     0          0         0  1234567   12345    0    0    0     0       0          0
  eth1:    1000      10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0
`

func TestNetDevSumsRealInterfacesOnly(t *testing.T) {
	n := parseNetDev(procNetDev)
	if !n.OK {
		t.Fatal("no counters parsed")
	}
	// eth0 + eth1, and deliberately not lo.
	if n.RxBytes != 8765432+1000 {
		t.Errorf("rx = %d, want %d", n.RxBytes, 8765432+1000)
	}
	if n.TxBytes != 1234567+2000 {
		t.Errorf("tx = %d, want %d", n.TxBytes, 1234567+2000)
	}
}

// TestLoopbackIsExcluded states the reason on its own, because the number is
// wrong rather than merely noisy when lo is included: a container talking to
// itself is not traffic anyone is measuring, and on a chatty one lo dwarfs the
// interface that carries real traffic.
func TestLoopbackIsExcluded(t *testing.T) {
	only := `Inter-|   Receive                        |  Transmit
 face |bytes  packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    lo: 500000    1000    0    0    0     0          0         0 500000    1000    0    0    0     0       0          0
`
	if n := parseNetDev(only); n.OK {
		t.Errorf("a loopback-only container reported %d/%d bytes", n.RxBytes, n.TxBytes)
	}
}

func TestNetDevRejectsGarbage(t *testing.T) {
	for name, text := range map[string]string{
		"empty":         "",
		"headers only":  "Inter-|   Receive  |  Transmit\n face |bytes packets|bytes packets\n",
		"no colon":      "eth0 1 2 3 4 5 6 7 8 9\n",
		"truncated row": "  eth0: 1 2 3\n",
		"non numeric":   "  eth0: abc def ghi jkl mno pqr stu vwx yz\n",
	} {
		t.Run(name, func(t *testing.T) {
			if n := parseNetDev(text); n.OK {
				t.Errorf("parsed %d/%d from %q", n.RxBytes, n.TxBytes, text)
			}
		})
	}
}

// TestOneBadRowDoesNotLoseTheGoodOnes: a container with a strange interface
// should still report the ones that parsed.
func TestOneBadRowDoesNotLoseTheGoodOnes(t *testing.T) {
	mixed := "  bad: nope\n" + "  eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n"
	n := parseNetDev(mixed)
	if !n.OK || n.RxBytes != 100 || n.TxBytes != 200 {
		t.Errorf("got ok=%v rx=%d tx=%d, want the eth0 row kept", n.OK, n.RxBytes, n.TxBytes)
	}
}

func counterFor(t *inproc.Telemetry, name, cid string) (int64, bool) {
	for _, p := range t.CounterSnapshot() {
		if p.Name != name {
			continue
		}
		for _, a := range p.Attrs {
			if a.Key == AttrContainerID && a.Value == cid {
				return p.Value, true
			}
		}
	}
	return 0, false
}

func netSample(id string, rx, tx uint64) sample {
	return sample{ShortID: id, Runtime: "docker", MemoryBytes: 1,
		Net: netCounters{RxBytes: rx, TxBytes: tx, OK: true}}
}

// TestFirstSightingIsABaselineNotTraffic. The kernel counter is the
// container's whole lifetime, so publishing it on the first read would report
// hours of traffic as one cycle's worth and produce a spike that never
// happened.
func TestFirstSightingIsABaselineNotTraffic(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)
	m.emitPerContainer(h, []sample{netSample("a", 1_000_000, 2_000_000)})
	if v, ok := counterFor(tel, MetricInstanceNetRx, "a"); ok {
		t.Errorf("first sighting published %d bytes; it is a baseline", v)
	}
}

func TestSubsequentCyclesPublishTheDelta(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)
	m.emitPerContainer(h, []sample{netSample("a", 1000, 2000)})
	m.emitPerContainer(h, []sample{netSample("a", 1500, 2200)})

	if v, _ := counterFor(tel, MetricInstanceNetRx, "a"); v != 500 {
		t.Errorf("rx = %d, want 500", v)
	}
	if v, _ := counterFor(tel, MetricInstanceNetTx, "a"); v != 200 {
		t.Errorf("tx = %d, want 200", v)
	}
}

// TestRestartRebaselinesRatherThanReportingNegative. A restarted container
// gets a fresh network namespace counting from zero. Treating the drop as a
// delta would either underflow or report a huge negative, and the bytes
// between the readings belong to a container that no longer exists.
func TestRestartRebaselinesRatherThanReportingNegative(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)
	m.emitPerContainer(h, []sample{netSample("a", 9_000_000, 9_000_000)})
	m.emitPerContainer(h, []sample{netSample("a", 40, 40)}) // restarted
	m.emitPerContainer(h, []sample{netSample("a", 140, 190)})

	rx, _ := counterFor(tel, MetricInstanceNetRx, "a")
	if rx != 100 {
		t.Errorf("rx = %d, want 100: only the traffic after the restart", rx)
	}
	if tx, _ := counterFor(tel, MetricInstanceNetTx, "a"); tx != 150 {
		t.Errorf("tx = %d, want 150", tx)
	}
}

// TestUnmeasuredNetworkIsAbsentNotZero. A host-networked container, or one
// with no readable process, has no measurement -- and zero is a claim that it
// sent nothing, which is a different and false statement.
func TestUnmeasuredNetworkIsAbsentNotZero(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)
	m.emitPerContainer(h, []sample{{ShortID: "hostnet", Runtime: "docker", MemoryBytes: 5}})
	m.emitPerContainer(h, []sample{{ShortID: "hostnet", Runtime: "docker", MemoryBytes: 5}})

	if _, ok := counterFor(tel, MetricInstanceNetRx, "hostnet"); ok {
		t.Error("a container with no network measurement reported one")
	}
	// Its memory must survive: one unmeasurable signal does not void the rest.
	if mem := seriesFor(tel, MetricInstanceMemory); mem["hostnet"] != 5 {
		t.Error("memory was dropped along with the unmeasured network")
	}
}

// TestStoppedContainerReleasesItsNetworkState guards a leak the CPU and memory
// path does not have: the delta baseline is a second map keyed on container
// id, and it has to be cleaned up with the series.
func TestStoppedContainerReleasesItsNetworkState(t *testing.T) {
	tel := inproc.NewTelemetry()
	m, h := newTestModule(tel)
	m.emitPerContainer(h, []sample{netSample("gone", 100, 100), netSample("stays", 100, 100)})
	m.emitPerContainer(h, []sample{netSample("stays", 200, 200)})

	m.mu.Lock()
	_, leaked := m.lastNet["gone"]
	_, kept := m.lastNet["stays"]
	m.mu.Unlock()

	if leaked {
		t.Error("a stopped container's baseline is still held")
	}
	if !kept {
		t.Error("the running container's baseline was dropped")
	}
}

// TestNetworkMetricsDoNotCollideWithTheHostsOwn. host.network.* is the whole
// machine, and a container's traffic is a component of it. Under one name any
// aggregation that did not inspect label sets would double-count.
func TestNetworkMetricsDoNotCollideWithTheHostsOwn(t *testing.T) {
	for _, n := range []string{MetricInstanceNetRx, MetricInstanceNetTx} {
		if n == "host.network.rx_bytes" || n == "host.network.tx_bytes" {
			t.Errorf("per-container metric %q reuses the host metric's name", n)
		}
		for _, rollup := range []string{MetricRunning, MetricMemoryUsage, MetricCPUUtilization} {
			if n == rollup {
				t.Errorf("per-container metric %q reuses a rollup's name", n)
			}
		}
	}
}

func TestNetworkRetirementIsBestEffort(t *testing.T) {
	m := &Module{}
	m.settings = DefaultSettings()
	h := module.Host{Telemetry: noRetire{inproc.NewTelemetry()}}
	m.emitPerContainer(h, []sample{netSample("a", 1, 1)})
	m.emitPerContainer(h, []sample{netSample("a", 2, 2)})
	m.emitPerContainer(h, nil) // must not panic
}
