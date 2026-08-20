package host

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

// scaleReader returns a fake reader shaped like a large host: many mounts, many
// interfaces, many cores. These are the shapes that turn a cheap collector into
// an expensive one, so they are benchmarked rather than assumed.
func scaleReader(filesystems, interfaces, disks, cores int) *fakeReader {
	f := newFakeReader()

	f.fsFn = func(context.Context) ([]FilesystemStats, error) {
		out := make([]FilesystemStats, filesystems)
		for i := range out {
			out[i] = FilesystemStats{
				Mountpoint: "/mnt/vol" + strconv.Itoa(i),
				Device:     "/dev/sd" + strconv.Itoa(i),
				FSType:     "ext4",
				TotalBytes: KnownU64(1 << 40),
				UsedBytes:  KnownU64(1 << 39),
				AvailBytes: KnownU64(1 << 39),
				TotalInode: KnownU64(1 << 20),
				UsedInode:  KnownU64(1 << 19),
			}
		}
		return out, nil
	}
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		out := make([]InterfaceStats, interfaces)
		for i := range out {
			v := uint64(i * 1000)
			out[i] = InterfaceStats{
				Name:      "eth" + strconv.Itoa(i),
				RxBytes:   KnownU64(v),
				TxBytes:   KnownU64(v),
				RxPackets: KnownU64(v),
				TxPackets: KnownU64(v),
				RxErrors:  KnownU64(v),
				TxErrors:  KnownU64(v),
				RxDropped: KnownU64(v),
				TxDropped: KnownU64(v),
			}
		}
		return out, nil
	}
	f.diskFn = func(context.Context) ([]DiskStats, error) {
		out := make([]DiskStats, disks)
		for i := range out {
			v := uint64(i * 1000)
			out[i] = DiskStats{
				Device:     "sd" + strconv.Itoa(i),
				ReadBytes:  KnownU64(v),
				WriteBytes: KnownU64(v),
				ReadOps:    KnownU64(v),
				WriteOps:   KnownU64(v),
				IOTime:     KnownU64(v),
			}
		}
		return out, nil
	}
	f.cpuFn = func(_ context.Context, perCore bool) (CPUStats, error) {
		s := CPUStats{
			LogicalCount:  KnownU64(uint64(cores)),
			PhysicalCount: KnownU64(uint64(cores / 2)),
			HasTotal:      true,
			Total:         CPUTimes{User: 1000, System: 500, Idle: 8500},
		}
		if perCore {
			s.PerCore = make([]CPUTimes, cores)
		}
		return s, nil
	}
	return f
}

// benchEmit measures the emit path, which is what runs every cycle for the life
// of the agent. The reader is excluded so the number is attributable.
func benchEmit(b *testing.B, name string, filesystems, interfaces, disks, cores int) {
	b.Run(name, func(b *testing.B) {
		f := scaleReader(filesystems, interfaces, disks, cores)
		s := DefaultSettings()
		// Raise the caps so the benchmark measures work rather than the
		// filtering that would normally shed it.
		s.MaxFilesystems = filesystems + 1
		s.MaxInterfaces = interfaces + 1
		s.MaxDisks = disks + 1
		s.FilesystemExclude = nil
		s.NetworkExclude = nil
		s.DiskExclude = nil

		tel := newBenchTelemetry()
		em := newEmitter(newInstruments(tel), s)
		em.setEntity("ent-host-1")

		ctx := context.Background()
		cpu, _ := f.ReadCPU(ctx, false)
		mem, _ := f.ReadMemory(ctx)
		disksData, _ := f.ReadDisks(ctx)
		fsData, _ := f.ReadFilesystems(ctx)
		netData, _ := f.ReadInterfaces(ctx)
		osData, _ := f.ReadOS(ctx)
		loadData, _ := f.ReadLoad(ctx)
		now := time.Now()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			em.emitCPU(cpu)
			em.emitMemory(mem)
			em.emitDisk(disksData)
			em.emitFilesystems(fsData)
			em.emitNetwork(netData)
			em.emitOS(osData, now)
			em.emitLoad(loadData)
			em.items = 0
		}
	})
}

func BenchmarkFullCollection(b *testing.B) {
	benchEmit(b, "typical_host", 3, 4, 2, 8)
	benchEmit(b, "large_host", 64, 32, 16, 64)
	benchEmit(b, "container_host_500_mounts", 500, 200, 32, 96)
	benchEmit(b, "many_cores_256", 4, 4, 2, 256)
}

// nopTelemetry discards everything.
//
// Using the in-process adapter here would fold its map bookkeeping into the
// measurement, and the number wanted is the MODULE's emit cost — the part that
// stays the agent's responsibility once a real Telemetry Plane adapter is
// behind the port.
type nopTelemetry struct{}

func newBenchTelemetry() nopTelemetry { return nopTelemetry{} }

func (nopTelemetry) Counter(string) platform.Counter     { return nopInstrument{} }
func (nopTelemetry) Gauge(string) platform.Gauge         { return nopInstrument{} }
func (nopTelemetry) Histogram(string) platform.Histogram { return nopInstrument{} }
func (nopTelemetry) Emit(platform.Event)                 {}
func (nopTelemetry) EmitLog(platform.LogRecord)          {}
func (nopTelemetry) IngestTraces(platform.TracePayload)  {}

type nopInstrument struct{}

func (nopInstrument) Add(int64, ...platform.Attr)       {}
func (nopInstrument) Set(float64, ...platform.Attr)     {}
func (nopInstrument) Observe(float64, ...platform.Attr) {}

func BenchmarkCardinalityFiltering(b *testing.B) {
	s := DefaultSettings()
	items := make([]InterfaceStats, 1000)
	for i := range items {
		name := "eth" + strconv.Itoa(i)
		if i%3 == 0 {
			name = "veth" + strconv.Itoa(i)
		}
		items[i] = InterfaceStats{Name: name}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selectBounded(items, func(n InterfaceStats) string { return n.Name },
			s.NetworkExclude, s.MaxInterfaces)
	}
}

// TestHostModuleSteadyStateFootprint reports what the module actually costs.
//
// It is a test rather than a benchmark because the interesting figures are
// levels — goroutines held, memory retained after many cycles — not a rate. The
// assertions are loose ceilings that catch a regression in KIND (a goroutine per
// cycle, a map that never stops growing) rather than pinning numbers that
// differ per machine.
func TestHostModuleSteadyStateFootprint(t *testing.T) {
	const cycles = 200

	f := scaleReader(40, 24, 12, 32)
	h := newHarness(t, fullSet(f), map[string]string{
		"interval.cpu":        "1s",
		"interval.memory":     "1s",
		"interval.network":    "1s",
		"interval.load":       "1s",
		"interval.disk":       "1s",
		"interval.filesystem": "1s",
		"interval.os":         "1s",
	})

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutinesBefore := runtime.NumGoroutine()

	start := time.Now()
	h.start()
	startup := time.Since(start)

	for _, src := range AllSources {
		h.waitCollections(src, 1)
	}
	for i := 0; i < cycles; i++ {
		h.advance(2 * time.Second)
	}
	h.waitCollections(SourceCPU, cycles/2)

	goroutinesDuring := runtime.NumGoroutine()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	stats := h.mod.Statistics(t.Context()).Counters
	var collections int64
	for _, src := range AllSources {
		collections += stats[src.String()+".successes"]
	}

	t.Logf("host module: startup=%v collections=%d goroutines=+%d retained_heap=%.1f KiB",
		startup, collections, goroutinesDuring-goroutinesBefore, float64(retained)/1024)

	if delta := goroutinesDuring - goroutinesBefore; delta > 3 {
		t.Errorf("module holds %d extra goroutines after %d cycles; it must own one collection goroutine",
			delta, cycles)
	}
	// Retained heap must not scale with the number of cycles. A per-cycle leak
	// of even 1 KiB would be ~200 KiB here and unbounded in production.
	if retained > 2<<20 {
		t.Errorf("retained heap grew by %.1f KiB over %d cycles; something is accumulating",
			float64(retained)/1024, cycles)
	}
	if startup > 250*time.Millisecond {
		t.Errorf("module start took %v; Start must return promptly", startup)
	}

	if err := h.mod.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "goroutines to return to baseline", func() bool {
		return runtime.NumGoroutine() <= goroutinesBefore+1
	})
}

// TestCounterStateDoesNotGrowWithChurn proves the delta bookkeeping is bounded
// on a host whose interfaces come and go, which is what container hosts do.
func TestCounterStateDoesNotGrowWithChurn(t *testing.T) {
	cycle := 0
	f := newFakeReader()
	f.netFn = func(context.Context) ([]InterfaceStats, error) {
		cycle++
		out := make([]InterfaceStats, 20)
		for i := range out {
			// Every cycle presents an entirely different set of names.
			out[i] = InterfaceStats{
				Name:    fmt.Sprintf("veth%d-%d", cycle, i),
				RxBytes: KnownU64(uint64(i)),
			}
		}
		return out, nil
	}

	h := newHarness(t, fullSet(f), map[string]string{"interval.network": "1s", "network.max": "64"})
	h.start()
	h.waitCollections(SourceNetwork, 1)
	for i := 0; i < 50; i++ {
		h.advance(2 * time.Second)
	}
	h.waitCollections(SourceNetwork, 25)

	// 8 counters per interface, 20 interfaces = 160 live keys. Without reaping
	// this would be 160 x cycles.
	if got := h.mod.em.netCounters.size(); got > 200 {
		t.Fatalf("counter state holds %d baselines after 50 cycles of churn; it is leaking", got)
	}
}
