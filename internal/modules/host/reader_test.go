package host

import (
	"runtime"
	"testing"
	"time"
)

// These exercise the REAL platform reader on whatever machine the suite runs
// on. They assert plausibility rather than exact values — a machine's memory
// size is not knowable in advance — but plausibility catches the failures that
// actually happen in OS collectors: a unit conversion off by 1024, a struct
// field read from the wrong offset, a counter that is really a pointer.

func TestPlatformSetIsCoherent(t *testing.T) {
	set := NewSet()

	for _, src := range AllSources {
		if set.Has(src) {
			if reason := set.UnsupportedReason(src); reason != "" {
				t.Errorf("source %s has a reader AND an unsupported reason %q", src, reason)
			}
			continue
		}
		// Every absent source must explain itself. "Not available" with no
		// reason is what makes operators open support tickets.
		if set.UnsupportedReason(src) == "" {
			t.Errorf("source %s is absent with no recorded reason", src)
		}
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if len(set.Available()) == 0 {
			t.Fatalf("no sources available on %s, which is a supported platform", runtime.GOOS)
		}
	}
}

func TestRealCPUReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.CPU == nil {
		t.Skipf("no CPU reader on %s", runtime.GOOS)
	}

	got, err := set.CPU.ReadCPU(t.Context(), false)
	if err != nil {
		t.Fatalf("ReadCPU: %v", err)
	}
	if !got.LogicalCount.OK || got.LogicalCount.V == 0 {
		t.Fatal("logical CPU count is unknown or zero")
	}
	if int(got.LogicalCount.V) != runtime.NumCPU() {
		t.Logf("logical count %d differs from runtime.NumCPU() %d (containers and cgroups can cause this)",
			got.LogicalCount.V, runtime.NumCPU())
	}
	if got.PhysicalCount.OK && got.PhysicalCount.V > got.LogicalCount.V {
		t.Fatalf("physical cores (%d) exceed logical CPUs (%d)", got.PhysicalCount.V, got.LogicalCount.V)
	}
	if got.HasTotal && got.Total.Total() == 0 {
		t.Fatal("CPU times are all zero on a running machine")
	}
}

func TestRealCPUTimesAdvance(t *testing.T) {
	set := NewSet()
	if set.CPU == nil {
		t.Skipf("no CPU reader on %s", runtime.GOOS)
	}
	first, err := set.CPU.ReadCPU(t.Context(), false)
	if err != nil || !first.HasTotal {
		t.Skip("cumulative CPU time is not available on this platform")
	}

	// Burn a little CPU so the counters must move.
	deadline := time.Now().Add(60 * time.Millisecond)
	for time.Now().Before(deadline) {
	}

	second, err := set.CPU.ReadCPU(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Total.Total() <= first.Total.Total() {
		t.Fatalf("CPU time did not advance: %d -> %d", first.Total.Total(), second.Total.Total())
	}
	// And a real utilisation must be computable and in range.
	var s cpuState
	s.utilisation(first.Total)
	busy, _, _, _, _, _, ok := s.utilisation(second.Total)
	if !ok {
		t.Fatal("no utilisation from two real samples")
	}
	if busy < 0 || busy > 1 {
		t.Fatalf("busy = %v, outside [0,1]", busy)
	}
}

func TestRealMemoryReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.Memory == nil {
		t.Skipf("no memory reader on %s", runtime.GOOS)
	}
	got, err := set.Memory.ReadMemory(t.Context())
	if err != nil {
		t.Fatalf("ReadMemory: %v", err)
	}
	if !got.Total.OK {
		t.Fatal("total memory is unknown")
	}
	// A machine running Go tests has at least 64 MiB and less than 64 TiB. A
	// kB/byte confusion lands outside this range in either direction.
	const minBytes = 64 << 20
	const maxBytes = 64 << 40
	if got.Total.V < minBytes || got.Total.V > maxBytes {
		t.Fatalf("total memory %d bytes is implausible; check unit conversion", got.Total.V)
	}
	if got.Used.OK && got.Used.V > got.Total.V {
		t.Fatalf("used (%d) exceeds total (%d)", got.Used.V, got.Total.V)
	}
	if got.Available.OK && got.Available.V > got.Total.V {
		t.Fatalf("available (%d) exceeds total (%d)", got.Available.V, got.Total.V)
	}
}

func TestRealFilesystemReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.Filesystem == nil {
		t.Skipf("no filesystem reader on %s", runtime.GOOS)
	}
	got, err := set.Filesystem.ReadFilesystems(t.Context())
	if err != nil {
		t.Fatalf("ReadFilesystems: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no filesystems reported on a running machine")
	}

	var withSize int
	for _, fs := range got {
		if fs.Mountpoint == "" {
			t.Error("a filesystem was reported with no mountpoint")
		}
		if !fs.TotalBytes.OK {
			continue
		}
		withSize++
		if fs.UsedBytes.OK && fs.UsedBytes.V > fs.TotalBytes.V {
			t.Errorf("%s: used (%d) exceeds total (%d)", fs.Mountpoint, fs.UsedBytes.V, fs.TotalBytes.V)
		}
		// On some Darwin volumes Bavail can exceed Blocks (snapshot / reserve
		// accounting). Treat that as "unknown available" rather than failing CI.
		if fs.AvailBytes.OK && fs.AvailBytes.V > fs.TotalBytes.V {
			if runtime.GOOS == "darwin" {
				t.Logf("%s: available (%d) exceeds total (%d); ignoring on darwin", fs.Mountpoint, fs.AvailBytes.V, fs.TotalBytes.V)
			} else {
				t.Errorf("%s: available (%d) exceeds total (%d)", fs.Mountpoint, fs.AvailBytes.V, fs.TotalBytes.V)
			}
		}
	}
	if withSize == 0 {
		t.Fatal("no filesystem reported a size")
	}

	// The default filters must leave something worth reporting.
	kept, _ := filterFilesystems(got, DefaultSettings())
	if len(kept) == 0 {
		t.Fatalf("default filters removed all %d filesystems", len(got))
	}
	t.Logf("%d filesystems, %d after default filtering", len(got), len(kept))
}

func TestRealNetworkReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.Network == nil {
		t.Skipf("no network reader on %s", runtime.GOOS)
	}
	got, err := set.Network.ReadInterfaces(t.Context())
	if err != nil {
		t.Fatalf("ReadInterfaces: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no interfaces reported on a running machine")
	}
	for _, n := range got {
		if n.Name == "" {
			t.Error("an interface was reported with no name")
		}
		// A counter read from the wrong struct offset is usually a pointer,
		// which lands far above any plausible byte count.
		const implausible = 1 << 60
		if n.RxBytes.OK && n.RxBytes.V > implausible {
			t.Errorf("%s: rx_bytes %d is implausible; check struct layout", n.Name, n.RxBytes.V)
		}
		if n.TxBytes.OK && n.TxBytes.V > implausible {
			t.Errorf("%s: tx_bytes %d is implausible; check struct layout", n.Name, n.TxBytes.V)
		}
	}

	kept, _ := selectBounded(got, func(i InterfaceStats) string { return i.Name },
		DefaultSettings().NetworkExclude, DefaultSettings().MaxInterfaces)
	t.Logf("%d interfaces, %d after default filtering", len(got), len(kept))
	if len(kept) > DefaultSettings().MaxInterfaces {
		t.Fatalf("filtering left %d interfaces, above the cap", len(kept))
	}
}

func TestRealOSReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.OS == nil {
		t.Skipf("no OS reader on %s", runtime.GOOS)
	}
	got, err := set.OS.ReadOS(t.Context())
	if err != nil {
		t.Fatalf("ReadOS: %v", err)
	}
	if got.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", got.OS, runtime.GOOS)
	}
	if got.Architecture != runtime.GOARCH {
		t.Errorf("architecture = %q, want %q", got.Architecture, runtime.GOARCH)
	}
	if got.Hostname == "" {
		t.Error("hostname is empty")
	}
	if got.KernelVersion == "" {
		t.Error("kernel version is empty")
	}
	if got.HasBootTime {
		if got.BootTime.After(time.Now()) {
			t.Errorf("boot time %v is in the future", got.BootTime)
		}
		if time.Since(got.BootTime) > 10*365*24*time.Hour {
			t.Errorf("boot time %v implies more than ten years of uptime", got.BootTime)
		}
	}
	t.Logf("os=%s platform=%s version=%s kernel=%s arch=%s",
		got.OS, got.Platform, got.PlatformVersion, got.KernelVersion, got.Architecture)
}

func TestRealDiskReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.Disk == nil {
		t.Skipf("no disk reader on %s: %s", runtime.GOOS, set.UnsupportedReason(SourceDisk))
	}
	got, err := set.Disk.ReadDisks(t.Context())
	if err != nil {
		t.Fatalf("ReadDisks: %v", err)
	}
	for _, d := range got {
		if d.Device == "" {
			t.Error("a device was reported with no name")
		}
	}
	t.Logf("%d block devices", len(got))
}

func TestRealLoadReaderIsPlausible(t *testing.T) {
	set := NewSet()
	if set.Load == nil {
		t.Skipf("no load reader on %s: %s", runtime.GOOS, set.UnsupportedReason(SourceLoad))
	}
	got, err := set.Load.ReadLoad(t.Context())
	if err != nil {
		t.Fatalf("ReadLoad: %v", err)
	}
	for name, v := range map[string]F64{"1m": got.Load1, "5m": got.Load5, "15m": got.Load15} {
		if !v.OK {
			t.Errorf("load %s is unknown", name)
			continue
		}
		if v.V < 0 || v.V > 100000 {
			t.Errorf("load %s = %v is implausible", name, v.V)
		}
	}
}

// Benchmarks against the real OS. These are the numbers that matter for the
// module's CPU budget, since they are what runs on a customer host.

func benchReader(b *testing.B, name string, fn func() error) {
	b.Helper()
	b.Run(name, func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := fn(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRealReaders(b *testing.B) {
	set := NewSet()
	ctx := b.Context()

	if set.CPU != nil {
		benchReader(b, "cpu", func() error { _, err := set.CPU.ReadCPU(ctx, false); return err })
	}
	if set.Memory != nil {
		benchReader(b, "memory", func() error { _, err := set.Memory.ReadMemory(ctx); return err })
	}
	if set.Disk != nil {
		benchReader(b, "disk", func() error { _, err := set.Disk.ReadDisks(ctx); return err })
	}
	if set.Filesystem != nil {
		benchReader(b, "filesystem", func() error { _, err := set.Filesystem.ReadFilesystems(ctx); return err })
	}
	if set.Network != nil {
		benchReader(b, "network", func() error { _, err := set.Network.ReadInterfaces(ctx); return err })
	}
	if set.OS != nil {
		benchReader(b, "os", func() error { _, err := set.OS.ReadOS(ctx); return err })
	}
	if set.Load != nil {
		benchReader(b, "load", func() error { _, err := set.Load.ReadLoad(ctx); return err })
	}
}
