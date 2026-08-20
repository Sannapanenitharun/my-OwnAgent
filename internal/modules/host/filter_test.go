package host

import (
	"fmt"
	"testing"
)

func names(fs []FilesystemStats) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Mountpoint
	}
	return out
}

func TestSelectBoundedIsDeterministic(t *testing.T) {
	// A cap applied in OS order would report a different subset every cycle.
	items := []string{"z", "m", "a", "q", "b"}
	id := func(s string) string { return s }

	kept, dropped := selectBounded(items, id, nil, 3)
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	want := []string{"a", "b", "m"}
	for i := range want {
		if kept[i] != want[i] {
			t.Fatalf("kept = %v, want %v", kept, want)
		}
	}

	// Same input in a different order must produce the same selection.
	shuffled := []string{"b", "z", "q", "a", "m"}
	kept2, _ := selectBounded(shuffled, id, nil, 3)
	for i := range want {
		if kept2[i] != want[i] {
			t.Fatalf("selection is order-dependent: %v vs %v", kept, kept2)
		}
	}
}

func TestSelectBoundedExcludesBySubstring(t *testing.T) {
	// The names needing exclusion are generated (vethAB12CD), so prefix
	// matching alone would force operators to enumerate the unpredictable.
	items := []string{"eth0", "vethAB12CD", "docker0", "wlan0"}
	kept, _ := selectBounded(items, func(s string) string { return s },
		[]string{"veth", "docker"}, 0)
	if len(kept) != 2 || kept[0] != "eth0" || kept[1] != "wlan0" {
		t.Fatalf("kept = %v", kept)
	}
}

func TestExclusionIsCaseInsensitive(t *testing.T) {
	if !excluded("vEthernet (Default Switch)", []string{"vethernet"}) {
		t.Fatal("exclusion should be case-insensitive")
	}
	if excluded("eth0", []string{"veth"}) {
		t.Fatal("eth0 must not be excluded by a veth rule")
	}
}

func TestNoCapMeansNoDrop(t *testing.T) {
	items := make([]string, 500)
	for i := range items {
		items[i] = fmt.Sprintf("i%03d", i)
	}
	kept, dropped := selectBounded(items, func(s string) string { return s }, nil, 0)
	if dropped != 0 || len(kept) != 500 {
		t.Fatalf("kept %d, dropped %d", len(kept), dropped)
	}
}

func TestFilterFilesystemsDropsPseudoFilesystems(t *testing.T) {
	// On a container host the overwhelming majority of mounts are
	// pseudo-filesystems no operator would alert on.
	s := DefaultSettings()
	in := []FilesystemStats{
		{Mountpoint: "/", FSType: "ext4", TotalBytes: KnownU64(1000)},
		{Mountpoint: "/sys/fs/cgroup", FSType: "cgroup2", TotalBytes: KnownU64(1000)},
		{Mountpoint: "/proc", FSType: "proc", TotalBytes: KnownU64(1000)},
		{Mountpoint: "/var/lib/docker/overlay2/x/merged", FSType: "overlay", TotalBytes: KnownU64(1000)},
		{Mountpoint: "/data", FSType: "xfs", TotalBytes: KnownU64(2000)},
	}
	kept, _ := filterFilesystems(in, s)
	got := names(kept)
	if len(got) != 2 {
		t.Fatalf("kept %v, want / and /data only", got)
	}
	if got[0] != "/" || got[1] != "/data" {
		t.Fatalf("kept %v", got)
	}
}

func TestFilterFilesystemsDropsZeroSizedMounts(t *testing.T) {
	// A mount with no usable size is a bind mount or placeholder; it carries
	// no information and would occupy a slot a real filesystem needs.
	s := DefaultSettings()
	in := []FilesystemStats{
		{Mountpoint: "/a", FSType: "ext4", TotalBytes: KnownU64(0)},
		{Mountpoint: "/b", FSType: "ext4"},
		{Mountpoint: "/c", FSType: "ext4", TotalBytes: KnownU64(100)},
	}
	kept, _ := filterFilesystems(in, s)
	if len(kept) != 1 || kept[0].Mountpoint != "/c" {
		t.Fatalf("kept %v", names(kept))
	}
}

func TestFilterFilesystemsRespectsCap(t *testing.T) {
	s := DefaultSettings()
	s.MaxFilesystems = 5
	s.FilesystemExclude = nil

	in := make([]FilesystemStats, 100)
	for i := range in {
		in[i] = FilesystemStats{
			Mountpoint: fmt.Sprintf("/mnt/%03d", i),
			FSType:     "ext4",
			TotalBytes: KnownU64(1000),
		}
	}
	kept, dropped := filterFilesystems(in, s)
	if len(kept) != 5 || dropped != 95 {
		t.Fatalf("kept %d, dropped %d; want 5 and 95", len(kept), dropped)
	}
}

func BenchmarkFilterFilesystemsLarge(b *testing.B) {
	s := DefaultSettings()
	in := make([]FilesystemStats, 500)
	for i := range in {
		fsType := "ext4"
		if i%3 == 0 {
			fsType = "overlay"
		}
		in[i] = FilesystemStats{
			Mountpoint: fmt.Sprintf("/var/lib/containers/%03d/merged", i),
			FSType:     fsType,
			TotalBytes: KnownU64(1000),
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filterFilesystems(in, s)
	}
}
