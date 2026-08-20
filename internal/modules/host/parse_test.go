package host

import (
	"strings"
	"testing"
	"time"
)

// These run on every platform, not just Linux. Kernel text formats are where
// collectors historically get subtly wrong numbers, and those defects are only
// cheap to find if the tests run on the machine the developer is using.

const procStatSample = `cpu  1234567 8901 234567 89012345 6789 0 12345 678 0 0
cpu0 308641 2225 58641 22253086 1697 0 3086 169 0 0
cpu1 308642 2225 58642 22253086 1697 0 3086 169 0 0
cpu2 308642 2225 58642 22253086 1697 0 3086 170 0 0
cpu3 308642 2226 58642 22253087 1698 0 3087 170 0 0
intr 123456789 0 0 0
ctxt 987654321
btime 1754870000
processes 123456
procs_running 2
procs_blocked 0
`

func TestParseProcStat(t *testing.T) {
	got, err := parseProcStat([]byte(procStatSample), false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasTotal {
		t.Fatal("aggregate cpu line was not parsed")
	}
	want := CPUTimes{
		User: 1234567, Nice: 8901, System: 234567, Idle: 89012345,
		IOWait: 6789, IRQ: 0, SoftIRQ: 12345, Steal: 678,
	}
	if got.Total != want {
		t.Fatalf("times = %+v, want %+v", got.Total, want)
	}
	// Logical CPUs are counted from the per-core lines even when per-core
	// collection is off.
	if !got.LogicalCount.OK || got.LogicalCount.V != 4 {
		t.Fatalf("logical count = %+v, want 4", got.LogicalCount)
	}
	if len(got.PerCore) != 0 {
		t.Fatalf("per-core data collected when not requested: %d entries", len(got.PerCore))
	}
}

func TestParseProcStatPerCore(t *testing.T) {
	got, err := parseProcStat([]byte(procStatSample), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PerCore) != 4 {
		t.Fatalf("per-core entries = %d, want 4", len(got.PerCore))
	}
	if got.PerCore[3].Steal != 170 {
		t.Fatalf("cpu3 steal = %d, want 170", got.PerCore[3].Steal)
	}
}

func TestParseProcStatToleratesShortAndLongLines(t *testing.T) {
	// The kernel has added columns to this line over releases (iowait, steal,
	// guest). A parser that demands an exact width breaks on kernels newer or
	// older than itself.
	short := "cpu  100 20 30 40\n"
	got, err := parseProcStat([]byte(short), false)
	if err != nil {
		t.Fatalf("short line rejected: %v", err)
	}
	if got.Total.Idle != 40 || got.Total.IOWait != 0 {
		t.Fatalf("short line parsed as %+v", got.Total)
	}

	long := "cpu  1 2 3 4 5 6 7 8 9 10 11 12 13\n"
	if _, err := parseProcStat([]byte(long), false); err != nil {
		t.Fatalf("long line rejected: %v", err)
	}
}

func TestParseProcStatRejectsMissingAggregate(t *testing.T) {
	if _, err := parseProcStat([]byte("intr 1\nctxt 2\n"), false); err == nil {
		t.Fatal("a /proc/stat with no cpu line must be an error, not a zero sample")
	}
}

func TestCPUTimesExcludeGuestFromTotal(t *testing.T) {
	// Guest time is already counted inside User. Adding it again inflates the
	// denominator and understates utilisation on every virtualised host.
	line := "cpu  100 0 0 100 0 0 0 0 5000 5000\n"
	got, err := parseProcStat([]byte(line), false)
	if err != nil {
		t.Fatal(err)
	}
	if total := got.Total.Total(); total != 200 {
		t.Fatalf("total = %d, want 200; guest columns must not be summed", total)
	}
}

const meminfoSample = `MemTotal:       16316104 kB
MemFree:         1234567 kB
MemAvailable:    9876543 kB
Buffers:          123456 kB
Cached:          4567890 kB
SwapCached:            0 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
HugePages_Total:       0
HugePages_Free:        0
Hugepagesize:       2048 kB
`

func TestParseMeminfo(t *testing.T) {
	got, err := parseMeminfo([]byte(meminfoSample))
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(16316104) * 1024; got.Total.V != want {
		t.Fatalf("total = %d, want %d (kB suffix must be honoured)", got.Total.V, want)
	}
	if want := uint64(9876543) * 1024; got.Available.V != want {
		t.Fatalf("available = %d, want %d", got.Available.V, want)
	}
	// Used must derive from MemAvailable, not from MemFree: Total-Free counts
	// reclaimable page cache as used and makes every healthy host look full.
	if want := (uint64(16316104) - uint64(9876543)) * 1024; got.Used.V != want {
		t.Fatalf("used = %d, want %d (must derive from MemAvailable)", got.Used.V, want)
	}
	if got.SwapUsed.V != 0 || !got.SwapUsed.OK {
		t.Fatalf("swap used = %+v, want a known 0", got.SwapUsed)
	}
}

func TestParseMeminfoWithoutMemAvailable(t *testing.T) {
	// Kernels before 3.14 have no MemAvailable; the fallback must still avoid
	// counting buffers and cache as used.
	old := "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 200 kB\nCached: 300 kB\n"
	got, err := parseMeminfo([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(400) * 1024; got.Used.V != want {
		t.Fatalf("used = %d, want %d", got.Used.V, want)
	}
}

func TestParseMeminfoRejectsGarbage(t *testing.T) {
	if _, err := parseMeminfo([]byte("nothing useful here\n")); err == nil {
		t.Fatal("a meminfo with no MemTotal must be an error, not a zero sample")
	}
}

func TestParseMeminfoIgnoresNonNumericLines(t *testing.T) {
	got, err := parseMeminfo([]byte("MemTotal: 1000 kB\nVmallocTotal: notanumber kB\n"))
	if err != nil {
		t.Fatalf("a single unparsable line must not fail the whole file: %v", err)
	}
	if got.Total.V != 1000*1024 {
		t.Fatalf("total = %d", got.Total.V)
	}
}

const diskstatsSample = `   8       0 sda 123456 1000 9876543 45678 234567 2000 8765432 56789 0 34567 102467
   8       1 sda1 1234 10 98765 456 2345 20 87654 567 0 345 1023
 253       0 dm-0 100 0 800 50 200 0 1600 100 0 150 150
   7       0 loop0 5 0 40 1 0 0 0 0 0 1 1
`

func TestParseDiskstats(t *testing.T) {
	got, err := parseDiskstats([]byte(diskstatsSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("parsed %d devices, want 4", len(got))
	}
	sda := got[0]
	if sda.Device != "sda" {
		t.Fatalf("device = %q", sda.Device)
	}
	// Sectors are always 512 bytes in this file regardless of the device's
	// real sector size; using the device's logical block size overcounts.
	if want := uint64(9876543) * 512; sda.ReadBytes.V != want {
		t.Fatalf("read bytes = %d, want %d", sda.ReadBytes.V, want)
	}
	if want := uint64(8765432) * 512; sda.WriteBytes.V != want {
		t.Fatalf("write bytes = %d, want %d", sda.WriteBytes.V, want)
	}
	if sda.ReadOps.V != 123456 || sda.WriteOps.V != 234567 {
		t.Fatalf("ops = %d/%d", sda.ReadOps.V, sda.WriteOps.V)
	}
	if sda.IOTime.V != 34567 {
		t.Fatalf("io time = %d, want 34567 (column 13)", sda.IOTime.V)
	}
}

func TestParseDiskstatsSkipsShortLines(t *testing.T) {
	got, err := parseDiskstats([]byte("   8       0 sda 1 2 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a truncated line produced %d devices", len(got))
	}
}

const netDevSample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    8901    0    0    0     0          0         0  1234567    8901    0    0    0     0       0          0
  eth0: 987654321 1234567   12   34    0     0          0      5678 123456789  987654   56   78    0     0       0          0
wlan0:12345 678 0 0 0 0 0 0 54321 876 0 0 0 0 0 0
`

func TestParseNetDev(t *testing.T) {
	got, err := parseNetDev([]byte(netDevSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d interfaces, want 3", len(got))
	}
	eth := got[1]
	if eth.Name != "eth0" {
		t.Fatalf("name = %q", eth.Name)
	}
	if eth.RxBytes.V != 987654321 || eth.TxBytes.V != 123456789 {
		t.Fatalf("rx/tx bytes = %d/%d", eth.RxBytes.V, eth.TxBytes.V)
	}
	if eth.RxErrors.V != 12 || eth.RxDropped.V != 34 {
		t.Fatalf("rx errs/drops = %d/%d", eth.RxErrors.V, eth.RxDropped.V)
	}
	// Transmit errors are column 11 overall, not column 3 of the transmit
	// group counted from the wrong place.
	if eth.TxErrors.V != 56 || eth.TxDropped.V != 78 {
		t.Fatalf("tx errs/drops = %d/%d, want 56/78", eth.TxErrors.V, eth.TxDropped.V)
	}
}

func TestParseNetDevHandlesNoSpaceBeforeColon(t *testing.T) {
	// An interface name long enough to touch the colon has no separating
	// space. This is a real format, not a hypothetical.
	got, err := parseNetDev([]byte(netDevSample))
	if err != nil {
		t.Fatal(err)
	}
	if got[2].Name != "wlan0" || got[2].RxBytes.V != 12345 {
		t.Fatalf("tightly packed line parsed as %+v", got[2])
	}
}

func TestParseLoadavg(t *testing.T) {
	got, err := parseLoadavg([]byte("0.52 0.71 0.85 2/1234 56789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Load1.V != 0.52 || got.Load5.V != 0.71 || got.Load15.V != 0.85 {
		t.Fatalf("load = %v/%v/%v", got.Load1.V, got.Load5.V, got.Load15.V)
	}
}

func TestParseLoadavgRejectsMalformed(t *testing.T) {
	for _, in := range []string{"", "0.5\n", "a b c\n"} {
		if _, err := parseLoadavg([]byte(in)); err == nil {
			t.Errorf("input %q should be rejected", in)
		}
	}
}

func TestParseUptime(t *testing.T) {
	got, err := parseUptime([]byte("123456.78 987654.32\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Duration(123456.78 * float64(time.Second)); got != want {
		t.Fatalf("uptime = %v, want %v", got, want)
	}
}

func TestParseOSRelease(t *testing.T) {
	sample := `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
`
	name, version := parseOSRelease([]byte(sample))
	if name != "Ubuntu" {
		t.Fatalf("name = %q", name)
	}
	if version != "22.04" {
		t.Fatalf("version = %q, want the quoted VERSION_ID unquoted", version)
	}
}

func TestParseOSReleaseFallsBackToID(t *testing.T) {
	name, _ := parseOSRelease([]byte("ID=alpine\nVERSION_ID=3.19\n"))
	if name != "alpine" {
		t.Fatalf("name = %q, want the ID when NAME is absent", name)
	}
}

const mountsSample = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
/dev/sda2 /boot ext4 ro,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1637224k,mode=755 0 0
/dev/sdb1 /mnt/my\040drive xfs rw,relatime 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime 0 0
`

func TestParseMounts(t *testing.T) {
	got, err := parseMounts([]byte(mountsSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("parsed %d mounts, want 7", len(got))
	}
	if got[2].Mountpoint != "/" || got[2].FSType != "ext4" || got[2].ReadOnly {
		t.Fatalf("root mount parsed as %+v", got[2])
	}
	if !got[3].ReadOnly {
		t.Fatal("a mount with the ro option was not marked read-only")
	}
}

func TestParseMountsUnescapesOctal(t *testing.T) {
	// A mountpoint with a space arrives as \040. Failing to unescape produces
	// a path that does not exist, and then a statfs failure that looks like a
	// permissions problem.
	got, err := parseMounts([]byte(mountsSample))
	if err != nil {
		t.Fatal(err)
	}
	if got[5].Mountpoint != "/mnt/my drive" {
		t.Fatalf("mountpoint = %q, want %q", got[5].Mountpoint, "/mnt/my drive")
	}
}

func TestParseMountsReadOnlyDoesNotMatchSubstrings(t *testing.T) {
	// "relatime" contains no "ro" option, but a naive substring search over
	// the option string would match "errors=remount-ro".
	got, err := parseMounts([]byte("/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReadOnly {
		t.Fatal("a read-write mount with errors=remount-ro was reported read-only")
	}
}

func TestParseUintRejectsNonDigits(t *testing.T) {
	for _, in := range []string{"", "12a", "-5", "1.5", " 1"} {
		if _, err := parseUint([]byte(in)); err == nil {
			t.Errorf("parseUint(%q) should fail", in)
		}
	}
}

func TestParseUintDetectsOverflow(t *testing.T) {
	if _, err := parseUint([]byte("99999999999999999999999")); err == nil {
		t.Fatal("overflow must be rejected rather than silently wrapping")
	}
}

func TestSplitFieldsHandlesTabsAndRuns(t *testing.T) {
	got := splitFields([]byte("  a\t\tb   c  "), nil)
	if len(got) != 3 || string(got[0]) != "a" || string(got[2]) != "c" {
		t.Fatalf("fields = %q", got)
	}
}

func TestForEachLineHandlesCRLFAndNoTrailingNewline(t *testing.T) {
	var lines []string
	err := forEachLine([]byte("a\r\nb\nc"), func(l []byte) error {
		lines = append(lines, string(l))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "a,b,c" {
		t.Fatalf("lines = %v", lines)
	}
}

// Parsing must not allocate per line: these files are read on every collection
// cycle for the life of the agent.
func BenchmarkParseProcStat(b *testing.B) {
	data := []byte(procStatSample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseProcStat(data, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseProcStatManyCores(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("cpu  1 2 3 4 5 6 7 8 0 0\n")
	for i := 0; i < 128; i++ {
		sb.WriteString("cpu0 1 2 3 4 5 6 7 8 0 0\n")
	}
	data := []byte(sb.String())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseProcStat(data, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseMeminfo(b *testing.B) {
	data := []byte(meminfoSample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseMeminfo(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseNetDev(b *testing.B) {
	data := []byte(netDevSample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseNetDev(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseMounts(b *testing.B) {
	data := []byte(mountsSample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseMounts(data); err != nil {
			b.Fatal(err)
		}
	}
}
