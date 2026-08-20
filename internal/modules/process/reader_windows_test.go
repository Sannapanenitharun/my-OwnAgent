//go:build windows

package process

import (
	"os"
	"testing"
	"unsafe"
)

// TestProcessEntry32LayoutMatchesWindows guards the one class of defect that
// does not announce itself.
//
// If the Go struct's layout disagrees with PROCESSENTRY32W, Windows does not
// return an error — it fills the buffer and the reader decodes a parent PID out
// of the middle of a pointer. Checking the size against the documented value,
// and sanity-checking the decoded fields against a process we know, converts
// that silent corruption into a test failure.
func TestProcessEntry32LayoutMatchesWindows(t *testing.T) {
	// dwSize is what Windows validates. On 64-bit Windows PROCESSENTRY32W is
	// 568 bytes: three DWORDs and four bytes of padding, a ULONG_PTR, five more
	// DWORDs, then 260 WCHARs.
	const want = 568
	if got := unsafe.Sizeof(processEntry32{}); got != want {
		t.Fatalf("sizeof(processEntry32) = %d, want %d; the layout does not match "+
			"PROCESSENTRY32W and every decoded field is suspect", got, want)
	}
}

func TestWindowsDecodesThisProcessCorrectly(t *testing.T) {
	// The strongest available check on the struct layout: enumerate, find
	// ourselves, and compare against values the Go runtime already knows.
	r := &windowsReader{}
	listing, err := r.ListProcesses(t.Context(), ListOptions{})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}

	self := PID(os.Getpid())
	parent := PID(os.Getppid())
	var found *Info
	for i := range listing.Processes {
		if listing.Processes[i].PID == self {
			found = &listing.Processes[i]
			break
		}
	}
	if found == nil {
		t.Fatal("the toolhelp snapshot did not include this process")
	}

	if found.PPID != parent {
		t.Errorf("ppid = %d, want %d (os.Getppid); the snapshot struct layout is wrong",
			found.PPID, parent)
	}
	if !found.Threads.OK || found.Threads.V == 0 || found.Threads.V > 10000 {
		t.Errorf("threads = %v, which is implausible for a Go test binary", found.Threads)
	}
	if !found.RSSBytes.OK || found.RSSBytes.V < 1<<20 {
		t.Errorf("RSS = %v; a Go test binary uses more than a megabyte", found.RSSBytes)
	}
	t.Logf("self decoded: pid=%d ppid=%d name=%q threads=%d rss=%d KiB",
		found.PID, found.PPID, found.Name, found.Threads.V, found.RSSBytes.V/1024)
}

// TestWindowsReportsDenialsRatherThanFailing records what an unelevated agent
// actually sees on a real Windows machine.
func TestWindowsReportsDenialsRatherThanFailing(t *testing.T) {
	r := &windowsReader{}
	listing, err := r.ListProcesses(t.Context(), ListOptions{})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}

	// Every process must still be reported, whether or not it could be opened:
	// process.count is a fact about the machine.
	if len(listing.Processes) < 10 {
		t.Errorf("only %d processes reported; no Windows host runs that few",
			len(listing.Processes))
	}

	var withCPU, withoutCPU int
	for _, p := range listing.Processes {
		if p.CPUNanos().OK {
			withCPU++
		} else {
			withoutCPU++
		}
	}
	t.Logf("windows: %d processes (%d openable, %d not), %d denied, %d vanished mid-scan",
		len(listing.Processes), withCPU, withoutCPU, listing.Denied, listing.Vanished)

	if withCPU == 0 {
		t.Error("no process could be opened at all; the reader is not working")
	}
}

func TestWindowsStateIsUnsupportedNotFaked(t *testing.T) {
	// Windows schedules threads, not processes. Reporting every process as
	// "running" would be a different measurement wearing a familiar name.
	set := platformSet()
	if set.Has(FeatureState) {
		t.Fatal("Windows declares per-process run state support, which it does not have")
	}
	if set.UnsupportedReason(FeatureState) == "" {
		t.Error("no reason recorded for the missing state feature")
	}

	r := &windowsReader{}
	listing, err := r.ListProcesses(t.Context(), ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range listing.Processes {
		if p.State != StateUnknown {
			t.Fatalf("pid %d reports state %s on Windows; it must be unknown", p.PID, p.State)
		}
	}
}

func TestWindowsCommandLineIsUnsupportedByPolicy(t *testing.T) {
	// Reading another process's command line on Windows requires locating its
	// PEB and calling ReadProcessMemory. That prohibition is worth more than the
	// field, so the reader must be absent rather than clever.
	set := platformSet()
	if set.Command != nil {
		t.Fatal("Windows provides a command-line reader; that would require reading process memory")
	}
	if set.Has(FeatureCommandLine) {
		t.Error("Windows claims command-line support")
	}
}

func TestWindowsFiletimeConversion(t *testing.T) {
	// The FILETIME epoch is 1601-01-01; getting the offset wrong shifts every
	// process start time by 369 years, which is obvious in a test and invisible
	// on a dashboard that formats it as a date.
	const unixEpochAsFiletime = 116444736000000000
	if got := filetimeToTime(unixEpochAsFiletime); got.Unix() != 0 {
		t.Errorf("the FILETIME Unix epoch converted to %v, want 1970-01-01", got)
	}
	// One second later.
	if got := filetimeToTime(unixEpochAsFiletime + 10_000_000); got.Unix() != 1 {
		t.Errorf("epoch+1s converted to %v", got)
	}
	// A value below the Unix epoch has no sensible representation and must not
	// wrap into a plausible-looking date.
	if got := filetimeToTime(1); !got.IsZero() {
		t.Errorf("a pre-1970 FILETIME converted to %v, want the zero time", got)
	}
}
