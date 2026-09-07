package logs

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestTheFileBudgetTruncatesRatherThanThins pins a semantic that is easy to
// misread and was, in fact, misread.
//
// max.files caps the whole CYCLE, and patterns are walked in order. Exceeding
// it does not sample the paths evenly -- it cuts the list at the limit and
// never looks at the rest. Because the important files are listed first, a
// budget that is too small looks exactly like a budget that is fine: syslog
// and auth.log keep flowing while the tail of the list is silently dead.
//
// That is how nine patterns on a real host -- dmesg, the Apache-convention
// logs, the sar reports and the SSM audit trail -- were added, tested, and
// never read.
func TestTheFileBudgetTruncatesRatherThanThins(t *testing.T) {
	dir := t.TempDir()
	crowded := filepath.Join(dir, "crowded")
	quiet := filepath.Join(dir, "quiet")
	for _, d := range []string{crowded, quiet} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		name := filepath.Join(crowded, "app"+strconv.Itoa(i)+".log")
		if err := os.WriteFile(name, []byte("hello\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lonely := filepath.Join(quiet, "audit.log")
	if err := os.WriteFile(lonely, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths := []string{
		filepath.Join(crowded, "*.log"),
		filepath.Join(quiet, "*.log"), // listed last, like the new patterns
	}

	read := func(maxFiles int) map[string]bool {
		s := DefaultSettings()
		s.Paths = paths
		s.MaxFiles = maxFiles
		tl := newFileTailer()
		if _, err := tl.Read(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		seen := make(map[string]bool, len(tl.state))
		for p := range tl.state {
			seen[p] = true
		}
		return seen
	}

	// Budget below the first pattern's match count: the second pattern is
	// never reached.
	tight := read(10)
	if len(tight) != 10 {
		t.Errorf("opened %d files with max.files=10, want 10", len(tight))
	}
	if tight[lonely] {
		t.Error("the trailing pattern was read despite an exhausted budget; " +
			"if this is now fair scheduling, update this test deliberately")
	}

	// Budget above the total: everything is reached, including the pattern
	// that comes last.
	roomy := read(100)
	if !roomy[lonely] {
		t.Error("the trailing pattern was NOT read even with budget to spare -- " +
			"trailing patterns are dead weight")
	}
	if len(roomy) != 41 {
		t.Errorf("opened %d files with max.files=100, want 41", len(roomy))
	}
}

// TestTheDefaultBudgetCoversTheDefaultPaths is the guard that would have
// caught the starvation when the paths were widened.
//
// It cannot count files on the test machine, so it checks the thing that is
// checkable: that the default is not back down at the value that was chosen
// when the path list was a quarter of its current length. A real Ubuntu host
// with Docker measured 62 candidate files against a budget of 32.
func TestTheDefaultBudgetCoversTheDefaultPaths(t *testing.T) {
	s := DefaultSettings()
	if s.MaxFiles < 64 {
		t.Errorf("default max.files = %d, which is below the file count of a "+
			"real host running the default path list; trailing patterns will "+
			"never be opened", s.MaxFiles)
	}
}
