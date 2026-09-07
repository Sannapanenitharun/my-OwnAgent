package logs

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// discoverHook is set by discover_linux.go on the one platform that has
// /proc. Everywhere else it stays nil and the tailer reads only what it was
// configured to read.
var discoverHook func(Settings) map[string]logOwner

// logOwner is the process found holding a discovered log file open. It is
// declared here rather than in the Linux file so the portable tailer can name
// the type without a build tag.
type logOwner struct {
	PID     int
	Process string
}

// underAnyRoot reports whether path sits inside one of the allowed roots.
//
// The comparison is on path SEGMENTS, not on a string prefix: "/var/logger"
// starts with "/var/log" and must not be admitted by it.
func underAnyRoot(path string, roots []string) bool {
	if len(path) == 0 || path[0] != '/' {
		return false
	}
	// A path containing ".." never reaches here through /proc -- the kernel
	// reports the resolved target -- but checking costs nothing and the day
	// this function acquires a second caller it will matter.
	if strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		return false
	}
	for _, root := range roots {
		root = strings.TrimRight(strings.TrimSpace(root), "/")
		if root == "" {
			continue
		}
		if strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// defaultDiscoverRoots is deliberately just the system log directory.
//
// Widening this is a security decision, not a convenience one: every added
// root is a directory in which any process on the host can nominate a file
// for a privileged agent to read and ship.
func defaultDiscoverRoots() []string {
	return []string{"/var/log"}
}

// fileTailer follows configured paths from the current end of each file so a
// restart does not re-ship history. Rotation (size shrinks) resets to offset 0.
type fileTailer struct {
	state map[string]*fileState

	// owners maps a discovered path to the process that writes it, and
	// lastDiscovery rate-limits the walk that produces it.
	owners        map[string]logOwner
	lastDiscovery time.Time
	now           func() time.Time
}

type fileState struct {
	offset int64
	size   int64
	// binary is decided once, on first sight. Re-sniffing every cycle would
	// pay for a decision that cannot change without the file being replaced,
	// and a replaced file resets this state anyway.
	binary bool
}

func newFileTailer() *fileTailer {
	return &fileTailer{
		state:  map[string]*fileState{},
		owners: map[string]logOwner{},
		now:    time.Now,
	}
}

// refreshDiscovery re-runs the descriptor walk when it is due. Discovered
// paths ACCUMULATE rather than replace: a process that has just restarted is
// briefly absent from /proc, and dropping its log the moment it does would
// lose exactly the lines explaining why it restarted. Paths that stop
// existing fall out at open time, which is the honest place to notice.
func (t *fileTailer) refreshDiscovery(s Settings) {
	if !s.DiscoverLogs || discoverHook == nil {
		return
	}
	every := s.DiscoverInterval
	if every <= 0 {
		every = 60 * time.Second
	}
	now := t.now()
	if !t.lastDiscovery.IsZero() && now.Sub(t.lastDiscovery) < every {
		return
	}
	t.lastDiscovery = now
	for path, owner := range discoverHook(s) {
		t.owners[path] = owner
	}
}

// discoveredPaths returns the discovered set in a stable order, so a batch cap
// truncates the same way twice rather than shipping a different arbitrary
// subset every cycle.
func (t *fileTailer) discoveredPaths() []string {
	if len(t.owners) == 0 {
		return nil
	}
	out := make([]string, 0, len(t.owners))
	for p := range t.owners {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (t *fileTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	paths := s.Paths
	if len(paths) == 0 {
		paths = defaultLogPaths()
	}
	t.refreshDiscovery(s)
	// Configured paths come first. If the file budget runs out, it runs out on
	// what the operator asked for, never on what the agent found by itself.
	paths = append(append([]string(nil), paths...), t.discoveredPaths()...)
	var out []Record
	opened := 0
	for _, pattern := range paths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			matches = []string{pattern}
		}
		if len(matches) == 0 {
			matches = []string{pattern}
		}
		for _, path := range matches {
			if excluded(path, s.Exclude) {
				continue
			}
			if opened >= s.MaxFiles {
				break
			}
			recs, ok := t.readPath(path, s)
			if ok {
				opened++
			}
			out = append(out, recs...)
			if len(out) >= s.MaxBatch {
				return out[:s.MaxBatch], nil
			}
		}
	}
	return out, nil
}

func (t *fileTailer) readPath(path string, s Settings) ([]Record, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return nil, false
	}
	cur := t.state[path]
	if cur == nil {
		// First sight: start at end so existing content is not re-shipped,
		// and decide once whether this is text at all.
		t.state[path] = &fileState{offset: st.Size(), size: st.Size(), binary: sniffBinary(f)}
		return nil, true
	}
	if cur.binary {
		return nil, false
	}
	if st.Size() < cur.size {
		cur.offset = 0
	}
	if _, err := f.Seek(cur.offset, io.SeekStart); err != nil {
		return nil, true
	}
	limit := int64(s.MaxBytesPerS)
	if limit <= 0 {
		limit = 256 * 1024
	}
	r := io.LimitReader(f, limit)
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, s.MaxLineBytes+1)
	var out []Record
	consumed := cur.offset
	for sc.Scan() {
		line := sc.Text()
		consumed += int64(len(sc.Bytes()) + 1)
		rec := Record{Body: line, Source: SourceFiles, File: path}
		if owner, ok := t.owners[path]; ok {
			rec.PID, rec.Process = owner.PID, owner.Process
		}
		out = append(out, rec)
		if len(out) >= s.MaxBatch {
			break
		}
	}
	cur.offset = consumed
	if cur.offset > st.Size() {
		cur.offset = st.Size()
	}
	cur.size = st.Size()
	return out, true
}

func excluded(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, p := range patterns {
		if p == path || p == base {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if strings.Contains(path, p) && strings.Contains(p, string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// Binary files must never be tailed as text.
//
// This became load-bearing the moment the default paths widened to catch logs
// with no .log suffix. /var/log holds several files that are not text at all
// and sit right next to ones that are: wtmp, btmp and lastlog are arrays of C
// structs, and atop and sysstat write their own binary formats. Tailing any of
// them line-by-line ships NUL bytes and struct padding into the log pipeline,
// where it is unreadable, unsearchable, and impossible to explain.
//
// Extension is not the test. /var/log/dmesg has no suffix and is text;
// /var/log/wtmp has no suffix and is not. So the file itself is asked.
const binarySniffLen = 512

// looksBinary reports whether the head of a file is not text.
//
// A NUL byte is the decisive signal -- no text log contains one, and every
// fixed-width C struct does. The control-character ratio catches the rest
// without rejecting UTF-8, whose continuation bytes are all >= 0x80 and are
// counted as text here.
func looksBinary(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	ctrl := 0
	for _, c := range head {
		if c == 0 {
			return true
		}
		// Tab, newline and carriage return are text; the rest of C0 is not.
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			ctrl++
		}
	}
	return ctrl*100/len(head) > 10
}

// sniffBinary reads the head of an open file without disturbing a caller that
// has not seeded its offset yet.
func sniffBinary(f *os.File) bool {
	head := make([]byte, binarySniffLen)
	n, err := f.ReadAt(head, 0)
	if n == 0 && err != nil {
		return false
	}
	return looksBinary(head[:n])
}
