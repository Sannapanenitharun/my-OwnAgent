//go:build linux

package logs

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Log discovery: find log files by asking which ones processes have open.
//
// Until now the agent tailed exactly the paths an operator listed, which has
// two costs. The obvious one is that an unlisted log is an invisible log. The
// subtler one is attribution: a line read from a configured path is known to
// have come from that path and nothing else, so "which application wrote
// this" was a question the agent could not answer -- the reason the
// Applications view had an empty log panel.
//
// Discovering through /proc/<pid>/fd answers both at once. Walking a
// process's descriptors and finding it holds /var/log/nginx/error.log open
// for writing establishes the file AND its owner in the same step: the
// attribution is not inferred from the content or the filename, it is a
// property of how the file was found. This is the mechanism Dynatrace's
// OneAgent uses, filters included.
//
// SECURITY. This walk runs as root and takes its candidate paths from
// whatever processes happen to have open, which is attacker-influenced input:
// a hostile process can open any file it can reach and would be delighted for
// a privileged agent to tail it into the log pipeline. So the paths are NOT
// trusted. A candidate must sit under one of a small set of allowed roots
// (/var/log by default) before anything opens it. Without that check a
// process opening /etc/shadow would have its contents shipped off the host,
// which is the kind of feature that gets an agent banned rather than
// deployed.

const (
	// procRootLogs is separate from the process module's constant so this
	// walk can be pointed at a fixture in tests.
	procRootLogs = "/proc"

	// A candidate must be at least this large. A file with nothing in it is
	// not yet evidence of anything, and log frameworks routinely open files
	// they have not written to.
	minLogBytes = 512

	// ...and must have been written to recently. A log nobody has appended to
	// in a week is history, and tailing it costs an open and a stat per cycle
	// forever.
	maxLogAge = 7 * 24 * time.Hour

	// Bounds on the walk itself. A host with thousands of processes must not
	// turn discovery into the most expensive thing the agent does.
	maxDiscoverProcs = 2048
	maxDiscoverFDs   = 256
	maxPathLen       = 4096
)

// discoverLogFiles returns the log files processes on this host have open for
// writing, mapped to the process that holds each one.
//
// Failure is never fatal and denial is never an error: another user's /proc
// entry is a privilege boundary, and a process that exits mid-walk is the
// normal case rather than a fault.
func discoverLogFiles(s Settings) map[string]logOwner {
	roots := s.DiscoverRoots
	if len(roots) == 0 {
		roots = defaultDiscoverRoots()
	}
	limit := s.MaxDiscovered
	if limit <= 0 {
		limit = 128
	}

	out := make(map[string]logOwner, 16)
	proc, err := os.Open(procRootLogs)
	if err != nil {
		return out
	}
	defer proc.Close()

	cutoff := time.Now().Add(-maxLogAge)
	scanned := 0
	for len(out) < limit && scanned < maxDiscoverProcs {
		names, err := proc.Readdirnames(256)
		if err != nil && len(names) == 0 {
			break
		}
		for _, name := range names {
			if len(out) >= limit || scanned >= maxDiscoverProcs {
				break
			}
			pid, err := strconv.Atoi(name)
			if err != nil || pid <= 0 {
				continue
			}
			scanned++
			scanProcessLogs(pid, roots, cutoff, limit, out)
		}
		if len(names) < 256 {
			break
		}
	}
	return out
}

func scanProcessLogs(pid int, roots []string, cutoff time.Time, limit int, out map[string]logOwner) {
	base := procRootLogs + "/" + strconv.Itoa(pid) + "/fd"
	dir, err := os.Open(base)
	if err != nil {
		return
	}
	defer dir.Close()

	comm := ""
	buf := make([]byte, maxPathLen)
	seen := 0
	for seen < maxDiscoverFDs && len(out) < limit {
		names, err := dir.Readdirnames(64)
		if err != nil && len(names) == 0 {
			return
		}
		for _, fd := range names {
			if seen >= maxDiscoverFDs || len(out) >= limit {
				return
			}
			seen++
			n, err := syscall.Readlink(base+"/"+fd, buf)
			if err != nil || n <= 0 {
				continue
			}
			path := string(buf[:n])

			// The allow-list is checked FIRST, before any syscall touches the
			// target. Everything below this line is work done on a path the
			// agent has already agreed it is willing to read.
			if !underAnyRoot(path, roots) {
				continue
			}
			if _, already := out[path]; already {
				continue
			}
			// The kernel appends " (deleted)" to the link target of an
			// unlinked file. Tailing one follows a handle nothing else can
			// see and that no rotation will ever reset.
			if strings.HasSuffix(path, " (deleted)") {
				continue
			}
			if !writable(base + "/../fdinfo/" + fd) {
				continue
			}
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			if st.Size() < minLogBytes || st.ModTime().Before(cutoff) {
				continue
			}
			if comm == "" {
				comm = readComm(pid)
			}
			out[path] = logOwner{PID: pid, Process: comm}
		}
		if len(names) < 64 {
			return
		}
	}
}

// writable reports whether a descriptor was opened for writing, read from
// /proc/<pid>/fdinfo/<n>'s octal `flags:` line.
//
// This is the check that separates "this process writes this log" from "this
// process happens to be reading a file". Without it, one program reading
// another's log would make the reader look like the author, which is exactly
// the wrong attribution to publish.
func writable(fdinfo string) bool {
	b, err := os.ReadFile(fdinfo)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "flags:")
		if !ok {
			continue
		}
		flags, err := strconv.ParseInt(strings.TrimSpace(rest), 8, 64)
		if err != nil {
			return false
		}
		// The access mode is the low two bits: 0 read-only, 1 write-only,
		// 2 read-write.
		mode := flags & 3
		return mode == syscall.O_WRONLY || mode == syscall.O_RDWR
	}
	return false
}

func readComm(pid int) string {
	b, err := os.ReadFile(procRootLogs + "/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func init() {
	// Wiring lives here rather than in platformSet so the tailer stays
	// portable: on every other platform this file does not exist and the
	// hook stays nil.
	discoverHook = discoverLogFiles
}
