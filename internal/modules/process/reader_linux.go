//go:build linux

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Linux reads everything from procfs. No cgo, no shelling out, no third-party
// library, and no elevated privileges.
//
// What the agent deliberately never touches, even though procfs would allow it:
//
//	/proc/PID/environ   environment variables — the single richest source of
//	                    credentials on a typical host
//	/proc/PID/mem       process memory
//	/proc/PID/maps      memory layout
//	/proc/PID/smaps     ditto, and expensive enough to be a denial of service
//	                    against the host at scale
//
// That list is enforced by a test in internal/architecture, not just documented,
// because "we don't read that" is a security property and security properties
// erode when they live only in prose.

var (
	procRoot = "/proc"
	// pageSize converts the RSS field of /proc/PID/stat, which the kernel
	// reports in pages.
	pageSize = uint64(os.Getpagesize())
)

// enumChunk bounds how many directory names are pulled from /proc at a time.
// Reading all of them in one call would allocate a slice proportional to the
// process count, which is precisely the unbounded behaviour the module exists to
// avoid on a fifty-thousand-process host.
const enumChunk = 4096

// statBufSize is the reusable read buffer for /proc/PID/stat. The line is a few
// hundred bytes; a process named with 15 bytes of padding cannot make it exceed
// this, and the reader grows the buffer rather than truncating if one ever did.
const statBufSize = 1024

type linuxReader struct {
	// buf is reused across every per-process read in a cycle. Readers are called
	// from the single collection goroutine, one at a time, so a shared scratch
	// buffer is safe and removes one allocation per process.
	buf []byte

	// boot is cached because converting a process's start stamp to wall-clock
	// time needs it, and re-reading it per process would be fifty thousand
	// pointless file reads. It cannot change without the host rebooting, which
	// the agent does not survive.
	boot     BootIdentity
	bootRead bool

	// fields is the reusable field index for parseStat. Rebuilding it per
	// process would cost seven append-grows and three kilobytes each time.
	fields [][]byte
}

func platformSet() Set {
	r := &linuxReader{buf: make([]byte, statBufSize)}
	return Set{
		Lister:  r,
		IO:      r,
		Files:   r,
		Path:    r,
		Command: r,
		Boot:    r,
		Inline: map[Feature]bool{
			FeatureCPU:     true,
			FeatureMemory:  true,
			FeatureThreads: true,
			FeatureState:   true,
			FeatureUser:    true,
		},
	}
}

// readFileInto reads a small procfs file into a reusable buffer.
//
// It uses the raw syscalls rather than os.ReadFile for one reason that matters
// at scale: os.Open allocates an *os.File with a finalizer, and procfs files
// report a size of zero so ReadFile runs a grow loop. At fifty thousand
// processes per cycle those costs are the difference between a collection that
// allocates a few kilobytes and one that allocates tens of megabytes.
func (r *linuxReader) readFileInto(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	n := 0
	for {
		if n == len(r.buf) {
			r.buf = append(r.buf, make([]byte, len(r.buf))...)
		}
		got, err := syscall.Read(fd, r.buf[n:])
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if got == 0 {
			break
		}
		n += got
	}
	return r.buf[:n], nil
}

// classify maps an errno onto the three outcomes a per-process read can have.
// Getting this mapping right is what keeps normal churn out of the error
// counters.
func classify(err error) (vanished, denied bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT, syscall.ESRCH:
			// The process exited between enumeration and this read. Normal.
			return true, false
		case syscall.EACCES, syscall.EPERM:
			return false, true
		}
	}
	if os.IsNotExist(err) {
		return true, false
	}
	if os.IsPermission(err) {
		return false, true
	}
	return false, false
}

func (r *linuxReader) ListProcesses(ctx context.Context, opts ListOptions) (Listing, error) {
	if !r.bootRead {
		// A missing boot time costs absolute start timestamps, not the
		// enumeration: the instance key uses the raw stamp and is unaffected.
		r.boot, _ = r.ReadBootIdentity(ctx)
		r.bootRead = true
	}

	dir, err := os.Open(procRoot)
	if err != nil {
		return Listing{}, fmt.Errorf("opening %s: %w", procRoot, err)
	}
	defer dir.Close()

	var out Listing
	// The result slice is grown from a modest hint rather than sized from the
	// directory: a host that briefly forks a hundred thousand processes must not
	// be able to make the agent allocate proportionally in one step.
	out.Processes = make([]Info, 0, 256)

	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		names, err := dir.Readdirnames(enumChunk)
		if err != nil && len(names) == 0 {
			break // io.EOF, or the directory went away
		}
		for _, name := range names {
			pid, ok := numericPID(name)
			if !ok || !opts.accept(pid) {
				continue
			}
			info, err := r.readOne(pid, opts.WantUser)
			if err != nil {
				switch vanished, denied := classify(err); {
				case vanished:
					out.Vanished++
				case denied:
					out.Denied++
				default:
					out.Unreadable++
				}
				continue
			}
			out.Processes = append(out.Processes, info)
		}
		if len(names) < enumChunk {
			break
		}
	}
	return out, nil
}

// numericPID reports whether a /proc entry names a process. procfs also contains
// non-numeric entries (self, net, meminfo, ...) which must be skipped without
// treating them as malformed.
func numericPID(name string) (PID, bool) {
	if len(name) == 0 || name[0] < '1' || name[0] > '9' {
		return 0, false
	}
	v, err := strconv.ParseUint(name, 10, 31)
	if err != nil {
		return 0, false
	}
	return PID(v), true
}

func (r *linuxReader) readOne(pid PID, wantUser bool) (Info, error) {
	base := procRoot + "/" + strconv.Itoa(int(pid))
	data, err := r.readFileInto(base + "/stat")
	if err != nil {
		return Info{}, err
	}
	info, fields, err := parseStat(data, pageSize, r.fields)
	r.fields = fields
	if err != nil {
		return Info{}, err
	}
	// The PID in the file is authoritative. If it disagrees with the directory
	// name the entry was recycled underneath the read, so it is treated as churn
	// rather than trusted.
	if info.PID != pid {
		return Info{}, syscall.ESRCH
	}

	if r.boot.HasTime {
		info.StartTime = startTimeFrom(r.boot.Time, info.StartRaw)
		info.HasStartTime = true
	}

	if wantUser {
		// The owner of the /proc/PID directory is the process's real UID. One
		// stat(2) is far cheaper than parsing /proc/PID/status, which is a
		// fifty-line text file read purely for one number.
		var st syscall.Stat_t
		if err := syscall.Stat(base, &st); err == nil {
			info.UID = KnownU64(uint64(st.Uid))
		}
	}
	return info, nil
}

func (r *linuxReader) ReadIO(_ context.Context, pid PID) (IOCounters, error) {
	// /proc/PID/io is mode 0400 and owned by the process owner, so an unelevated
	// agent can read its own processes and is denied everything else. That is a
	// privilege boundary, reported as such, not a failure to fix by demanding
	// root.
	data, err := r.readFileInto(procRoot + "/" + strconv.Itoa(int(pid)) + "/io")
	if err != nil {
		return IOCounters{}, err
	}
	return parseIO(data)
}

func (r *linuxReader) ReadOpenFiles(_ context.Context, pid PID) (U64, error) {
	dir, err := os.Open(procRoot + "/" + strconv.Itoa(int(pid)) + "/fd")
	if err != nil {
		return U64{}, err
	}
	defer dir.Close()

	// Counted in chunks, and the descriptor NAMES are discarded immediately. A
	// process holding a million descriptors must cost the agent a bounded amount
	// of memory, and the names themselves are of no interest — only the count is
	// emitted, never a path.
	var n uint64
	for {
		names, err := dir.Readdirnames(enumChunk)
		n += uint64(len(names))
		if err != nil || len(names) < enumChunk {
			break
		}
	}
	return KnownU64(n), nil
}

func (r *linuxReader) ReadExecutablePath(_ context.Context, pid PID) (string, error) {
	// Readlink, never Open. The target is attacker-controlled and may point
	// anywhere; the agent reports the link and never follows it.
	buf := make([]byte, 512)
	n, err := syscall.Readlink(procRoot+"/"+strconv.Itoa(int(pid))+"/exe", buf)
	if err != nil {
		return "", err
	}
	if n <= 0 {
		return "", syscall.ENOENT
	}
	return string(buf[:n]), nil
}

func (r *linuxReader) ReadCommandLine(_ context.Context, pid PID) ([]string, error) {
	data, err := r.readFileInto(procRoot + "/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return nil, err
	}
	return parseCmdline(data, maxCommandArgs, maxCommandBytes), nil
}

func (r *linuxReader) ReadBootIdentity(_ context.Context) (BootIdentity, error) {
	var out BootIdentity
	// boot_id is a random UUID regenerated on every boot. It is exactly the
	// discriminator the instance key needs, and unlike boot time it cannot drift
	// when the clock is stepped by NTP shortly after start-up.
	if data, err := os.ReadFile(procRoot + "/sys/kernel/random/boot_id"); err == nil {
		out.ID = string(trimSpace(data))
	}
	if data, err := os.ReadFile(procRoot + "/stat"); err == nil {
		if t, err := parseBootTime(data); err == nil {
			out.Time = t
			out.HasTime = true
			if out.ID == "" {
				out.ID = "btime-" + strconv.FormatInt(t.Unix(), 10)
			}
		}
	}
	if out.ID == "" {
		return BootIdentity{}, fmt.Errorf("no boot identity available under %s", procRoot)
	}
	return out, nil
}

var (
	_ Lister        = (*linuxReader)(nil)
	_ IOReader      = (*linuxReader)(nil)
	_ FileReader    = (*linuxReader)(nil)
	_ PathReader    = (*linuxReader)(nil)
	_ CommandReader = (*linuxReader)(nil)
	_ BootReader    = (*linuxReader)(nil)
)
