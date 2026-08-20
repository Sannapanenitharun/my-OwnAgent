package process

import (
	"fmt"
	"time"
)

// Parsers for the Linux procfs formats.
//
// They live in a file with NO build tag, and take []byte rather than a path, so
// that the entire Linux parsing surface is unit-testable on any development
// machine against captured fixtures. /proc/PID/stat in particular has a format
// that is easy to parse almost correctly — see parseStat — and "almost" here
// means silently attributing one process's CPU time to another.
//
// The byte helpers duplicate the host module's. Modules may not import each
// other, and two collectors sharing a release cadence costs far more than fifty
// lines of scanning code. See internal/architecture.

// clockTicksPerSecond is USER_HZ, the unit of the CPU time and start time fields
// in /proc/PID/stat.
//
// The correct way to obtain it is sysconf(_SC_CLK_TCK), which needs cgo. The
// kernel's USER_HZ is fixed at 100 on every architecture Linux supports for the
// procfs ABI — it is deliberately decoupled from CONFIG_HZ precisely so that
// this constant can be relied on — so the value is hardcoded WITH its reasoning
// rather than the module dragging in a C toolchain for one integer.
const clockTicksPerSecond = 100

// nanosPerTick converts a /proc/PID/stat CPU tick count to nanoseconds.
const nanosPerTick = uint64(time.Second) / clockTicksPerSecond

// forEachLine calls fn for each newline-terminated line, without allocating.
func forEachLine(data []byte, fn func(line []byte) error) error {
	for len(data) > 0 {
		i := indexByte(data, '\n')
		var line []byte
		if i < 0 {
			line, data = data, nil
		} else {
			line, data = data[:i], data[i+1:]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

func trimSpace(b []byte) []byte {
	for len(b) > 0 && isSpace(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && isSpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

// splitFields appends whitespace-separated fields of line to dst and returns it.
// Passing a reused dst keeps parsing allocation-free across calls, which is what
// makes a fifty-thousand-process sweep affordable.
func splitFields(line []byte, dst [][]byte) [][]byte {
	dst = dst[:0]
	i := 0
	for i < len(line) {
		for i < len(line) && isSpace(line[i]) {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && !isSpace(line[i]) {
			i++
		}
		dst = append(dst, line[start:i])
	}
	return dst
}

// parseUint parses a base-10 unsigned integer without allocating.
func parseUint(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("empty integer")
	}
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid integer %q", string(b))
		}
		d := uint64(c - '0')
		if n > (1<<64-1-d)/10 {
			return 0, fmt.Errorf("integer overflow in %q", string(b))
		}
		n = n*10 + d
	}
	return n, nil
}

// statFields are the 1-based field numbers of proc(5)'s /proc/PID/stat that this
// module reads. They are named rather than inlined because an off-by-one here
// produces a number that is wrong but entirely plausible — attributing a
// process's virtual memory to its thread count, say — and such a defect can
// survive a long time in production.
const (
	statFieldState      = 3
	statFieldPPID       = 4
	statFieldUTime      = 14
	statFieldSTime      = 15
	statFieldNumThreads = 20
	statFieldStartTime  = 22
	statFieldVSize      = 23
	statFieldRSS        = 24
)

// parseStat parses /proc/PID/stat.
//
// The format's one genuine trap is field 2, the executable name, which is
// wrapped in parentheses and is NOT escaped. A process may legally be named
// ") 0 0 0 0 (" — and a hostile one will be. Splitting the line on whitespace,
// or scanning for the first ')', therefore misaligns every subsequent field and
// hands an attacker control over the numbers the agent reports.
//
// The only correct approach is to take the text between the FIRST '(' and the
// LAST ')', because the kernel writes the name verbatim between a leading '('
// and a trailing ')' and nothing after the name can contain a parenthesis.
//
// pageSize converts the RSS field, which the kernel reports in pages.
//
// scratch is a reusable field buffer, returned grown so the caller can pass it
// back. This is not a micro-optimisation: /proc/PID/stat has about fifty fields,
// so building the index from an empty slice costs seven append-grows and three
// kilobytes EVERY CALL — and this function runs once per process per cycle. The
// first benchmark of it measured 3,413 B and 7 allocations per call, which at
// fifty thousand processes is 170 MB of garbage per cycle from parsing alone.
func parseStat(data []byte, pageSize uint64, scratch [][]byte) (Info, [][]byte, error) {
	open := indexByte(data, '(')
	closeIdx := lastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return Info{}, scratch, fmt.Errorf("malformed stat line: no comm field")
	}

	pid, err := parseUint(trimSpace(data[:open]))
	if err != nil {
		return Info{}, scratch, fmt.Errorf("malformed stat pid: %w", err)
	}

	info := Info{
		PID: PID(pid),
		// Copied, not aliased: the read buffer is reused for the next process,
		// and this name is retained on the tracked instance.
		Name: string(data[open+1 : closeIdx]),
	}

	// Fields from `state` onward, which is field 3.
	fields := splitFields(data[closeIdx+1:], scratch)
	at := func(fieldNumber int) ([]byte, bool) {
		i := fieldNumber - statFieldState
		if i < 0 || i >= len(fields) {
			return nil, false
		}
		return fields[i], true
	}

	if f, ok := at(statFieldState); ok && len(f) > 0 {
		info.State = stateFromProcChar(f[0])
	}
	if f, ok := at(statFieldPPID); ok {
		if v, err := parseUint(f); err == nil {
			info.PPID = PID(v)
		}
	}

	utime, uok := statUint(at, statFieldUTime)
	stime, sok := statUint(at, statFieldSTime)
	if uok {
		info.CPUUserNanos = KnownU64(utime * nanosPerTick)
	}
	if sok {
		info.CPUSystemNanos = KnownU64(stime * nanosPerTick)
	}
	if v, ok := statUint(at, statFieldNumThreads); ok {
		info.Threads = KnownU64(v)
	}
	if v, ok := statUint(at, statFieldStartTime); ok {
		info.StartRaw = v
		info.HasStartRaw = true
	}
	if v, ok := statUint(at, statFieldVSize); ok {
		info.VirtualBytes = KnownU64(v)
	}
	if v, ok := statUint(at, statFieldRSS); ok && pageSize > 0 {
		// Overflow here would need an RSS beyond the address space, but the
		// value is attacker-adjacent enough to check rather than assume.
		if v <= (1<<64-1)/pageSize {
			info.RSSBytes = KnownU64(v * pageSize)
		}
	}

	if !info.HasStartRaw {
		// Without a start stamp there is no instance key, and without an
		// instance key a recycled PID would inherit the previous process's
		// counter baselines. That is worse than omitting the process.
		return Info{}, fields, fmt.Errorf("stat line for pid %d has no start time", pid)
	}
	return info, fields, nil
}

func statUint(at func(int) ([]byte, bool), field int) (uint64, bool) {
	f, ok := at(field)
	if !ok {
		return 0, false
	}
	v, err := parseUint(f)
	if err != nil {
		return 0, false
	}
	return v, true
}

// stateFromProcChar maps proc(5)'s single-character state onto the module's
// closed set. Unrecognised characters become StateUnknown rather than being
// forced onto the nearest-looking value.
func stateFromProcChar(c byte) State {
	switch c {
	case 'R':
		return StateRunning
	case 'S':
		return StateSleeping
	case 'D':
		return StateDiskSleep
	case 'T', 't':
		return StateStopped
	case 'Z', 'X', 'x':
		return StateZombie
	case 'I':
		return StateIdle
	default:
		return StateUnknown
	}
}

// parseIO parses /proc/PID/io.
//
// read_bytes and write_bytes are preferred over rchar and wchar: the former
// count bytes that actually reached the block layer, while the latter count
// bytes passed to read(2) and write(2) including those served from page cache.
// Reporting rchar as disk I/O is a common and badly misleading error.
func parseIO(data []byte) (IOCounters, error) {
	var io IOCounters
	var fields [][]byte
	found := false

	err := forEachLine(data, func(line []byte) error {
		fields = splitFields(line, fields)
		if len(fields) < 2 {
			return nil
		}
		key := fields[0]
		if len(key) > 0 && key[len(key)-1] == ':' {
			key = key[:len(key)-1]
		}
		v, err := parseUint(fields[1])
		if err != nil {
			return nil
		}
		switch string(key) {
		case "read_bytes":
			io.ReadBytes = KnownU64(v)
			found = true
		case "write_bytes":
			io.WriteBytes = KnownU64(v)
			found = true
		case "syscr":
			io.ReadOps = KnownU64(v)
			found = true
		case "syscw":
			io.WriteOps = KnownU64(v)
			found = true
		}
		return nil
	})
	if err != nil {
		return IOCounters{}, err
	}
	if !found {
		return IOCounters{}, fmt.Errorf("no recognised counters in io")
	}
	return io, nil
}

// parseCmdline splits /proc/PID/cmdline, whose arguments are NUL-separated.
//
// A process can rewrite its own argv, so this data is untrusted content of
// arbitrary length. maxArgs and maxArgBytes bound what is returned; the caller
// bounds it again before anything is emitted.
func parseCmdline(data []byte, maxArgs, maxArgBytes int) []string {
	if len(data) == 0 {
		return nil
	}
	if len(data) > maxArgBytes {
		data = data[:maxArgBytes]
	}
	var out []string
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == 0 {
			if i > start {
				out = append(out, string(data[start:i]))
				if len(out) >= maxArgs {
					return out
				}
			}
			start = i + 1
		}
	}
	return out
}

// parseBootTime extracts the btime line from /proc/stat, which is the boot
// instant as a Unix timestamp.
func parseBootTime(data []byte) (time.Time, error) {
	var fields [][]byte
	var out time.Time
	found := false

	err := forEachLine(data, func(line []byte) error {
		if found || len(line) < 6 || string(line[:5]) != "btime" {
			return nil
		}
		fields = splitFields(line, fields)
		if len(fields) < 2 {
			return nil
		}
		v, err := parseUint(fields[1])
		if err != nil {
			return nil
		}
		out = time.Unix(int64(v), 0)
		found = true
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	if !found {
		return time.Time{}, fmt.Errorf("no btime line in stat")
	}
	return out, nil
}

// startTimeFrom converts a /proc/PID/stat start stamp into wall-clock time.
func startTimeFrom(boot time.Time, startTicks uint64) time.Time {
	return boot.Add(time.Duration(startTicks) * (time.Second / clockTicksPerSecond))
}
