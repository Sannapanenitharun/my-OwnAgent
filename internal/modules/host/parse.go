package host

import (
	"fmt"
	"strconv"
	"time"
)

// Parsers for the Linux procfs text formats.
//
// They live in a file with NO build tag, and take []byte rather than a path, so
// that the entire Linux parsing surface is unit-testable on any development
// machine against captured fixtures. Kernel text formats are where collectors
// historically get subtly wrong numbers — a column counted from the wrong end,
// a unit assumed rather than checked — and those defects are only cheap to find
// if the tests run everywhere.

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

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// splitFields appends whitespace-separated fields of line to dst and returns
// it. Passing a reused dst keeps parsing allocation-free across calls.
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

// parseProcStat parses /proc/stat.
//
// Unknown trailing columns are ignored on purpose: the kernel has added columns
// to this line over time (iowait in 2.5, steal in 2.6.11, guest later), and a
// parser that rejects unexpected width breaks on kernels newer than itself.
func parseProcStat(data []byte, perCore bool) (CPUStats, error) {
	var out CPUStats
	var fields [][]byte
	logical := uint64(0)

	err := forEachLine(data, func(line []byte) error {
		if len(line) < 4 || line[0] != 'c' || line[1] != 'p' || line[2] != 'u' {
			return nil
		}
		fields = splitFields(line, fields)
		if len(fields) < 5 {
			return nil
		}
		name := fields[0]

		times, err := parseCPUTimes(fields[1:])
		if err != nil {
			return fmt.Errorf("cpu line %q: %w", string(name), err)
		}

		if len(name) == 3 { // aggregate "cpu"
			out.Total = times
			out.HasTotal = true
			return nil
		}
		// "cpuN": a per-core line. Counted even when per-core collection is
		// off, because it is the cheapest reliable logical CPU count available.
		logical++
		if perCore {
			out.PerCore = append(out.PerCore, times)
		}
		return nil
	})
	if err != nil {
		return CPUStats{}, err
	}
	if !out.HasTotal {
		return CPUStats{}, fmt.Errorf("no aggregate cpu line in /proc/stat")
	}
	if logical > 0 {
		out.LogicalCount = KnownU64(logical)
	}
	return out, nil
}

func parseCPUTimes(f [][]byte) (CPUTimes, error) {
	var t CPUTimes
	dst := []*uint64{&t.User, &t.Nice, &t.System, &t.Idle, &t.IOWait, &t.IRQ, &t.SoftIRQ, &t.Steal}
	for i, p := range dst {
		if i >= len(f) {
			break
		}
		v, err := parseUint(f[i])
		if err != nil {
			return CPUTimes{}, err
		}
		*p = v
	}
	return t, nil
}

// parseMeminfo parses /proc/meminfo. Values are reported in kB with an explicit
// unit suffix; the suffix is checked rather than assumed.
func parseMeminfo(data []byte) (MemoryStats, error) {
	var m MemoryStats
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
			return nil // non-numeric lines exist; skip rather than fail the file
		}
		if len(fields) >= 3 && string(fields[2]) == "kB" {
			if v > (1<<64-1)/1024 {
				return nil
			}
			v *= 1024
		}

		switch string(key) {
		case "MemTotal":
			m.Total = KnownU64(v)
			found = true
		case "MemFree":
			m.Free = KnownU64(v)
		case "MemAvailable":
			m.Available = KnownU64(v)
		case "Buffers":
			m.Buffers = KnownU64(v)
		case "Cached":
			m.Cached = KnownU64(v)
		case "SwapTotal":
			m.SwapTotal = KnownU64(v)
		case "SwapFree":
			m.SwapFree = KnownU64(v)
		}
		return nil
	})
	if err != nil {
		return MemoryStats{}, err
	}
	if !found {
		return MemoryStats{}, fmt.Errorf("no MemTotal in /proc/meminfo")
	}
	deriveMemory(&m)
	return m, nil
}

// deriveMemory fills Used and SwapUsed from whatever the platform supplied.
//
// "Used" prefers Total-Available because MemAvailable is the kernel's own
// estimate of what a new allocation could actually get, which is what an
// operator means by "used". Total-Free is the classic wrong answer: it counts
// reclaimable page cache as used and makes every healthy Linux host look full.
func deriveMemory(m *MemoryStats) {
	if !m.Used.OK && m.Total.OK {
		switch {
		case m.Available.OK && m.Total.V >= m.Available.V:
			m.Used = KnownU64(m.Total.V - m.Available.V)
		case m.Free.OK:
			used := m.Total.V
			for _, part := range []U64{m.Free, m.Buffers, m.Cached} {
				if part.OK && used >= part.V {
					used -= part.V
				}
			}
			m.Used = KnownU64(used)
		}
	}
	if !m.SwapUsed.OK && m.SwapTotal.OK && m.SwapFree.OK && m.SwapTotal.V >= m.SwapFree.V {
		m.SwapUsed = KnownU64(m.SwapTotal.V - m.SwapFree.V)
	}
}

// sectorSize is the unit of the sector columns in /proc/diskstats. The kernel
// reports these in fixed 512-byte units regardless of the device's real sector
// size; using the device's logical block size here is a classic overcount.
const sectorSize = 512

// parseDiskstats parses /proc/diskstats.
func parseDiskstats(data []byte) ([]DiskStats, error) {
	var out []DiskStats
	var fields [][]byte

	err := forEachLine(data, func(line []byte) error {
		fields = splitFields(line, fields)
		// major minor name reads rmerged sectors_read ms_read writes wmerged
		// sectors_written ms_write in_flight ms_io weighted_ms_io
		if len(fields) < 14 {
			return nil
		}
		name := string(fields[2])
		readOps, e1 := parseUint(fields[3])
		readSect, e2 := parseUint(fields[5])
		writeOps, e3 := parseUint(fields[7])
		writeSect, e4 := parseUint(fields[9])
		ioMs, e5 := parseUint(fields[12])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			return nil
		}
		out = append(out, DiskStats{
			Device:     name,
			ReadOps:    KnownU64(readOps),
			WriteOps:   KnownU64(writeOps),
			ReadBytes:  KnownU64(readSect * sectorSize),
			WriteBytes: KnownU64(writeSect * sectorSize),
			IOTime:     KnownU64(ioMs),
		})
		return nil
	})
	return out, err
}

// parseNetDev parses /proc/net/dev.
func parseNetDev(data []byte) ([]InterfaceStats, error) {
	var out []InterfaceStats
	var fields [][]byte
	line := 0

	err := forEachLine(data, func(l []byte) error {
		line++
		if line <= 2 { // two header lines
			return nil
		}
		colon := indexByte(l, ':')
		if colon < 0 {
			return nil
		}
		name := trimSpace(l[:colon])
		if len(name) == 0 {
			return nil
		}
		fields = splitFields(l[colon+1:], fields)
		// rx: bytes packets errs drop fifo frame compressed multicast
		// tx: bytes packets errs drop fifo colls carrier compressed
		if len(fields) < 16 {
			return nil
		}
		var v [16]uint64
		for i := 0; i < 16; i++ {
			n, err := parseUint(fields[i])
			if err != nil {
				return nil
			}
			v[i] = n
		}
		out = append(out, InterfaceStats{
			Name:      string(name),
			RxBytes:   KnownU64(v[0]),
			RxPackets: KnownU64(v[1]),
			RxErrors:  KnownU64(v[2]),
			RxDropped: KnownU64(v[3]),
			TxBytes:   KnownU64(v[8]),
			TxPackets: KnownU64(v[9]),
			TxErrors:  KnownU64(v[10]),
			TxDropped: KnownU64(v[11]),
		})
		return nil
	})
	return out, err
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && isSpace(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && isSpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

// parseLoadavg parses /proc/loadavg.
func parseLoadavg(data []byte) (LoadStats, error) {
	var fields [][]byte
	fields = splitFields(data, fields)
	if len(fields) < 3 {
		return LoadStats{}, fmt.Errorf("malformed /proc/loadavg")
	}
	var out LoadStats
	dst := []*F64{&out.Load1, &out.Load5, &out.Load15}
	for i, p := range dst {
		f, err := strconv.ParseFloat(string(fields[i]), 64)
		if err != nil {
			return LoadStats{}, fmt.Errorf("malformed load average: %w", err)
		}
		*p = KnownF64(f)
	}
	return out, nil
}

// parseUptime parses /proc/uptime and returns the uptime.
func parseUptime(data []byte) (time.Duration, error) {
	var fields [][]byte
	fields = splitFields(data, fields)
	if len(fields) < 1 {
		return 0, fmt.Errorf("malformed /proc/uptime")
	}
	secs, err := strconv.ParseFloat(string(fields[0]), 64)
	if err != nil {
		return 0, fmt.Errorf("malformed uptime: %w", err)
	}
	if secs < 0 {
		return 0, fmt.Errorf("negative uptime")
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// parseOSRelease parses /etc/os-release, returning the human name and version.
func parseOSRelease(data []byte) (name, version string) {
	_ = forEachLine(data, func(line []byte) error {
		line = trimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			return nil
		}
		eq := indexByte(line, '=')
		if eq < 0 {
			return nil
		}
		key := string(trimSpace(line[:eq]))
		val := unquote(trimSpace(line[eq+1:]))
		switch key {
		case "NAME":
			if name == "" {
				name = val
			}
		case "ID":
			if name == "" {
				name = val
			}
		case "VERSION_ID":
			version = val
		case "VERSION":
			if version == "" {
				version = val
			}
		}
		return nil
	})
	return name, version
}

func unquote(b []byte) string {
	if len(b) >= 2 && (b[0] == '"' || b[0] == '\'') && b[len(b)-1] == b[0] {
		b = b[1 : len(b)-1]
	}
	return string(b)
}

// mountEntry is one line of /proc/mounts.
type mountEntry struct {
	Device     string
	Mountpoint string
	FSType     string
	ReadOnly   bool
}

// parseMounts parses /proc/mounts (or /proc/self/mounts).
//
// Fields are octal-escaped by the kernel: a mountpoint containing a space
// appears as \040. Failing to unescape produces a path that does not exist,
// and then a statfs failure that looks like a permissions problem.
func parseMounts(data []byte) ([]mountEntry, error) {
	var out []mountEntry
	var fields [][]byte

	err := forEachLine(data, func(line []byte) error {
		fields = splitFields(line, fields)
		if len(fields) < 4 {
			return nil
		}
		e := mountEntry{
			Device:     unescapeOctal(fields[0]),
			Mountpoint: unescapeOctal(fields[1]),
			FSType:     string(fields[2]),
		}
		for _, opt := range splitComma(fields[3]) {
			if opt == "ro" {
				e.ReadOnly = true
				break
			}
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

func splitComma(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == ',' {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

func unescapeOctal(b []byte) string {
	if indexByte(b, '\\') < 0 {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+3 < len(b) &&
			b[i+1] >= '0' && b[i+1] <= '7' &&
			b[i+2] >= '0' && b[i+2] <= '7' &&
			b[i+3] >= '0' && b[i+3] <= '7' {
			out = append(out, (b[i+1]-'0')<<6|(b[i+2]-'0')<<3|(b[i+3]-'0'))
			i += 3
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}
