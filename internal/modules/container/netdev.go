package container

import (
	"strconv"
	"strings"
)

// Per-container network accounting.
//
// The container module reads cgroups, and cgroups do not account network
// traffic: v2 gives memory.current, cpu.stat and io.stat, and there is no
// net.stat to go with them. Linux accounts network per network NAMESPACE, not
// per cgroup, which is why a module built on cgroups reported CPU and memory
// and nothing else.
//
// The namespace is reachable without entering it. /proc/<pid>/net/dev is
// rendered in the network namespace of <pid>, so reading that path for any
// process inside the container yields the container's own interface counters
// -- no setns, no CAP_SYS_ADMIN, just read access to that pid's procfs.
//
// Two cases must be excluded rather than reported, because both would attach
// somebody else's traffic to this container:
//
//   - A container run with host networking shares the host's namespace, so
//     its "container network" is the whole machine's. Reporting it would
//     duplicate host.network.* under a container id.
//   - Containers that share a namespace (network_mode: container:x, or the
//     pods that put several containers behind one sandbox) all read the same
//     counters. That is the truth of how they are wired, so it is reported,
//     but it means the per-container numbers legitimately sum to more than
//     the host's.

// netCounters is one container's traffic, summed across its interfaces.
type netCounters struct {
	RxBytes uint64
	TxBytes uint64
	OK      bool
}

// parseNetDev sums the receive and transmit byte columns of /proc/net/dev.
//
// The loopback interface is excluded. A container talking to itself is not
// network traffic anyone is measuring, and on a busy container lo can dwarf
// the real interfaces and make the number meaningless.
//
// The format is two header lines, then one line per interface:
//
//	Inter-|   Receive                        |  Transmit
//	 face |bytes    packets errs drop fifo ...|bytes    packets ...
//	   lo:    12345      67    0    0    0 ...
//	 eth0:  9876543    1234    0    0    0 ...
func parseNetDev(text string) netCounters {
	var out netCounters
	for _, line := range strings.Split(text, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			// The two header lines carry a '|' rather than an interface
			// name; anything else without a colon is not a data row.
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		// Receive occupies the first eight columns and transmit the next
		// eight, so a row with fewer than nine is truncated and unusable.
		if len(fields) < 9 {
			continue
		}
		rx, errRx := strconv.ParseUint(fields[0], 10, 64)
		tx, errTx := strconv.ParseUint(fields[8], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		out.RxBytes += rx
		out.TxBytes += tx
		out.OK = true
	}
	return out
}
