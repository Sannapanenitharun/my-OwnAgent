package discovery

import (
	"errors"
	"strconv"
	"strings"
)

// Parsers for the kernel and userland text formats discovery reads.
//
// THIS FILE CARRIES NO BUILD TAG, and that is deliberate. Almost everything
// Linux discovery knows comes from parsing text — mountinfo, cgroup paths,
// /proc/net/tcp, os-release, DMI strings — and text parsers are exactly where
// collectors get subtly wrong answers: an off-by-one column, a little-endian
// address decoded big-endian, an escaped space in a mount point. Those defects
// are cheap to find only if the tests run everywhere, so the parsing lives here
// and the file I/O lives behind a build tag.
//
// Every function here is PURE: bytes in, values out, no syscalls, no state. That
// is what makes the hostile-input tests possible at all.
//
// Bounding policy: parsers cap LENGTHS, so that a pathological file cannot make
// the module hold megabytes. They do not sanitise CHARACTERS — that happens once
// at the entity boundary, so that there is a single auditable place where
// untrusted bytes become attribute values rather than a dozen.

var errParse = errors.New("discovery: malformed input")

// ─────────────────────────────────────────────────────────────────────────────
// /proc/PID/stat
// ─────────────────────────────────────────────────────────────────────────────

// Field indices in /proc/PID/stat, counted AFTER the comm field. Field 1 is the
// PID and field 2 is comm, both handled separately, so index 0 here is field 3.
const (
	dStatFieldState     = 0  // field 3
	dStatFieldPPID      = 1  // field 4
	dStatFieldStartTime = 19 // field 22
)

// parseProcStat extracts the identity fields discovery needs from a
// /proc/PID/stat line: PID, parent PID, executable name and raw start stamp.
//
// It is a separate, thinner parser from the process module's, because discovery
// wants identity and not resource counters — but it shares the one property that
// actually matters, and this is the reason the function exists at all:
//
// FIELD 2 IS THE EXECUTABLE NAME, IT IS WRAPPED IN PARENTHESES, AND IT IS NOT
// ESCAPED. A process may legally name itself ") 1 2 3 (" and a hostile one will,
// because every field after the name is then whatever it chose. Splitting the
// line on whitespace, or scanning for the FIRST ')', hands an attacker control
// of the parent PID and the start stamp — which in this module means control of
// the process's identity and of the relationships built from it. The name runs
// from the first '(' to the LAST ')'.
func parseProcStat(data []byte) (ProcessFacts, error) {
	var out ProcessFacts

	open := indexByte(data, '(')
	closeIdx := lastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return out, errParse
	}

	pid, err := parseUint(trimSpace(data[:open]))
	if err != nil {
		return out, errParse
	}
	out.PID = PID(pid)
	out.Name = string(data[open+1 : closeIdx])
	if len(out.Name) > maxNameLen {
		out.Name = out.Name[:maxNameLen]
	}

	fields := splitFields(data[closeIdx+1:], nil)
	if len(fields) <= dStatFieldStartTime {
		return out, errParse
	}

	if ppid, err := parseUint(fields[dStatFieldPPID]); err == nil {
		out.PPID = PID(ppid)
	}
	start, err := parseUint(fields[dStatFieldStartTime])
	if err != nil {
		// Without a start stamp there is no instance identity, and a recycled
		// PID would silently inherit the previous process's relationships.
		return out, errParse
	}
	out.StartRaw = start
	out.HasStartRaw = true
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// cgroups — the richest source of local relationship evidence on Linux
// ─────────────────────────────────────────────────────────────────────────────

// cgroupEvidence is what a control-group path proves about a process.
//
// Every field is evidence for exactly one functional relationship, and every
// field is absent unless the path actually said so. Nothing here is inferred:
// a process in /system.slice/nginx.service belongs to the nginx unit because
// systemd put it there, not because its name looks like nginx.
type cgroupEvidence struct {
	// Unit is the systemd unit name, e.g. "nginx.service".
	Unit string
	// ContainerID and Runtime name the container, when the path encodes one.
	ContainerID string
	Runtime     ContainerRuntime
	// PodUID is the Kubernetes pod UID, when the path encodes one.
	PodUID string
}

// Empty reports whether the path proved nothing.
func (e cgroupEvidence) Empty() bool {
	return e.Unit == "" && e.ContainerID == "" && e.PodUID == ""
}

// parseCgroupFile extracts the process's cgroup path from /proc/PID/cgroup.
//
// The file has one line per hierarchy: "hierarchy-ID:controller-list:path".
// Under cgroup v2 there is a single line with an empty controller list ("0::"),
// and under v1 there are many. The v2 line is preferred where present; failing
// that, the systemd-named v1 hierarchy is the one that carries unit and
// container structure. Other v1 controllers are ignored rather than merged,
// because they can disagree, and a merged path is evidence of nothing.
func parseCgroupFile(data []byte) string {
	var v1 string
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		// Split into at most three parts: the path itself may contain colons.
		first := indexByte(line, ':')
		if first < 0 {
			continue
		}
		second := indexByte(line[first+1:], ':')
		if second < 0 {
			continue
		}
		controllers := string(line[first+1 : first+1+second])
		path := string(line[first+1+second+1:])
		if len(path) > maxCgroupLen {
			path = path[:maxCgroupLen]
		}
		if controllers == "" {
			return path // cgroup v2: unified, authoritative
		}
		if v1 == "" && (controllers == "name=systemd" || strings.Contains(controllers, "cpu")) {
			v1 = path
		}
	}
	return v1
}

// containerIDPrefixes maps a cgroup path component prefix onto the runtime that
// writes it. Order matters: "cri-containerd-" must be tested before
// "containerd", and the table is scanned in this order rather than by map
// iteration for exactly that reason.
var containerIDPrefixes = []struct {
	prefix  string
	runtime ContainerRuntime
}{
	{"cri-containerd-", ContainerRuntimeContainerd},
	{"containerd-", ContainerRuntimeContainerd},
	{"docker-", ContainerRuntimeDocker},
	{"crio-", ContainerRuntimeCRIO},
	{"crio_", ContainerRuntimeCRIO},
	{"libpod-", ContainerRuntimePodman},
}

// minContainerIDLen is the shortest hex string accepted as a container ID.
//
// Runtimes use 64 hex characters and tools display the first 12. Accepting
// anything shorter would classify ordinary cgroup names as containers — a
// systemd scope called "abc" is not a container — so 12 is the floor and the
// value must be hex throughout.
const minContainerIDLen = 12

// parseCgroupPath turns a control-group path into evidence.
//
// The order of the checks is the precedence, and it is not arbitrary: a
// containerised process under systemd sits in a path that contains BOTH a slice
// and a container scope, e.g.
//
//	/system.slice/docker-3aa1....scope
//
// and reporting that as the systemd unit "docker" would attach every
// containerised process on the host to one bogus service. The container is the
// more specific fact, so the container check wins, and a unit is reported only
// from a component that actually ends in ".service".
func parseCgroupPath(path string) cgroupEvidence {
	var out cgroupEvidence
	if path == "" {
		return out
	}

	for _, comp := range strings.Split(path, "/") {
		if comp == "" {
			continue
		}
		if id, rt, ok := containerIDFrom(comp); ok {
			out.ContainerID = id
			out.Runtime = rt
			continue
		}
		if uid, ok := podUIDFrom(comp); ok {
			out.PodUID = uid
			continue
		}
		if strings.HasSuffix(comp, ".service") && len(comp) <= maxNameLen {
			// The LAST unit component wins: nested slices such as
			// /system.slice/system-getty.slice/getty@tty1.service put the
			// specific unit last.
			out.Unit = comp
			continue
		}
		if strings.HasPrefix(comp, "lxc.payload.") {
			out.ContainerID = strings.TrimPrefix(comp, "lxc.payload.")
			out.Runtime = ContainerRuntimeLXC
		}
	}

	// The cgroupfs driver, unlike the systemd driver, writes a bare path:
	//   /kubepods/burstable/pod<uid>/<64 hex>
	// and /docker/<64 hex> for plain Docker. Those bare hex components are
	// caught above by containerIDFrom's no-prefix branch.
	if out.ContainerID != "" && out.Runtime == ContainerRuntimeUnknown {
		if strings.HasPrefix(path, "/docker/") {
			out.Runtime = ContainerRuntimeDocker
		}
	}
	if len(out.ContainerID) > maxNameLen {
		out.ContainerID = out.ContainerID[:maxNameLen]
	}
	return out
}

// containerIDFrom recognises a container ID in one cgroup path component.
func containerIDFrom(comp string) (string, ContainerRuntime, bool) {
	c := strings.TrimSuffix(comp, ".scope")
	for _, p := range containerIDPrefixes {
		if !strings.HasPrefix(c, p.prefix) {
			continue
		}
		id := strings.TrimPrefix(c, p.prefix)
		if isHex(id) && len(id) >= minContainerIDLen {
			return id, p.runtime, true
		}
		// LXC names are not hex, and are handled by the caller.
		return "", ContainerRuntimeUnknown, false
	}
	// A bare hex component: the cgroupfs driver's form.
	if isHex(c) && len(c) >= minContainerIDLen {
		return c, ContainerRuntimeUnknown, true
	}
	return "", ContainerRuntimeUnknown, false
}

// podUIDFrom recognises a Kubernetes pod UID in one cgroup path component.
//
// The two cgroup drivers write it differently, and the difference is a trap:
//
//	cgroupfs: pod3d7e9c1a-4b2f-11ee-be56-0242ac120002
//	systemd:  kubepods-burstable-pod3d7e9c1a_4b2f_11ee_be56_0242ac120002.slice
//
// systemd forbids '-' inside a unit name component, so it substitutes '_'. A
// module that did not convert them back would produce two different pod UIDs for
// the same pod depending on which driver the node uses — and therefore two pod
// entities, on different nodes of the same cluster.
func podUIDFrom(comp string) (string, bool) {
	c := strings.TrimSuffix(comp, ".slice")
	// LAST occurrence, not first. The systemd driver's component is
	//
	//	kubepods-burstable-pod3d7e9c1a_4b2f_....slice
	//	    ^^^                ^^^
	//
	// and "kubePODs" contains "pod" three characters in. Searching forwards
	// finds that one and yields "s-burstable-pod3d7e9c1a...", which fails
	// validation — so no pod UID is extracted, no pod entity is created, and
	// no container is ever linked to a pod. On a kubeadm cluster, where the
	// systemd driver is the default, that is EVERY node.
	//
	// Searching backwards is safe because a pod UID is hexadecimal and dashes:
	// 'p' and 'o' cannot appear in one, so the last "pod" is always the prefix.
	i := strings.LastIndex(c, "pod")
	if i < 0 {
		return "", false
	}
	uid := c[i+len("pod"):]
	if uid == "" || len(uid) > maxNameLen {
		return "", false
	}
	// Only convert separators, never characters inside the identifier, so a
	// name that merely contains "pod" cannot be laundered into a UID.
	uid = strings.ReplaceAll(uid, "_", "-")
	if !isPodUID(uid) {
		return "", false
	}
	return uid, true
}

// isPodUID accepts the two shapes Kubernetes actually produces: a 36-character
// dashed UUID, or 32 undashed hex characters.
func isPodUID(s string) bool {
	switch len(s) {
	case 36:
		for i := 0; i < len(s); i++ {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if s[i] != '-' {
					return false
				}
				continue
			}
			if !isHexByte(s[i]) {
				return false
			}
		}
		return true
	case 32:
		return isHex(s)
	default:
		return false
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/self/mountinfo
// ─────────────────────────────────────────────────────────────────────────────

// pseudoFilesystems are kernel-internal filesystems that are not storage.
//
// They are excluded by default because a container host mounts hundreds of them
// — one proc, sysfs, mqueue and devpts per container — and each would otherwise
// become a discovered entity. They are excluded by TYPE rather than by mount
// point, because mount points are operator-chosen and types are not.
var pseudoFilesystems = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
	"efivarfs": true, "bpf": true, "debugfs": true, "tracefs": true,
	"hugetlbfs": true, "mqueue": true, "fusectl": true, "configfs": true,
	"binfmt_misc": true, "autofs": true, "rpc_pipefs": true, "nsfs": true,
	"selinuxfs": true, "ramfs": true, "squashfs": true,
}

// remoteFilesystems are network filesystems. A remote mount is a dependency on
// another host, which makes it a topology fact rather than a storage one.
var remoteFilesystems = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"glusterfs": true, "ceph": true, "afs": true, "9p": true, "fuse.sshfs": true,
	"lustre": true, "beegfs": true,
}

// parseMountinfo parses /proc/self/mountinfo.
//
// mountinfo rather than /etc/mtab or /proc/mounts, for two reasons that both
// matter here: mtab is a userland file that can be stale or a symlink an
// attacker controls, and mountinfo is the only one that reports the mount's
// own read-only flag separately from the superblock's.
//
// The format is positional up to an optional-fields section terminated by a
// lone "-", which is why the separator is searched for rather than assumed at a
// fixed index — the number of optional fields varies with the kernel and with
// whether the mount is shared, and code that assumes a count silently misreads
// the filesystem type on any host using shared subtrees.
func parseMountinfo(data []byte, includePseudo bool) []FilesystemFacts {
	var out []FilesystemFacts
	for _, line := range splitLines(data) {
		fields := strings.Fields(string(line))
		// id parent major:minor root mountpoint options ... - fstype source super
		if len(fields) < 10 {
			continue
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}

		fsType := fields[sep+1]
		if !includePseudo && pseudoFilesystems[fsType] {
			continue
		}

		mountpoint := unescapeOctal(fields[4])
		if len(mountpoint) > maxPathLen {
			mountpoint = mountpoint[:maxPathLen]
		}
		device := unescapeOctal(fields[sep+2])
		if len(device) > maxPathLen {
			device = device[:maxPathLen]
		}

		out = append(out, FilesystemFacts{
			Mountpoint: mountpoint,
			Device:     device,
			FSType:     fsType,
			// The MOUNT's read-only flag, in field 6, not the superblock's in
			// the last field. They differ: a read-write filesystem can be
			// bind-mounted read-only, and it is the mount that governs what a
			// process on this host can actually do.
			ReadOnly: hasOption(fields[5], "ro"),
			Remote:   remoteFilesystems[fsType] || strings.HasPrefix(fsType, "fuse.s3"),
		})
	}
	return out
}

func hasOption(options, want string) bool {
	for _, o := range strings.Split(options, ",") {
		if o == want {
			return true
		}
	}
	return false
}

// unescapeOctal decodes the \NNN escapes the kernel writes for characters that
// would otherwise break the field-separated format.
//
// A mount point may legally contain a space, and the kernel writes it as \040.
// Code that skips this step splits "/mnt/my backup" into two fields and reports
// a filesystem mounted at "/mnt/my" — which is not merely wrong but plausible.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/net/{tcp,tcp6,udp,udp6}
// ─────────────────────────────────────────────────────────────────────────────

// tcpStateListen is TCP_LISTEN as the kernel writes it in /proc/net/tcp.
const tcpStateListen = 0x0A

// Column indices in /proc/net/tcp, after the header line.
const (
	netFieldLocal  = 1
	netFieldRemote = 2
	netFieldState  = 3
	netFieldInode  = 9
)

// parseProcNet parses one of /proc/net/{tcp,tcp6,udp,udp6}, returning LISTENING
// sockets only.
//
// Listeners only, and the filter is applied here rather than downstream so that
// established connections are never held in memory at all. On a busy host
// /proc/net/tcp has tens of thousands of lines and two of them are listeners;
// materialising the rest to discard them later would be the module's largest
// allocation for no purpose, and would put third-party remote addresses in the
// agent's heap.
//
// UDP has no listen state, so a UDP socket counts as a listener when it has no
// peer — which is exactly what "bound but not connected" means.
func parseProcNet(data []byte, proto Protocol) []EndpointFacts {
	var out []EndpointFacts
	isUDP := proto == ProtocolUDP || proto == ProtocolUDP6

	for i, line := range splitLines(data) {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(string(line))
		if len(fields) <= netFieldInode {
			continue
		}

		state, err := strconv.ParseUint(fields[netFieldState], 16, 8)
		if err != nil {
			continue
		}
		if isUDP {
			// A UDP socket with a peer is a connected socket, not a service.
			if _, port, ok := parseHexAddr(fields[netFieldRemote]); !ok || port != 0 {
				continue
			}
		} else if state != tcpStateListen {
			continue
		}

		addr, port, ok := parseHexAddr(fields[netFieldLocal])
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[netFieldInode], 10, 64)
		if err != nil {
			continue
		}

		out = append(out, EndpointFacts{
			Protocol: proto,
			Address:  addr,
			Port:     port,
			Inode:    inode,
		})
	}
	return out
}

// parseHexAddr decodes the "ADDRESS:PORT" form used throughout /proc/net.
//
// THE ENDIANNESS IS THE TRAP. The address is written as hex 32-bit words in HOST
// byte order, which on every platform the agent supports is little-endian, while
// the port is big-endian. So 127.0.0.1:22 appears as "0100007F:0016" — and a
// decoder that reads the address as one big-endian number reports 1.0.0.127,
// which is a real address belonging to somebody else. IPv6 is four such words,
// each independently byte-swapped, in order.
func parseHexAddr(s string) (addr string, port uint16, ok bool) {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return "", 0, false
	}
	p, err := strconv.ParseUint(s[colon+1:], 16, 16)
	if err != nil {
		return "", 0, false
	}
	hex := s[:colon]

	switch len(hex) {
	case 8:
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return "", 0, false
		}
		// Little-endian word: the first hex pair is the LAST octet.
		return formatIPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), uint16(p), true
	case 32:
		var b [16]byte
		for w := 0; w < 4; w++ {
			v, err := strconv.ParseUint(hex[w*8:w*8+8], 16, 32)
			if err != nil {
				return "", 0, false
			}
			b[w*4+0] = byte(v)
			b[w*4+1] = byte(v >> 8)
			b[w*4+2] = byte(v >> 16)
			b[w*4+3] = byte(v >> 24)
		}
		return formatIPv6(b), uint16(p), true
	default:
		return "", 0, false
	}
}

func formatIPv4(a, b, c, d byte) string {
	var buf []byte
	buf = strconv.AppendUint(buf, uint64(a), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(b), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(c), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(d), 10)
	return string(buf)
}

// formatIPv6 renders an address in the canonical form, including the "::"
// run-length compression and the IPv4-mapped ("::ffff:1.2.3.4") special case.
//
// Canonical form matters more than it looks: the address is part of the
// endpoint's natural key, so two spellings of one address would be two entities.
func formatIPv6(b [16]byte) string {
	// IPv4-mapped and IPv4-compatible addresses render as IPv4, which is what
	// every operator tool shows and therefore what the key should contain.
	isV4Mapped := true
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			isV4Mapped = false
			break
		}
	}
	if isV4Mapped && b[10] == 0xff && b[11] == 0xff {
		return formatIPv4(b[12], b[13], b[14], b[15])
	}

	var groups [8]uint16
	for i := range groups {
		groups[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}

	// Longest run of zero groups, at least two long, is replaced by "::".
	bestStart, bestLen, curStart, curLen := -1, 0, -1, 0
	for i, g := range groups {
		if g == 0 {
			if curStart < 0 {
				curStart = i
			}
			curLen++
			if curLen > bestLen {
				bestStart, bestLen = curStart, curLen
			}
			continue
		}
		curStart, curLen = -1, 0
	}
	if bestLen < 2 {
		bestStart, bestLen = -1, 0
	}

	var out []byte
	for i := 0; i < 8; i++ {
		if i == bestStart {
			out = append(out, ':', ':')
			i += bestLen - 1
			continue
		}
		if len(out) > 0 && out[len(out)-1] != ':' {
			out = append(out, ':')
		}
		out = strconv.AppendUint(out, uint64(groups[i]), 16)
	}
	if len(out) == 0 {
		return "::"
	}
	return string(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// /etc/os-release
// ─────────────────────────────────────────────────────────────────────────────

// parseOSRelease extracts the distribution identity from an os-release file.
//
// Values may be quoted or bare and the file may contain keys this module has
// never heard of, so unknown keys are skipped rather than treated as malformed —
// distributions add their own, and a parser that rejected the whole file over
// one would report every such host as unknown.
func parseOSRelease(data []byte) (id, version, pretty string) {
	for _, line := range splitLines(data) {
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		key, value, found := strings.Cut(s, "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if len(value) > maxNameLen {
			value = value[:maxNameLen]
		}
		switch strings.TrimSpace(key) {
		case "ID":
			id = value
		case "VERSION_ID":
			version = value
		case "PRETTY_NAME":
			pretty = value
		}
	}
	return id, version, pretty
}

// ─────────────────────────────────────────────────────────────────────────────
// DMI / SMBIOS firmware evidence
// ─────────────────────────────────────────────────────────────────────────────

// azureChassisAssetTag is the fixed chassis asset tag Azure writes on every VM.
//
// It is the only way to tell Azure from generic Hyper-V using firmware alone:
// both report a system vendor of "Microsoft Corporation" and a product of
// "Virtual Machine", so without this tag an Azure fleet reports as on-premises
// Hyper-V — a wrong answer that looks entirely plausible.
const azureChassisAssetTag = "7783-7084-3265-9085-8269-3286-77"

// classifyPlatform maps firmware strings onto a provider.
//
// This is evidence-based classification, not a guess: every provider below
// writes its own name into SMBIOS, the strings are stable across instance types,
// and any user may read them. What the function will NOT do is fall back to
// something plausible — an unrecognised platform returns Unknown, and the raw
// vendor and product strings travel with it so that an operator can see what the
// module actually saw.
func classifyPlatform(vendor, product, assetTag string) CloudProvider {
	v := strings.ToLower(strings.TrimSpace(vendor))
	p := strings.ToLower(strings.TrimSpace(product))

	switch {
	case strings.TrimSpace(assetTag) == azureChassisAssetTag:
		return CloudProviderAzure
	case strings.Contains(v, "amazon") || strings.Contains(p, "amazon ec2"):
		return CloudProviderAWS
	case strings.Contains(v, "google"):
		return CloudProviderGCP
	case strings.Contains(v, "alibaba"):
		return CloudProviderAlibaba
	case strings.Contains(v, "openstack") || strings.Contains(p, "openstack"):
		return CloudProviderOpenStack
	case strings.Contains(v, "vmware"):
		return CloudProviderVMware
	case strings.Contains(v, "innotek") || strings.Contains(p, "virtualbox"):
		// Checked before "oracle": Oracle owns VirtualBox and newer builds
		// report an Oracle vendor string, which would otherwise classify every
		// developer laptop as Oracle Cloud.
		return CloudProviderVirtualBox
	case strings.Contains(v, "oracle"):
		return CloudProviderOracle
	case strings.Contains(v, "xen") || strings.Contains(p, "hvm domu"):
		return CloudProviderXen
	case strings.Contains(v, "microsoft"):
		return CloudProviderHyperV
	case strings.Contains(v, "qemu") || strings.Contains(p, "kvm") ||
		strings.Contains(p, "standard pc"):
		return CloudProviderKVM
	case v == "":
		return CloudProviderUnknown
	default:
		// A vendor string that is present and matches nothing known is positive
		// evidence of physical hardware: hypervisors identify themselves, and
		// server vendors (Dell, HPE, Supermicro, Lenovo) do not pretend to be
		// one. This is the one inference in the module, and it is stated rather
		// than hidden because "bare metal" and "unknown" are different answers.
		return CloudProviderBareMetal
	}
}

// awsInstanceIDFrom recognises an EC2 instance ID in the DMI board asset tag.
//
// AWS writes it there on Nitro instances, which is the one case where the
// provider's own identifier is available WITHOUT a metadata-service request. It
// is validated rather than trusted: the field is firmware-supplied, and an
// unvalidated value would flow into an entity natural key.
func awsInstanceIDFrom(assetTag string) string {
	s := strings.TrimSpace(assetTag)
	if !strings.HasPrefix(s, "i-") || len(s) < 10 || len(s) > 32 {
		return ""
	}
	if !isHex(s[2:]) {
		return ""
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte helpers. Written out rather than reaching for bytes/strings so that the
// hot paths do no allocation; the process module's parser made the same trade
// after benchmarking showed it was worth 170 MB per cycle at scale.
// ─────────────────────────────────────────────────────────────────────────────

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
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

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

// splitFields splits on runs of whitespace, reusing dst's backing array.
func splitFields(b []byte, dst [][]byte) [][]byte {
	dst = dst[:0]
	i := 0
	for i < len(b) {
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) {
			break
		}
		start := i
		for i < len(b) && !isSpace(b[i]) {
			i++
		}
		dst = append(dst, b[start:i])
	}
	return dst
}

// splitLines splits on '\n', tolerating CRLF and a missing final newline.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '\n' {
			line := b[start:i]
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	// A trailing newline produces a final empty line; drop it so callers do not
	// each have to.
	if n := len(out); n > 0 && len(out[n-1]) == 0 {
		out = out[:n-1]
	}
	return out
}

// parseUint parses a decimal unsigned integer, rejecting everything else —
// including signs, dots and hex prefixes, which the kernel never writes and
// whose acceptance would mean silently misreading a corrupted field.
func parseUint(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, errParse
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, errParse
		}
		d := uint64(c - '0')
		if v > (1<<64-1-d)/10 {
			return 0, errParse
		}
		v = v*10 + d
	}
	return v, nil
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}
