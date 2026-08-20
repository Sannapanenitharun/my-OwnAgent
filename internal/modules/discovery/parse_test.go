package discovery

import (
	"strings"
	"testing"
)

// These run on every developer platform, not just Linux, which is the whole
// reason parse.go carries no build tag. Kernel text formats are where discovery
// gets subtly wrong answers, and those defects are only cheap to find if the
// tests run everywhere.

// ─────────────────────────────────────────────────────────────────────────────
// /proc/PID/stat
// ─────────────────────────────────────────────────────────────────────────────

// TestParseProcStatSurvivesHostileProcessNames is the single most important
// parser test in this module.
//
// Field 2 of /proc/PID/stat is the executable name, wrapped in parentheses and
// NOT escaped. A process may legally name itself ") 0 0 0 0 (" — and a hostile
// one will, because doing so lets it choose the values the agent reports for
// every field after it. In THIS module those fields are the parent PID and the
// start stamp, which means a naive parser hands an attacker control over a
// process's identity and over the relationships built from it.
func TestParseProcStatSurvivesHostileProcessNames(t *testing.T) {
	tests := []struct {
		desc     string
		comm     string
		wantName string
	}{
		{"plain", "nginx", "nginx"},
		{"space", "postgres writer", "postgres writer"},
		{"closing paren", "evil)", "evil)"},
		{"opening paren", "(evil", "(evil"},
		{"forged fields", ") 9 9999 9 9 9 9 9 9 9 9 9 9 9 (", ") 9 9999 9 9 9 9 9 9 9 9 9 9 9 ("},
		{"only parens", ")(", ")("},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Everything after the comm is fixed, so a misparse shows up as a
			// wrong PPID or start stamp rather than as an error.
			line := "1234 (" + tc.comm + ") S 77 1234 1234 0 -1 0 0 0 0 0 150 75 0 0 20 0 4 0 987654 12345678 900"
			got, err := parseProcStat([]byte(line))
			if err != nil {
				t.Fatalf("parseProcStat: %v", err)
			}
			if got.Name != tc.wantName {
				t.Errorf("name = %q, want %q", got.Name, tc.wantName)
			}
			if got.PID != 1234 {
				t.Errorf("pid = %d, want 1234", got.PID)
			}
			if got.PPID != 77 {
				t.Errorf("ppid = %d, want 77 — the comm field shifted the columns", got.PPID)
			}
			if got.StartRaw != 987654 {
				t.Errorf("start = %d, want 987654 — the comm field shifted the columns", got.StartRaw)
			}
		})
	}
}

func TestParseProcStatRejectsMalformedInput(t *testing.T) {
	for _, line := range []string{
		"",
		"1234 nginx S 1",
		"1234 (nginx S 1",
		"abc (nginx) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22",
		// Truncated before the start stamp: without it there is no instance
		// identity, and a recycled PID would inherit another process's
		// relationships.
		"1234 (nginx) S 1 2 3",
	} {
		if _, err := parseProcStat([]byte(line)); err == nil {
			t.Errorf("malformed stat line was accepted: %q", line)
		}
	}
}

func TestParseProcStatBoundsAnEnormousName(t *testing.T) {
	// A process name is chosen by the process. The parser bounds it where the
	// untrusted bytes enter rather than trusting a later stage.
	huge := strings.Repeat("A", 10000)
	line := "1 (" + huge + ") S 0 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10"
	got, err := parseProcStat([]byte(line))
	if err != nil {
		t.Fatalf("parseProcStat: %v", err)
	}
	if len(got.Name) > maxNameLen {
		t.Errorf("name is %d bytes, want at most %d", len(got.Name), maxNameLen)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// cgroups
// ─────────────────────────────────────────────────────────────────────────────

func TestParseCgroupFilePrefersTheUnifiedHierarchy(t *testing.T) {
	// A v1/v2 hybrid host lists many hierarchies. The unified one (empty
	// controller list) is authoritative; merging the others would produce a path
	// that is evidence of nothing.
	data := []byte(strings.Join([]string{
		"12:pids:/user.slice/user-1000.slice",
		"5:cpu,cpuacct:/system.slice/wrong.service",
		"1:name=systemd:/system.slice/also-wrong.service",
		"0::/system.slice/nginx.service",
	}, "\n"))

	if got := parseCgroupFile(data); got != "/system.slice/nginx.service" {
		t.Errorf("got %q, want the unified v2 path", got)
	}
}

func TestParseCgroupFileFallsBackToSystemdHierarchy(t *testing.T) {
	data := []byte("12:pids:/ignored\n1:name=systemd:/system.slice/sshd.service\n")
	if got := parseCgroupFile(data); got != "/system.slice/sshd.service" {
		t.Errorf("got %q, want the systemd v1 path", got)
	}
	if got := parseCgroupFile([]byte("garbage\n\n")); got != "" {
		t.Errorf("got %q, want empty for unparseable content", got)
	}
}

// TestParseCgroupPathExtractsTheRightEvidence covers every cgroup shape the
// supported runtimes and drivers actually produce.
//
// The table IS the specification. Each row is a real path from a real
// configuration, and the expectations encode the precedence decisions: a
// container inside a systemd slice is a container, not a service named "docker".
func TestParseCgroupPathExtractsTheRightEvidence(t *testing.T) {
	const id = "3aa1b7c9d2e4f6081a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081"
	const podUID = "3d7e9c1a-4b2f-11ee-be56-0242ac120002"

	tests := []struct {
		desc string
		path string
		want cgroupEvidence
	}{
		{
			desc: "systemd service",
			path: "/system.slice/nginx.service",
			want: cgroupEvidence{Unit: "nginx.service"},
		},
		{
			desc: "nested systemd slice keeps the specific unit",
			path: "/system.slice/system-getty.slice/getty@tty1.service",
			want: cgroupEvidence{Unit: "getty@tty1.service"},
		},
		{
			desc: "docker under systemd is a container, not a service",
			path: "/system.slice/docker-" + id + ".scope",
			want: cgroupEvidence{ContainerID: id, Runtime: ContainerRuntimeDocker},
		},
		{
			desc: "docker with the cgroupfs driver",
			path: "/docker/" + id,
			want: cgroupEvidence{ContainerID: id, Runtime: ContainerRuntimeDocker},
		},
		{
			desc: "kubernetes with containerd and the systemd driver",
			path: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3d7e9c1a_4b2f_11ee_be56_0242ac120002.slice/cri-containerd-" + id + ".scope",
			want: cgroupEvidence{ContainerID: id, Runtime: ContainerRuntimeContainerd, PodUID: podUID},
		},
		{
			desc: "kubernetes with the cgroupfs driver",
			path: "/kubepods/burstable/pod" + podUID + "/" + id,
			want: cgroupEvidence{ContainerID: id, PodUID: podUID},
		},
		{
			desc: "cri-o",
			path: "/kubepods.slice/kubepods-pod" + strings.ReplaceAll(podUID, "-", "_") + ".slice/crio-" + id + ".scope",
			want: cgroupEvidence{ContainerID: id, Runtime: ContainerRuntimeCRIO, PodUID: podUID},
		},
		{
			desc: "podman",
			path: "/machine.slice/libpod-" + id + ".scope",
			want: cgroupEvidence{ContainerID: id, Runtime: ContainerRuntimePodman},
		},
		{
			desc: "lxc",
			path: "/lxc.payload.web01",
			want: cgroupEvidence{ContainerID: "web01", Runtime: ContainerRuntimeLXC},
		},
		{
			desc: "a user session proves nothing",
			path: "/user.slice/user-1000.slice/session-3.scope",
			want: cgroupEvidence{},
		},
		{
			desc: "the root cgroup proves nothing",
			path: "/",
			want: cgroupEvidence{},
		},
		{
			desc: "empty",
			path: "",
			want: cgroupEvidence{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := parseCgroupPath(tc.path)
			if got != tc.want {
				t.Errorf("parseCgroupPath(%q):\n got %+v\nwant %+v", tc.path, got, tc.want)
			}
		})
	}
}

// TestParseCgroupPathNormalisesPodUIDAcrossDrivers is called out separately
// because it is the defect that would be hardest to notice in production.
//
// The systemd cgroup driver substitutes '_' for '-' inside a unit name. A module
// that did not convert them back would report two DIFFERENT pod UIDs for the
// same pod depending on which driver a node uses — producing two pod entities
// per pod across a mixed cluster, with no error anywhere.
func TestParseCgroupPathNormalisesPodUIDAcrossDrivers(t *testing.T) {
	const uid = "3d7e9c1a-4b2f-11ee-be56-0242ac120002"
	systemd := parseCgroupPath("/kubepods.slice/kubepods-burstable-pod" +
		strings.ReplaceAll(uid, "-", "_") + ".slice")
	cgroupfs := parseCgroupPath("/kubepods/burstable/pod" + uid)

	if systemd.PodUID != cgroupfs.PodUID {
		t.Errorf("the two cgroup drivers produced different pod UIDs:\n systemd  = %q\n cgroupfs = %q",
			systemd.PodUID, cgroupfs.PodUID)
	}
	if systemd.PodUID != uid {
		t.Errorf("pod UID = %q, want %q", systemd.PodUID, uid)
	}
}

func TestContainerIDRequiresPlausibleHex(t *testing.T) {
	// Short or non-hex components are ordinary cgroup names. Accepting them
	// would classify a systemd scope called "abc" as a container.
	for _, comp := range []string{"abc", "docker-xyz", "session-3.scope", "docker-abc"} {
		if _, _, ok := containerIDFrom(comp); ok {
			t.Errorf("%q was accepted as a container ID", comp)
		}
	}
	if _, _, ok := containerIDFrom("abcdef012345"); !ok {
		t.Error("a 12-character hex component was rejected")
	}
}

func TestPodUIDRejectsLookalikes(t *testing.T) {
	// A component merely containing "pod" is not a pod. Only the two shapes
	// Kubernetes actually writes are accepted.
	for _, comp := range []string{"podman.service", "pod", "podxyz", "tripod.slice"} {
		if uid, ok := podUIDFrom(comp); ok {
			t.Errorf("%q was accepted as a pod UID (got %q)", comp, uid)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// mountinfo
// ─────────────────────────────────────────────────────────────────────────────

const realMountinfo = `21 27 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
22 27 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
27 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
36 27 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate
48 27 259:1 / /boot/efi rw,relatime shared:44 - vfat /dev/nvme0n1p1 rw,fmask=0077
99 27 0:52 / /mnt/data ro,relatime shared:60 - nfs4 fileserver:/export rw,vers=4.2
120 27 259:2 /var/lib/docker/overlay2 /var/lib/docker/overlay2 rw,relatime - ext4 /dev/nvme0n1p2 rw`

func TestParseMountinfoReadsTheRightColumns(t *testing.T) {
	got := parseMountinfo([]byte(realMountinfo), true)
	if len(got) != 7 {
		t.Fatalf("got %d mounts, want 7", len(got))
	}

	byMount := make(map[string]FilesystemFacts, len(got))
	for _, f := range got {
		byMount[f.Mountpoint] = f
	}

	root, ok := byMount["/"]
	if !ok {
		t.Fatal("the root filesystem was not parsed")
	}
	if root.FSType != "ext4" || root.Device != "/dev/nvme0n1p2" {
		t.Errorf("root = %+v, want ext4 on /dev/nvme0n1p2", root)
	}
	if root.ReadOnly {
		t.Error("root was reported read-only")
	}

	nfs, ok := byMount["/mnt/data"]
	if !ok {
		t.Fatal("the NFS mount was not parsed")
	}
	if !nfs.Remote {
		t.Error("an nfs4 mount was not marked remote; a remote mount is a dependency on another host")
	}
	// The MOUNT is read-only even though the superblock options say rw. Reading
	// the last field instead of field 6 would get this backwards.
	if !nfs.ReadOnly {
		t.Error("the mount's own ro flag was ignored in favour of the superblock's rw")
	}
}

func TestParseMountinfoFiltersPseudoFilesystems(t *testing.T) {
	got := parseMountinfo([]byte(realMountinfo), false)
	for _, f := range got {
		if pseudoFilesystems[f.FSType] {
			t.Errorf("pseudo filesystem %q at %q was not filtered", f.FSType, f.Mountpoint)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d real filesystems, want 4: %+v", len(got), got)
	}
}

// TestParseMountinfoHandlesVariableOptionalFields is the column-counting trap.
//
// The optional-fields section between the mount options and the "-" separator
// varies in length with the kernel and with whether the mount is shared. Code
// that assumes a fixed count silently misreads the filesystem type on any host
// using shared subtrees — which is every modern host.
func TestParseMountinfoHandlesVariableOptionalFields(t *testing.T) {
	lines := []string{
		// No optional fields at all.
		`27 1 259:2 / / rw,relatime - ext4 /dev/sda1 rw`,
		// One.
		`27 1 259:2 / /a rw,relatime shared:1 - ext4 /dev/sda2 rw`,
		// Three.
		`27 1 259:2 / /b rw,relatime shared:1 master:2 propagate_from:3 - ext4 /dev/sda3 rw`,
	}
	got := parseMountinfo([]byte(strings.Join(lines, "\n")), true)
	if len(got) != 3 {
		t.Fatalf("got %d mounts, want 3", len(got))
	}
	for i, f := range got {
		if f.FSType != "ext4" {
			t.Errorf("mount %d: fstype = %q, want ext4 — the optional-fields section shifted the columns", i, f.FSType)
		}
	}
}

// TestParseMountinfoUnescapesOctal covers the mount point that contains a space.
//
// The kernel writes it as \040. Code that skips the decode splits
// "/mnt/my backup" into two fields and reports a filesystem mounted at
// "/mnt/my" — which is not merely wrong but plausible.
func TestParseMountinfoUnescapesOctal(t *testing.T) {
	line := `27 1 259:2 / /mnt/my\040backup rw,relatime - ext4 /dev/sda1 rw`
	got := parseMountinfo([]byte(line), true)
	if len(got) != 1 {
		t.Fatalf("got %d mounts, want 1", len(got))
	}
	if got[0].Mountpoint != "/mnt/my backup" {
		t.Errorf("mountpoint = %q, want %q", got[0].Mountpoint, "/mnt/my backup")
	}
}

func TestParseMountinfoBoundsPathologicalPaths(t *testing.T) {
	line := `27 1 259:2 / /` + strings.Repeat("x", 5000) + ` rw - ext4 /dev/sda1 rw`
	got := parseMountinfo([]byte(line), true)
	if len(got) != 1 {
		t.Fatalf("got %d mounts, want 1", len(got))
	}
	if len(got[0].Mountpoint) > maxPathLen {
		t.Errorf("mountpoint is %d bytes, want at most %d", len(got[0].Mountpoint), maxPathLen)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/net
// ─────────────────────────────────────────────────────────────────────────────

const realProcNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 24601 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20134 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 0100007F:B3C4 01 00000000:00000000 00:00000000 00000000  1000        0 51234 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19876 1 0000000000000000 100 0 0 10 0`

// TestParseProcNetDecodesLittleEndianAddresses is the endianness trap, and it is
// the one that produces a WRONG ANSWER rather than an error.
//
// /proc/net writes the address as hex 32-bit words in host byte order, which is
// little-endian, while the port is big-endian. So 127.0.0.1:53 appears as
// "0100007F:0035". A decoder that reads the address as one big-endian number
// reports 1.0.0.127 — a real address, belonging to somebody else.
func TestParseProcNetDecodesLittleEndianAddresses(t *testing.T) {
	got := parseProcNet([]byte(realProcNetTCP), ProtocolTCP)

	want := []struct {
		addr string
		port uint16
	}{
		{"127.0.0.53", 53}, // 3500007F:0035
		{"0.0.0.0", 22},    // 00000000:0016
		{"127.0.0.1", 631}, // 0100007F:0277
	}
	if len(got) != len(want) {
		t.Fatalf("got %d listeners, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Address != w.addr || got[i].Port != w.port {
			t.Errorf("listener %d = %s:%d, want %s:%d",
				i, got[i].Address, got[i].Port, w.addr, w.port)
		}
	}
}

// TestParseProcNetReturnsListenersOnly is a memory property as much as a
// correctness one. On a busy host /proc/net/tcp has tens of thousands of lines
// and two of them are listeners; materialising the rest to discard them later
// would be the module's largest allocation, and would put third-party remote
// addresses in the agent's heap.
func TestParseProcNetReturnsListenersOnly(t *testing.T) {
	got := parseProcNet([]byte(realProcNetTCP), ProtocolTCP)
	for _, e := range got {
		if e.Port == 8080 {
			t.Error("an ESTABLISHED connection (state 01) was reported as a listener")
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d entries, want the 3 sockets in state 0A", len(got))
	}
}

func TestParseProcNetCapturesInodesForCorrelation(t *testing.T) {
	got := parseProcNet([]byte(realProcNetTCP), ProtocolTCP)
	if len(got) == 0 {
		t.Fatal("no listeners parsed")
	}
	if got[0].Inode != 24601 {
		t.Errorf("inode = %d, want 24601 — without it no endpoint can be attributed to a process", got[0].Inode)
	}
}

const realProcNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20135 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 33445 1 0000000000000000 100 0 0 10 0`

func TestParseProcNetHandlesIPv6(t *testing.T) {
	got := parseProcNet([]byte(realProcNetTCP6), ProtocolTCP6)
	if len(got) != 2 {
		t.Fatalf("got %d listeners, want 2: %+v", len(got), got)
	}
	if got[0].Address != "::" || got[0].Port != 22 {
		t.Errorf("wildcard v6 listener = %s:%d, want :::22", got[0].Address, got[0].Port)
	}
	// ::1 is written as four little-endian words: the loopback bit lands in the
	// last word's lowest byte.
	if got[1].Address != "::1" || got[1].Port != 8081 {
		t.Errorf("v6 loopback listener = %s:%d, want ::1:8081", got[1].Address, got[1].Port)
	}
}

const realProcNetUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 24610 2 0000000000000000 0
   1: 0100007F:BB40 0800080A:0035 01 00000000:00000000 00:00000000 00000000  1000        0 51299 2 0000000000000000 0`

// TestParseProcNetTreatsBoundUDPSocketsAsListeners covers the fact that UDP has
// no listen state. A UDP socket with no peer is bound and serving; one with a
// peer is a client conversation and is not a service this host offers.
func TestParseProcNetTreatsBoundUDPSocketsAsListeners(t *testing.T) {
	got := parseProcNet([]byte(realProcNetUDP), ProtocolUDP)
	if len(got) != 1 {
		t.Fatalf("got %d UDP listeners, want 1: %+v", len(got), got)
	}
	if got[0].Address != "127.0.0.53" || got[0].Port != 53 {
		t.Errorf("UDP listener = %s:%d, want 127.0.0.53:53", got[0].Address, got[0].Port)
	}
}

func TestParseProcNetIgnoresGarbage(t *testing.T) {
	for _, data := range []string{
		"",
		"header only\n",
		"header\nnot enough fields here\n",
		"header\n 0: ZZZZZZZZ:0016 00000000:0000 0A 0 0 0 0 0 123\n",
	} {
		if got := parseProcNet([]byte(data), ProtocolTCP); len(got) != 0 {
			t.Errorf("garbage produced %d listeners: %+v", len(got), got)
		}
	}
}

func TestFormatIPv6Canonicalises(t *testing.T) {
	// The address is part of an endpoint's natural key, so two spellings of one
	// address would be two entities.
	tests := []struct {
		in   [16]byte
		want string
	}{
		{[16]byte{}, "::"},
		{[16]byte{15: 1}, "::1"},
		{[16]byte{0: 0xfe, 1: 0x80, 15: 1}, "fe80::1"},
		{[16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 168, 14: 1, 15: 10}, "192.168.1.10"},
		{[16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 0x01}, "2001:db8::1"},
	}
	for _, tc := range tests {
		if got := formatIPv6(tc.in); got != tc.want {
			t.Errorf("formatIPv6(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// os-release and DMI
// ─────────────────────────────────────────────────────────────────────────────

func TestParseOSRelease(t *testing.T) {
	data := []byte(`PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
# a comment
UNKNOWN_KEY=something
`)
	id, version, pretty := parseOSRelease(data)
	if id != "ubuntu" {
		t.Errorf("id = %q, want ubuntu", id)
	}
	if version != "22.04" {
		t.Errorf("version = %q, want 22.04", version)
	}
	if pretty != "Ubuntu 22.04.3 LTS" {
		t.Errorf("pretty = %q, want %q", pretty, "Ubuntu 22.04.3 LTS")
	}

	// An unknown key must not make the whole file unparseable: distributions add
	// their own, and rejecting the file over one would report every such host as
	// unknown.
	if id, _, _ := parseOSRelease([]byte("WEIRD=1\nID=alpine\n")); id != "alpine" {
		t.Errorf("id = %q, want alpine despite the unknown key", id)
	}
}

// TestClassifyPlatformRecognisesRealFirmwareStrings uses the strings the
// providers actually write. The two ordering-sensitive rows are the point: Azure
// and Hyper-V are distinguished only by the chassis asset tag, and VirtualBox
// must be tested before Oracle because Oracle owns VirtualBox.
func TestClassifyPlatformRecognisesRealFirmwareStrings(t *testing.T) {
	tests := []struct {
		desc     string
		vendor   string
		product  string
		assetTag string
		want     CloudProvider
	}{
		{"aws nitro", "Amazon EC2", "m5.large", "", CloudProviderAWS},
		{"aws xen", "Xen", "HVM domU", "", CloudProviderXen},
		{"gcp", "Google", "Google Compute Engine", "", CloudProviderGCP},
		{"azure", "Microsoft Corporation", "Virtual Machine", azureChassisAssetTag, CloudProviderAzure},
		{"hyper-v on-premises", "Microsoft Corporation", "Virtual Machine", "", CloudProviderHyperV},
		{"vmware", "VMware, Inc.", "VMware Virtual Platform", "", CloudProviderVMware},
		{"kvm", "QEMU", "Standard PC (i440FX + PIIX, 1996)", "", CloudProviderKVM},
		{"virtualbox", "innotek GmbH", "VirtualBox", "", CloudProviderVirtualBox},
		{"virtualbox under oracle branding", "Oracle Corporation", "VirtualBox", "", CloudProviderVirtualBox},
		{"openstack", "OpenStack Foundation", "OpenStack Nova", "", CloudProviderOpenStack},
		{"alibaba", "Alibaba Cloud", "Alibaba Cloud ECS", "", CloudProviderAlibaba},
		{"physical dell", "Dell Inc.", "PowerEdge R750", "", CloudProviderBareMetal},
		{"physical supermicro", "Supermicro", "Super Server", "", CloudProviderBareMetal},
		{"no firmware", "", "", "", CloudProviderUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if got := classifyPlatform(tc.vendor, tc.product, tc.assetTag); got != tc.want {
				t.Errorf("classifyPlatform(%q, %q, %q) = %v, want %v",
					tc.vendor, tc.product, tc.assetTag, got, tc.want)
			}
		})
	}
}

func TestAWSInstanceIDIsValidatedNotTrusted(t *testing.T) {
	// The asset tag is firmware-supplied and flows into an entity natural key,
	// so it is validated rather than passed through.
	if got := awsInstanceIDFrom("i-0abc123def4567890"); got != "i-0abc123def4567890" {
		t.Errorf("a valid instance ID was rejected: %q", got)
	}
	for _, bad := range []string{"", "Default string", "i-", "i-zzz", "not-an-id", "i-" + strings.Repeat("a", 64)} {
		if got := awsInstanceIDFrom(bad); got != "" {
			t.Errorf("%q was accepted as an instance ID (got %q)", bad, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestParseUintRejectsOverflowAndGarbage(t *testing.T) {
	if _, err := parseUint([]byte("18446744073709551616")); err == nil {
		t.Error("an integer past uint64 was accepted")
	}
	for _, s := range []string{"", "-1", "1.5", "0x10", "12a"} {
		if _, err := parseUint([]byte(s)); err == nil {
			t.Errorf("%q was accepted as an integer", s)
		}
	}
	if v, err := parseUint([]byte("18446744073709551615")); err != nil || v != 1<<64-1 {
		t.Errorf("max uint64 = %v, %v", v, err)
	}
}

func TestSplitLinesHandlesCRLFAndMissingTrailingNewline(t *testing.T) {
	got := splitLines([]byte("a\r\nb\nc"))
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(got), got)
	}
	if string(got[0]) != "a" || string(got[2]) != "c" {
		t.Errorf("lines = %q", got)
	}
	if n := len(splitLines([]byte("a\n"))); n != 1 {
		t.Errorf("a trailing newline produced %d lines, want 1", n)
	}
	if n := len(splitLines(nil)); n != 0 {
		t.Errorf("empty input produced %d lines", n)
	}
}
