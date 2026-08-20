//go:build windows

package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Windows discovery goes through documented Win32 APIs loaded from System32.
//
// Security notes that shaped this file:
//
//   - Every non-KnownDLL is loaded by absolute path from the real system
//     directory. NewLazyDLL alone would search the working directory first and
//     is a DLL-planting vector in a process that may run as a service account.
//   - The Service Control Manager is opened with SC_MANAGER_ENUMERATE_SERVICE
//     and nothing else. That is a read-only right available to any authenticated
//     user; SC_MANAGER_ALL_ACCESS would let the agent start, stop and
//     RECONFIGURE services, which is a host-takeover primitive an observability
//     agent has no business holding.
//   - The TCP and UDP tables are read with the OWNER_PID_LISTENER class, so the
//     kernel returns listeners with their owning process directly. Windows makes
//     free what Linux charges a descriptor scan for.
//   - No WMI, no COM, no PowerShell, no registry writes. WMI in particular is a
//     well-known source of agent CPU spikes and hangs on unhealthy hosts.

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")
	modadvapi32 = loadSystemDLL("advapi32.dll")
	modiphlpapi = loadSystemDLL("iphlpapi.dll")

	procGetTickCount64          = modkernel32.NewProc("GetTickCount64")
	procGetLogicalDriveStringsW = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modkernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformationW   = modkernel32.NewProc("GetVolumeInformationW")
	procRtlGetVersion           = modntdll.NewProc("RtlGetVersion")

	procOpenSCManagerW        = modadvapi32.NewProc("OpenSCManagerW")
	procCloseServiceHandle    = modadvapi32.NewProc("CloseServiceHandle")
	procEnumServicesStatusExW = modadvapi32.NewProc("EnumServicesStatusExW")

	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

// loadSystemDLL resolves a DLL from the real system directory by absolute path,
// so that a writable directory earlier in the search order cannot substitute its
// own copy. GetSystemDirectoryW itself lives in kernel32, a KnownDLL, so the
// bootstrap is safe.
func loadSystemDLL(name string) *syscall.LazyDLL {
	getSystemDirectory := modkernel32.NewProc("GetSystemDirectoryW")
	buf := make([]uint16, 320)
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) >= len(buf) {
		return syscall.NewLazyDLL(name)
	}
	return syscall.NewLazyDLL(syscall.UTF16ToString(buf[:n]) + `\` + name)
}

const (
	// scManagerEnumerateService is the ONLY right requested. See the file
	// comment: the alternative is a host-takeover primitive.
	scManagerEnumerateService = 0x0004

	serviceWin32      = 0x00000030
	serviceStateAll   = 0x00000003
	scEnumProcessInfo = 0

	serviceStopped         = 1
	serviceStartPending    = 2
	serviceStopPending     = 3
	serviceRunning         = 4
	serviceContinuePending = 5
	servicePausePending    = 6
	servicePaused          = 7

	errMoreData           = 234
	errInsufficientBuffer = 122

	driveFixed   = 3
	driveRemote  = 4
	driveRAMDisk = 6

	fileReadOnlyVolume = 0x00080000

	tcpTableOwnerPIDListener = 3
	udpTableOwnerPID         = 1

	afINET  = 2
	afINET6 = 23
)

type windowsSource struct{}

func platformSet() Set {
	s := &windowsSource{}
	return Set{
		Host:       s,
		Process:    s,
		Service:    s,
		Interface:  s,
		Endpoint:   s,
		Filesystem: s,
		Runtime:    s,
		Cloud:      s,
		// Windows containers exist, but they are not discoverable from a host
		// process's own metadata the way cgroup membership is on Linux:
		// establishing which processes belong to which container requires the
		// container runtime's API. Reporting the domain as unavailable is
		// honest; returning an empty list would read as "this host runs no
		// containers".
		Container: nil,
		// The agent could be running in a Windows pod, but the pod-to-container
		// evidence that makes the Kubernetes domain useful comes from cgroups,
		// which Windows does not have.
		Kubernetes: nil,
		Unsupported: []Unsupported{
			{Domain: DomainContainer, Reason: "Windows container membership cannot be established from local process metadata; it requires the container runtime's API, which this agent does not call"},
			{Domain: DomainKubernetes, Reason: "Kubernetes pod evidence on this agent is derived from control groups, which Windows does not provide"},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Host
// ─────────────────────────────────────────────────────────────────────────────

// osVersionInfoEx is RTL_OSVERSIONINFOEXW.
type osVersionInfoEx struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

func (s *windowsSource) DiscoverHost(context.Context) (HostFacts, error) {
	out := HostFacts{
		OS:           "windows",
		Distribution: "windows",
		Architecture: runtime.GOARCH,
	}
	out.Hostname, _ = os.Hostname()

	// RtlGetVersion rather than GetVersionEx: GetVersionEx lies to processes
	// without a compatibility manifest, reporting 6.2 on Windows 10 and later,
	// so an inventory built on it would report a decade-old OS on every host.
	var info osVersionInfoEx
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(info))
	if ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&info))); ret == 0 {
		out.Version = fmt.Sprintf("%d.%d.%d",
			info.MajorVersion, info.MinorVersion, info.BuildNumber)
		out.KernelVersion = out.Version
	}

	if ms, _, _ := procGetTickCount64.Call(); ms > 0 {
		out.BootTime = time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second)
		out.HasBootTime = true
	}

	// A CONSTANT boot namespace, matching the process module's. Windows process
	// start stamps are absolute FILETIMEs, so they need no boot discriminator —
	// and deriving one from the tick count produces a value that changes across
	// agent restarts, which would re-key every process entity on the host. The
	// two modules must agree here or the platform mints two entities per
	// process; see platform/entity.go and ADR-0006.
	out.BootID = windowsBootNamespace

	out.TimeZone, _ = time.Now().Zone()
	return out, nil
}

// windowsBootNamespace must equal process.WindowsBootNamespace.
//
// It is duplicated rather than imported because modules may not import each
// other. That duplication is a real cost and it is guarded rather than trusted:
// an integration test runs both modules' readers on this platform and asserts
// the two constants agree, which is the only way to keep them in step without
// coupling the modules.
const windowsBootNamespace = "windows-absolute-start"

// ─────────────────────────────────────────────────────────────────────────────
// Processes
// ─────────────────────────────────────────────────────────────────────────────

// DiscoverProcesses is deliberately minimal on Windows.
//
// Discovery needs process identity so that services and listeners have something
// to point at. Everything else about a process — CPU, memory, handles — belongs
// to the process module, and enumerating it twice would double the cost of the
// agent's most expensive operation for data this module discards.
//
// The toolhelp snapshot supplies identity for every process in one call, and the
// start stamp comes from OpenProcess/GetProcessTimes for the bounded set that
// actually needs one.
func (s *windowsSource) DiscoverProcesses(ctx context.Context, opts ProcessOptions) (ProcessListing, error) {
	snapshot, err := createToolhelpSnapshot()
	if err != nil {
		return ProcessListing{}, err
	}
	defer syscall.CloseHandle(snapshot)

	var out ProcessListing
	out.Processes = make([]ProcessFacts, 0, 256)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := process32First(snapshot, &entry); err != nil {
		return out, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		facts := ProcessFacts{
			PID:  PID(entry.ProcessID),
			PPID: PID(entry.ParentProcessID),
			Name: syscall.UTF16ToString(entry.ExeFile[:]),
		}
		if start, ok := processStartStamp(entry.ProcessID); ok {
			facts.StartRaw = start
			facts.HasStartRaw = true
		} else if entry.ProcessID <= 4 {
			// The Idle and System processes cannot be opened by anyone. They are
			// real and worth reporting, and a fixed stamp is honest for them
			// because they are created exactly once per boot and never recycled.
			facts.StartRaw = 0
			facts.HasStartRaw = true
		} else {
			out.Denied++
		}
		out.Processes = append(out.Processes, facts)

		if err := process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	_ = opts
	return out, nil
}

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

func createToolhelpSnapshot() (syscall.Handle, error) {
	const th32csSnapProcess = 0x00000002
	h, err := syscall.CreateToolhelp32Snapshot(th32csSnapProcess, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	return h, nil
}

func process32First(h syscall.Handle, e *processEntry32) error {
	return syscall.Process32First(h, (*syscall.ProcessEntry32)(unsafe.Pointer(e)))
}

func process32Next(h syscall.Handle, e *processEntry32) error {
	return syscall.Process32Next(h, (*syscall.ProcessEntry32)(unsafe.Pointer(e)))
}

// processStartStamp returns a process's creation time as a raw FILETIME.
//
// PROCESS_QUERY_LIMITED_INFORMATION, not PROCESS_QUERY_INFORMATION, and the
// difference is the point: the limited right returns creation time and image
// name and CANNOT read process memory, so an agent holding it has no path to the
// address space of what it observes. Being denied another user's process is a
// privilege boundary working correctly, not a fault to fix with elevation.
func processStartStamp(pid uint32) (uint64, bool) {
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(h)

	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, false
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), true
}

// ─────────────────────────────────────────────────────────────────────────────
// Services — the Service Control Manager, read-only
// ─────────────────────────────────────────────────────────────────────────────

// enumServiceStatusProcess is ENUM_SERVICE_STATUS_PROCESSW.
type enumServiceStatusProcess struct {
	ServiceName   *uint16
	DisplayName   *uint16
	ServiceStatus serviceStatusProcess
}

// serviceStatusProcess is SERVICE_STATUS_PROCESS.
type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

// DiscoverServices enumerates Win32 services through the SCM.
//
// This is the richest service inventory of any supported platform, and it is
// free: EnumServicesStatusExW returns the name, display name, state AND owning
// process ID of every service in one call. On Linux the same information needs
// D-Bus, which the module refuses to use.
func (s *windowsSource) DiscoverServices(ctx context.Context) ([]ServiceFacts, error) {
	scm, _, err := procOpenSCManagerW.Call(0, 0, scManagerEnumerateService)
	if scm == 0 {
		return nil, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer procCloseServiceHandle.Call(scm)

	var needed, returned, resume uint32
	ret, _, callErr := procEnumServicesStatusExW.Call(
		scm, scEnumProcessInfo, serviceWin32, serviceStateAll,
		0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)
	if ret != 0 {
		return nil, nil // no services at all, which is legal on Nano Server
	}
	if e, ok := callErr.(syscall.Errno); !ok || (e != errMoreData && e != errInsufficientBuffer) {
		return nil, fmt.Errorf("EnumServicesStatusEx sizing: %w", callErr)
	}
	if needed == 0 {
		return nil, nil
	}

	buf := make([]byte, needed)
	ret, _, callErr = procEnumServicesStatusExW.Call(
		scm, scEnumProcessInfo, serviceWin32, serviceStateAll,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)
	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: %w", callErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The returned count is bounded by what the SCM wrote into a buffer this
	// code sized, so it cannot exceed the buffer — but it is checked anyway,
	// because the alternative to checking a length before an unsafe slice is a
	// memory-safety bug rather than a wrong number.
	entrySize := unsafe.Sizeof(enumServiceStatusProcess{})
	if uintptr(returned)*entrySize > uintptr(len(buf)) {
		return nil, fmt.Errorf("EnumServicesStatusEx returned %d entries, more than the buffer holds", returned)
	}

	out := make([]ServiceFacts, 0, returned)
	entries := unsafe.Slice((*enumServiceStatusProcess)(unsafe.Pointer(&buf[0])), returned)
	for i := range entries {
		e := &entries[i]
		svc := ServiceFacts{
			Name:        utf16PtrToString(e.ServiceName),
			DisplayName: utf16PtrToString(e.DisplayName),
			Kind:        ServiceKindWindows,
			State:       windowsServiceState(e.ServiceStatus.CurrentState),
		}
		if e.ServiceStatus.ProcessID != 0 {
			svc.MainPID = PID(e.ServiceStatus.ProcessID)
			svc.HasMainPID = true
		}
		out = append(out, svc)
	}
	return out, nil
}

func windowsServiceState(state uint32) ServiceState {
	switch state {
	case serviceRunning:
		return ServiceStateRunning
	case serviceStopped:
		return ServiceStateStopped
	case serviceStartPending, serviceContinuePending:
		return ServiceStateStarting
	case serviceStopPending, servicePausePending:
		return ServiceStateStopping
	case servicePaused:
		// Paused is neither running nor stopped. It maps to Stopped rather than
		// Unknown because, from the point of view of anything depending on the
		// service, a paused service is not serving.
		return ServiceStateStopped
	default:
		return ServiceStateUnknown
	}
}

// utf16PtrToString converts a NUL-terminated UTF-16 string with a hard length
// bound.
//
// The bound is not defensive decoration. The pointer comes from a buffer the
// kernel filled, and a walk with no limit on a value that failed to be
// NUL-terminated would read past the allocation — turning a malformed API result
// into a crash or a disclosure.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	const maxChars = 1024
	buf := make([]uint16, 0, 64)
	for i := 0; i < maxChars; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*2))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return syscall.UTF16ToString(buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// Network interfaces
// ─────────────────────────────────────────────────────────────────────────────

func (s *windowsSource) DiscoverInterfaces(context.Context) ([]InterfaceFacts, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating interfaces: %w", err)
	}
	out := make([]InterfaceFacts, 0, len(ifaces))
	for _, iface := range ifaces {
		f := InterfaceFacts{
			Name:         iface.Name,
			Index:        iface.Index,
			HardwareAddr: iface.HardwareAddr.String(),
			MTU:          iface.MTU,
			Up:           iface.Flags&net.FlagUp != 0,
			Loopback:     iface.Flags&net.FlagLoopback != 0,
			Virtual:      isVirtualWindowsInterface(iface),
		}
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				f.Addresses = append(f.Addresses, a.String())
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// isVirtualWindowsInterface classifies by NAME, because Windows exposes no
// cheap per-adapter "is this hardware" flag through the standard library.
//
// The list covers the software adapters that actually proliferate: Hyper-V
// switches on a virtualisation host, the WSL and Docker NAT adapters on a
// developer machine, and VPN tunnels.
var windowsVirtualHints = []string{
	"loopback", "hyper-v", "vethernet", "wsl", "docker", "vmware",
	"virtualbox", "tap-", "tun", "vpn", "teredo", "isatap", "bluetooth",
}

func isVirtualWindowsInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagLoopback != 0 {
		return true
	}
	lower := strings.ToLower(iface.Name)
	for _, h := range windowsVirtualHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Listening endpoints
// ─────────────────────────────────────────────────────────────────────────────

// mibTCPRowOwnerPID is MIB_TCPROW_OWNER_PID.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6RowOwnerPID is MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUDPRowOwnerPID is MIB_UDPROW_OWNER_PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// mibUDP6RowOwnerPID is MIB_UDP6ROW_OWNER_PID.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// DiscoverEndpoints reads the listener tables.
//
// Windows returns the owning PID in the same structure, so the Correlate option
// costs nothing here — the expensive descriptor scan it guards is a Linux-only
// problem. The option is honoured anyway rather than ignored, because an
// operator who turned correlation off asked for endpoints without process
// attribution and should get the same answer on every platform.
func (s *windowsSource) DiscoverEndpoints(ctx context.Context, opts EndpointOptions) ([]EndpointFacts, error) {
	var out []EndpointFacts

	if rows, err := tcpTable(afINET); err == nil {
		for i := range rows {
			out = append(out, EndpointFacts{
				Protocol: ProtocolTCP,
				Address:  formatIPv4BE(rows[i].LocalAddr),
				Port:     ntohs(rows[i].LocalPort),
				OwnerPID: PID(rows[i].OwningPID),
			})
		}
	}
	if rows, err := tcp6Table(); err == nil {
		for i := range rows {
			out = append(out, EndpointFacts{
				Protocol: ProtocolTCP6,
				Address:  formatIPv6(rows[i].LocalAddr),
				Port:     ntohs(rows[i].LocalPort),
				OwnerPID: PID(rows[i].OwningPID),
			})
		}
	}
	if rows, err := udpTable(afINET); err == nil {
		for i := range rows {
			out = append(out, EndpointFacts{
				Protocol: ProtocolUDP,
				Address:  formatIPv4BE(rows[i].LocalAddr),
				Port:     ntohs(rows[i].LocalPort),
				OwnerPID: PID(rows[i].OwningPID),
			})
		}
	}
	if rows, err := udp6Table(); err == nil {
		for i := range rows {
			out = append(out, EndpointFacts{
				Protocol: ProtocolUDP6,
				Address:  formatIPv6(rows[i].LocalAddr),
				Port:     ntohs(rows[i].LocalPort),
				OwnerPID: PID(rows[i].OwningPID),
			})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if opts.Correlate {
		for i := range out {
			if out[i].OwnerPID > 0 {
				out[i].HasOwnerPID = true
			}
		}
	}
	return out, nil
}

// extendedTable is the shared two-call pattern for the four table getters:
// size the buffer, then fill it. It is factored because getting the retry wrong
// — sizing once and assuming the size holds — is a race on a host whose socket
// table changes between the two calls, and it is better to have that logic in
// one place than in four.
func extendedTable(proc *syscall.LazyProc, family uintptr, class uintptr) ([]byte, uint32, error) {
	var size uint32
	for attempt := 0; attempt < 4; attempt++ {
		var base uintptr
		var buf []byte
		if size > 0 {
			buf = make([]byte, size)
			base = uintptr(unsafe.Pointer(&buf[0]))
		}
		ret, _, _ := proc.Call(base, uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		switch ret {
		case 0:
			if buf == nil {
				return nil, 0, nil
			}
			// The first four bytes are dwNumEntries.
			n := *(*uint32)(unsafe.Pointer(&buf[0]))
			return buf, n, nil
		case errInsufficientBuffer:
			// The table grew between the sizing call and the fill. Loop with the
			// new size.
			continue
		default:
			return nil, 0, fmt.Errorf("socket table query failed with code %d", ret)
		}
	}
	return nil, 0, fmt.Errorf("socket table kept growing between calls")
}

// rowsOf converts the variable-length table body into a typed slice, checking
// the length first so that a short buffer is an error rather than an
// out-of-bounds read.
func rowsOf[T any](buf []byte, n uint32) ([]T, error) {
	if buf == nil || n == 0 {
		return nil, nil
	}
	const headerSize = 4
	var zero T
	need := uintptr(n)*unsafe.Sizeof(zero) + headerSize
	if need > uintptr(len(buf)) {
		return nil, fmt.Errorf("socket table declared %d rows but the buffer holds %d bytes", n, len(buf))
	}
	return unsafe.Slice((*T)(unsafe.Pointer(&buf[headerSize])), n), nil
}

func tcpTable(family uintptr) ([]mibTCPRowOwnerPID, error) {
	buf, n, err := extendedTable(procGetExtendedTcpTable, family, tcpTableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	return rowsOf[mibTCPRowOwnerPID](buf, n)
}

func tcp6Table() ([]mibTCP6RowOwnerPID, error) {
	buf, n, err := extendedTable(procGetExtendedTcpTable, afINET6, tcpTableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	return rowsOf[mibTCP6RowOwnerPID](buf, n)
}

func udpTable(family uintptr) ([]mibUDPRowOwnerPID, error) {
	buf, n, err := extendedTable(procGetExtendedUdpTable, family, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return rowsOf[mibUDPRowOwnerPID](buf, n)
}

func udp6Table() ([]mibUDP6RowOwnerPID, error) {
	buf, n, err := extendedTable(procGetExtendedUdpTable, afINET6, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return rowsOf[mibUDP6RowOwnerPID](buf, n)
}

// ntohs converts a network-order port, which the API returns in the low 16 bits
// of a DWORD.
func ntohs(v uint32) uint16 {
	return uint16(v&0xff)<<8 | uint16((v>>8)&0xff)
}

// formatIPv4BE renders an IPv4 address held in network byte order.
//
// Note the contrast with parse.go's parseHexAddr, which handles the LITTLE-endian
// form /proc/net uses. Two platforms, two orders, and mixing them up produces
// real addresses belonging to somebody else — which is why each has its own
// named function rather than one shared "format address".
func formatIPv4BE(addr uint32) string {
	return formatIPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystems
// ─────────────────────────────────────────────────────────────────────────────

func (s *windowsSource) DiscoverFilesystems(context.Context) ([]FilesystemFacts, error) {
	buf := make([]uint16, 256)
	n, _, err := procGetLogicalDriveStringsW.Call(
		uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if n == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStrings: %w", err)
	}
	if int(n) > len(buf) {
		return nil, fmt.Errorf("GetLogicalDriveStrings wants %d words, more than the buffer holds", n)
	}

	var out []FilesystemFacts
	for _, root := range splitUTF16List(buf[:n]) {
		rootPtr, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		dt, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(rootPtr)))
		switch dt {
		case driveFixed, driveRAMDisk, driveRemote:
		default:
			// Removable and CD-ROM drives are excluded: an empty optical drive
			// is not a filesystem, and a USB stick appearing and vanishing would
			// churn the topology for something nobody inventories.
			continue
		}

		fsType, readOnly := volumeInfo(rootPtr)
		out = append(out, FilesystemFacts{
			Mountpoint: strings.TrimSuffix(root, `\`),
			Device:     strings.TrimSuffix(root, `\`),
			FSType:     fsType,
			ReadOnly:   readOnly,
			Remote:     dt == driveRemote,
		})
	}
	return out, nil
}

func volumeInfo(rootPtr *uint16) (fsType string, readOnly bool) {
	var flags uint32
	fsNameBuf := make([]uint16, 32)
	ret, _, _ := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsNameBuf[0])), uintptr(len(fsNameBuf)))
	if ret == 0 {
		// A drive letter with no media, or one the agent may not query. Neither
		// is an error worth failing the whole enumeration for.
		return "", false
	}
	return syscall.UTF16ToString(fsNameBuf), flags&fileReadOnlyVolume != 0
}

// splitUTF16List splits a NUL-separated, double-NUL-terminated UTF-16 list.
func splitUTF16List(buf []uint16) []string {
	var out []string
	start := 0
	for i, c := range buf {
		if c != 0 {
			continue
		}
		if i > start {
			out = append(out, syscall.UTF16ToString(buf[start:i]))
		}
		start = i + 1
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime and cloud
// ─────────────────────────────────────────────────────────────────────────────

func (s *windowsSource) DiscoverRuntime(context.Context) (RuntimeFacts, error) {
	// Windows containers exist, but nothing a process can read about ITSELF
	// distinguishes one from a host reliably enough to report as evidence. The
	// module reports what it knows: not detected.
	return RuntimeFacts{}, nil
}

// DiscoverCloud classifies the platform from the SMBIOS firmware table.
//
// EnumSystemFirmwareTables and GetSystemFirmwareTable would give the raw SMBIOS
// blob, which would then need a full SMBIOS structure parser to reach the same
// three strings Linux exposes as files. That is a meaningful amount of unsafe
// parsing of firmware-supplied data — the exact place a length field is
// mishandled — for information also available from the registry.
//
// Neither is implemented here. The domain reports Unknown rather than guessing,
// and that gap is recorded in the readiness review rather than hidden: Windows
// cloud classification is the module's largest known coverage hole.
func (s *windowsSource) DiscoverCloud(context.Context) (CloudFacts, error) {
	return CloudFacts{Provider: CloudProviderUnknown}, nil
}

var (
	_ HostSource       = (*windowsSource)(nil)
	_ ProcessSource    = (*windowsSource)(nil)
	_ ServiceSource    = (*windowsSource)(nil)
	_ InterfaceSource  = (*windowsSource)(nil)
	_ EndpointSource   = (*windowsSource)(nil)
	_ FilesystemSource = (*windowsSource)(nil)
	_ RuntimeSource    = (*windowsSource)(nil)
	_ CloudSource      = (*windowsSource)(nil)
)
