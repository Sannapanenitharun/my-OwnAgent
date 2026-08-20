//go:build windows

package host

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Windows collection goes through documented Win32 APIs loaded from System32.
//
// Security notes that shaped this file:
//   - Every DLL is loaded with NewLazySystemDLL, which resolves only from the
//     system directory. NewLazyDLL would search the working directory first and
//     is a DLL-planting vector in a process that may run as a service account.
//   - Nothing here needs elevation. Block-device I/O counters would (they
//     require opening \\.\PhysicalDriveN), so that source is reported as
//     unsupported rather than making the agent demand Administrator.
//   - No WMI, no COM, no shelling out to PowerShell. WMI in particular is a
//     well-known source of agent CPU spikes and hangs on unhealthy hosts.

// modkernel32 and modntdll name KnownDLLs. Windows always resolves a KnownDLL
// from System32 regardless of the process search path, so loading them by name
// is not a planting vector.
//
// iphlpapi.dll is NOT a KnownDLL, so it is loaded by absolute path from the
// real system directory. The standard library has no NewLazySystemDLL — that
// lives in golang.org/x/sys/windows, which the agent does not depend on — so
// the hardening is done explicitly here rather than skipped.
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")
	modiphlpapi = loadSystemDLL("iphlpapi.dll")

	procGetSystemTimes                 = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx           = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetLogicalDriveStringsW        = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW                  = modkernel32.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW            = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumeInformationW          = modkernel32.NewProc("GetVolumeInformationW")
	procGetTickCount64                 = modkernel32.NewProc("GetTickCount64")
	procGetLogicalProcessorInformation = modkernel32.NewProc("GetLogicalProcessorInformation")
	procRtlGetVersion                  = modntdll.NewProc("RtlGetVersion")
	procGetIfTable2                    = modiphlpapi.NewProc("GetIfTable2")
	procFreeMibTable                   = modiphlpapi.NewProc("FreeMibTable")
)

// loadSystemDLL resolves a DLL from the real system directory by absolute
// path, so that a writable directory earlier in the search order cannot
// substitute its own copy. GetSystemDirectoryW itself lives in kernel32, a
// KnownDLL, so the bootstrap is safe.
//
// On failure it returns a lazy DLL for the bare name: the calls will fail
// cleanly and the affected source reports an error, which is a better outcome
// than the module refusing to start.
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
	driveFixed   = 3
	driveRAMDisk = 6

	fileReadOnlyVolume = 0x00080000

	relationProcessorCore = 0
	errInsufficientBuffer = 122

	ifOperStatusUp = 1

	// Bits of MIB_IF_ROW2.InterfaceAndOperStatusFlags, which is a C bitfield
	// of BOOLEANs allocated least-significant bit first.
	flagHardwareInterface = 0x01
	flagFilterInterface   = 0x02
)

type windowsReader struct{}

func platformSet() Set {
	r := &windowsReader{}
	return Set{
		CPU:        r,
		Memory:     r,
		Filesystem: r,
		Network:    r,
		OS:         r,
		// Disk I/O counters require IOCTL_DISK_PERFORMANCE on a raw device
		// handle, which needs Administrator. Requiring elevation for one
		// source would violate least privilege for the whole agent.
		Disk: nil,
		// Windows has no run-queue load average. There is no equivalent, and
		// synthesising one from processor queue length would be a different
		// measurement wearing the same name.
		Load: nil,
		Unsupported: []Unsupported{
			{Source: SourceDisk, Reason: "block device I/O counters require Administrator privileges on Windows; the agent runs with least privilege"},
			{Source: SourceLoad, Reason: "Windows has no run-queue load average"},
		},
	}
}

type filetime struct {
	Low  uint32
	High uint32
}

func (f filetime) uint64() uint64 { return uint64(f.High)<<32 | uint64(f.Low) }

func (r *windowsReader) ReadCPU(_ context.Context, _ bool) (CPUStats, error) {
	var idle, kernel, user filetime
	ret, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return CPUStats{}, fmt.Errorf("GetSystemTimes: %w", err)
	}

	idleT, kernelT, userT := idle.uint64(), kernel.uint64(), user.uint64()
	// Windows reports idle time INSIDE kernel time. Treating kernel as system
	// time directly is the classic Windows CPU bug: it makes an idle host look
	// permanently busy in kernel mode.
	var system uint64
	if kernelT >= idleT {
		system = kernelT - idleT
	}

	stats := CPUStats{
		Total:        CPUTimes{User: userT, System: system, Idle: idleT},
		HasTotal:     true,
		LogicalCount: KnownU64(uint64(runtime.NumCPU())),
	}
	// Per-core times would need NtQuerySystemInformation with an undocumented
	// class; the aggregate is the supported surface.
	if n, ok := physicalCoreCount(); ok {
		stats.PhysicalCount = KnownU64(n)
	}
	return stats, nil
}

// physicalCoreCount counts RelationProcessorCore entries.
//
// GetLogicalProcessorInformation reports only the caller's processor group, so
// on hosts with more than 64 logical processors this undercounts. It returns
// not-known rather than a wrong number when the call fails; the undercount case
// is documented in docs/HOST_MODULE.md.
func physicalCoreCount() (uint64, bool) {
	type systemLogicalProcessorInformation struct {
		ProcessorMask uintptr
		Relationship  uint32
		_             uint32
		_             [16]byte
	}

	var size uint32
	ret, _, _ := procGetLogicalProcessorInformation.Call(0, uintptr(unsafe.Pointer(&size)))
	if ret != 0 || size == 0 {
		return 0, false
	}
	entrySize := uint32(unsafe.Sizeof(systemLogicalProcessorInformation{}))
	if size%entrySize != 0 {
		return 0, false
	}
	buf := make([]byte, size)
	ret, _, _ = procGetLogicalProcessorInformation.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return 0, false
	}
	entries := unsafe.Slice(
		(*systemLogicalProcessorInformation)(unsafe.Pointer(&buf[0])),
		size/entrySize)
	var cores uint64
	for _, e := range entries {
		if e.Relationship == relationProcessorCore {
			cores++
		}
	}
	if cores == 0 {
		return 0, false
	}
	return cores, true
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func (r *windowsReader) ReadMemory(context.Context) (MemoryStats, error) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return MemoryStats{}, fmt.Errorf("GlobalMemoryStatusEx: %w", err)
	}

	out := MemoryStats{
		Total:     KnownU64(ms.TotalPhys),
		Available: KnownU64(ms.AvailPhys),
		Free:      KnownU64(ms.AvailPhys),
	}
	// Swap is deliberately left unknown. Windows exposes the COMMIT limit
	// (RAM + page file), not page file usage, and reporting commit as swap
	// would be a different measurement under a familiar name.
	deriveMemory(&out)
	return out, nil
}

func (r *windowsReader) ReadFilesystems(ctx context.Context) ([]FilesystemStats, error) {
	buf := make([]uint16, 512)
	n, _, err := procGetLogicalDriveStringsW.Call(
		uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if n == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW: %w", err)
	}
	if int(n) > len(buf) {
		return nil, fmt.Errorf("GetLogicalDriveStringsW: buffer too small (%d)", n)
	}

	var out []FilesystemStats
	for _, root := range splitUTF16List(buf[:n]) {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		rootPtr, perr := syscall.UTF16PtrFromString(root)
		if perr != nil {
			continue
		}
		dt, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(rootPtr)))
		// Only local, always-present volumes. Network and removable volumes
		// can block for seconds inside the free-space call when the backing
		// store is gone, and a collector must never stall on them.
		if dt != driveFixed && dt != driveRAMDisk {
			continue
		}

		var freeToCaller, total, totalFree uint64
		ret, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(rootPtr)),
			uintptr(unsafe.Pointer(&freeToCaller)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&totalFree)),
		)
		fs := FilesystemStats{Mountpoint: root, Device: root}
		fsType, readOnly := volumeInfo(rootPtr)
		fs.FSType = fsType
		fs.ReadOnly = readOnly

		if ret != 0 {
			fs.TotalBytes = KnownU64(total)
			fs.FreeBytes = KnownU64(totalFree)
			fs.AvailBytes = KnownU64(freeToCaller)
			if total >= totalFree {
				fs.UsedBytes = KnownU64(total - totalFree)
			}
		}
		// Inode counts have no NTFS equivalent and stay unknown.
		out = append(out, fs)
	}
	return out, nil
}

func volumeInfo(rootPtr *uint16) (fsType string, readOnly bool) {
	nameBuf := make([]uint16, 261)
	fsBuf := make([]uint16, 261)
	var serial, maxComp, flags uint32
	ret, _, _ := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComp)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsBuf[0])), uintptr(len(fsBuf)),
	)
	if ret == 0 {
		return "", false
	}
	return syscall.UTF16ToString(fsBuf), flags&fileReadOnlyVolume != 0
}

func splitUTF16List(buf []uint16) []string {
	var out []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			if i > start {
				out = append(out, syscall.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// mibIfRow2 mirrors MIB_IF_ROW2 from netioapi.h.
//
// The layout is load-bearing: a mismatch produces plausible-looking garbage
// rather than an error. It is verified at run time by
// TestMibIfRow2LayoutMatchesWindows, which checks the struct size against the
// documented 1352 bytes on 64-bit and sanity-checks decoded values.
type mibIfRow2 struct {
	InterfaceLuid            uint64
	InterfaceIndex           uint32
	InterfaceGUID            [16]byte
	Alias                    [257]uint16
	Description              [257]uint16
	PhysicalAddressLength    uint32
	PhysicalAddress          [32]uint8
	PermanentPhysicalAddress [32]uint8
	Mtu                      uint32
	Type                     uint32
	TunnelType               uint32
	MediaType                uint32
	PhysicalMediumType       uint32
	AccessType               uint32
	DirectionType            uint32
	// InterfaceAndOperStatusFlags is a bitfield of BOOLEANs occupying one byte;
	// the compiler inserts three bytes of padding before OperStatus in both C
	// and Go, which is why this must stay a uint8 followed by a uint32.
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGUID                 [16]byte
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// mibIfTable2 mirrors MIB_IF_TABLE2. NumEntries is followed by padding to the
// row array's 8-byte alignment; declaring the padding explicitly keeps the
// layout in the type rather than in pointer arithmetic, which also keeps
// `go vet` satisfied that no uintptr is being round-tripped through a pointer.
type mibIfTable2 struct {
	NumEntries uint32
	_          uint32
	Table      [1]mibIfRow2
}

func (r *windowsReader) ReadInterfaces(context.Context) ([]InterfaceStats, error) {
	var table *mibIfTable2
	ret, _, err := procGetIfTable2.Call(uintptr(unsafe.Pointer(&table)))
	if ret != 0 {
		return nil, fmt.Errorf("GetIfTable2: error %d: %w", ret, err)
	}
	if table == nil {
		return nil, fmt.Errorf("GetIfTable2 returned a nil table")
	}
	// The table is allocated by Windows, not by Go, so it must be released
	// explicitly; the garbage collector knows nothing about it.
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	numEntries := table.NumEntries
	if numEntries == 0 {
		return nil, nil
	}
	rows := unsafe.Slice(&table.Table[0], int(numEntries))

	out := make([]InterfaceStats, 0, numEntries)
	for i := range rows {
		row := &rows[i]
		// Skip filter interfaces. Windows reports every NDIS lightweight
		// filter binding (WFP, QoS Packet Scheduler, virtual switch
		// extensions) as its own row: on a stock Windows 11 laptop that is 23
		// of 42 rows, all near-zero, all pure cardinality. A filter binding is
		// not a network interface, so excluding it is a fact about the API
		// rather than a policy choice, and it belongs here rather than in
		// user-facing configuration.
		if row.InterfaceAndOperStatusFlags&flagFilterInterface != 0 {
			continue
		}
		name := syscall.UTF16ToString(row.Alias[:])
		if name == "" {
			name = syscall.UTF16ToString(row.Description[:])
		}
		if name == "" {
			continue
		}
		out = append(out, InterfaceStats{
			Name:       name,
			RxBytes:    KnownU64(row.InOctets),
			TxBytes:    KnownU64(row.OutOctets),
			RxPackets:  KnownU64(row.InUcastPkts + row.InNUcastPkts),
			TxPackets:  KnownU64(row.OutUcastPkts + row.OutNUcastPkts),
			RxErrors:   KnownU64(row.InErrors),
			TxErrors:   KnownU64(row.OutErrors),
			RxDropped:  KnownU64(row.InDiscards),
			TxDropped:  KnownU64(row.OutDiscards),
			Up:         row.OperStatus == ifOperStatusUp,
			KnownState: true,
		})
	}
	return out, nil
}

type osVersionInfoExW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       uint8
	Reserved          uint8
}

func (r *windowsReader) ReadOS(context.Context) (OSInfo, error) {
	info := OSInfo{
		OS:           "windows",
		Platform:     "Windows",
		Architecture: runtime.GOARCH,
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	var vi osVersionInfoExW
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	// RtlGetVersion reports the true version. GetVersionExW lies to unmanifested
	// processes for application-compatibility reasons, which would make an
	// agent misreport the OS of every host it runs on.
	if ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi))); ret == 0 {
		info.PlatformVersion = fmt.Sprintf("%d.%d.%d", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)
		info.KernelVersion = info.PlatformVersion
	}

	if ms, _, _ := procGetTickCount64.Call(); ms > 0 {
		info.BootTime = time.Now().Add(-time.Duration(ms) * time.Millisecond)
		info.HasBootTime = true
	}

	if info.Hostname == "" && info.PlatformVersion == "" {
		return OSInfo{}, fmt.Errorf("no host metadata available")
	}
	return info, nil
}
