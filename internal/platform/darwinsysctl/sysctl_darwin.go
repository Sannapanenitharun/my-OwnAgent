//go:build darwin

// Package darwinsysctl reads binary sysctl values without the NUL-stripping
// that syscall.Sysctl applies for string payloads.
package darwinsysctl

import (
	"fmt"
	"syscall"
	"unsafe"
)

// CTL_MAXNAME is from <sys/sysctl.h>.
const ctlMaxName = 12

// Bytes reads a binary sysctl via SYS___SYSCTL, preserving every returned byte
// (including trailing NULs). syscall.Sysctl cannot be used for values such as
// hw.memsize and vm.loadavg: it treats the buffer as a C string and drops a
// trailing 0x00, which is a common low byte on little-endian integer payloads.
func Bytes(name string, min int) ([]byte, error) {
	mib, err := nametomib(name)
	if err != nil {
		return nil, fmt.Errorf("sysctl %s: %w", name, err)
	}

	var n uintptr
	if err := sysctl(mib, nil, &n, nil, 0); err != nil {
		return nil, fmt.Errorf("sysctl %s (size): %w", name, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("sysctl %s: empty", name)
	}

	buf := make([]byte, n)
	if err := sysctl(mib, &buf[0], &n, nil, 0); err != nil {
		return nil, fmt.Errorf("sysctl %s: %w", name, err)
	}
	if int(n) < min {
		return nil, fmt.Errorf("sysctl %s: short read (%d bytes, want at least %d)", name, n, min)
	}
	return buf[:n], nil
}

func nametomib(name string) ([]int32, error) {
	// Magic sysctl {0,3}: write the name, read back the integer MIB.
	var buf [ctlMaxName + 2]int32
	n := uintptr(ctlMaxName) * unsafe.Sizeof(buf[0])
	nameBytes, err := syscall.ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}
	query := [2]int32{0, 3}
	if err := sysctl(query[:], (*byte)(unsafe.Pointer(&buf[0])), &n, &nameBytes[0], uintptr(len(name))); err != nil {
		return nil, err
	}
	count := int(n / unsafe.Sizeof(buf[0]))
	out := make([]int32, count)
	copy(out, buf[:count])
	return out, nil
}

func sysctl(mib []int32, old *byte, oldlen *uintptr, new *byte, newlen uintptr) error {
	var mibPtr unsafe.Pointer
	if len(mib) > 0 {
		mibPtr = unsafe.Pointer(&mib[0])
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(mibPtr),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(old)),
		uintptr(unsafe.Pointer(oldlen)),
		uintptr(unsafe.Pointer(new)),
		newlen,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
