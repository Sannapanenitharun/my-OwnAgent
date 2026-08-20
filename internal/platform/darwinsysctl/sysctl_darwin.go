//go:build darwin

// Package darwinsysctl reads binary sysctl values without the NUL-stripping
// that syscall.Sysctl applies for string payloads.
package darwinsysctl

import (
	"fmt"
	"syscall"
)

// Bytes reads a binary sysctl and restores a trailing NUL that syscall.Sysctl
// may have stripped. Without that restore, values such as hw.memsize (often
// ending in 0x00 on little-endian hosts) and vm.loadavg (fscale padding) fail
// short-read checks on real macOS runners.
func Bytes(name string, min int) ([]byte, error) {
	raw, err := syscall.Sysctl(name)
	if err != nil {
		return nil, err
	}
	b := []byte(raw)
	if len(b) == min-1 {
		b = append(b, 0)
	}
	if len(b) < min {
		return nil, fmt.Errorf("sysctl %s: short read (%d bytes, want at least %d)", name, len(b), min)
	}
	return b, nil
}
