//go:build !darwin

// Package darwinsysctl reads binary sysctl values on Darwin. Off Darwin this
// stub exists so documentation and import checks stay consistent.
package darwinsysctl

import "fmt"

// Bytes is unavailable off Darwin; Darwin-only callers import this package
// behind //go:build darwin files.
func Bytes(string, int) ([]byte, error) {
	return nil, fmt.Errorf("darwinsysctl: available only on darwin")
}
