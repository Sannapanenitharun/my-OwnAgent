//go:build !linux

package container

func supported() bool { return false }

func readSamples(_ int) ([]sample, error) {
	return nil, nil
}

type sample struct {
	ShortID     string
	Runtime     string
	MemoryBytes int64
	CPUUtil     float64
	Net         netCounters
}
