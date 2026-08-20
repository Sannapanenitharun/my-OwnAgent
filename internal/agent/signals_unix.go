//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// terminationSignals are the signals that begin a graceful shutdown.
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// reloadSignals are the signals that trigger a configuration reload. SIGHUP is
// the long-established convention for this on Unix, and service managers and
// configuration management tools already know how to send it.
func reloadSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}
