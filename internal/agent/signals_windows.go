//go:build windows

package agent

import "os"

// terminationSignals are the signals that begin a graceful shutdown.
//
// Windows delivers console control events (CTRL_C, CTRL_CLOSE) as os.Interrupt,
// and the Go runtime maps a Service Control Manager stop to the same path when
// the agent runs as a service.
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// reloadSignals is empty on Windows.
//
// Windows has no SIGHUP. Rather than emulate one with a signal that means
// something else, the agent exposes no signal-based reload here; the Windows
// reload path is a Service Control Manager custom control, which belongs with
// the service wrapper in Stage 15. Returning nil means the run loop simply
// never selects on a reload, which is honest and has no runtime cost.
func reloadSignals() []os.Signal { return nil }
