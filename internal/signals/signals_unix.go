//go:build !windows

package signals

import (
	"os"
	"syscall"
)

// Terminate asks the process to stop and let its connections finish.
var Terminate = []os.Signal{os.Interrupt, syscall.SIGTERM}

// Reload asks it to re-read what it may re-read while running.
var Reload = []os.Signal{syscall.SIGHUP}

// ToggleDebug asks it to flip the log level, for an incident on a process
// that is already running and whose environment cannot be changed from
// outside.
var ToggleDebug = []os.Signal{syscall.SIGUSR1}
