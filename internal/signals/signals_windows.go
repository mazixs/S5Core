//go:build windows

package signals

import (
	"os"
	"syscall"
)

// Terminate is what Windows delivers: Ctrl-C and the console close, both of
// which Go reports as os.Interrupt, plus SIGTERM for a process started under
// a supervisor that sends it.
var Terminate = []os.Signal{os.Interrupt, syscall.SIGTERM}

// Reload is empty. Windows has no SIGHUP to deliver - the constant exists in
// syscall, but nothing sends it - so a binary that listened for it would be
// promising a reload that never arrives. Configuration on Windows changes by
// restarting the process.
var Reload []os.Signal

// ToggleDebug is empty. There is no SIGUSR1 on Windows at all, which is what
// broke the release build. Both ways of changing the log level while the
// process runs go through a signal, so on Windows the level is what
// LOG_LEVEL or LOG_LEVEL_FILE said at startup and changing it means
// restarting. That is a real difference between the platforms and is
// documented as one rather than papered over with a signal nothing sends.
var ToggleDebug []os.Signal
