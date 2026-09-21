//go:build !windows

package signals

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// deliverHarmlessSignal sends the process a signal that does nothing on its
// own - SIGWINCH is ignored by default - and reports whether ch received it.
// A channel subscribed to everything receives it; a channel subscribed to
// nothing does not.
func deliverHarmlessSignal(t *testing.T, ch chan os.Signal) bool {
	t.Helper()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("signal self: %v", err)
	}
	select {
	case <-ch:
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}

func stopNotify(ch chan os.Signal) { signal.Stop(ch) }

// Unix is where the reload and the log level toggle actually work, and both
// are documented behaviour of the running server - README and
// docs/design/observability-policy.md. An empty list here would take them
// away without anything failing.
func TestUnixKeepsItsReloadAndToggleSignals(t *testing.T) {
	if len(Reload) == 0 {
		t.Error("no reload signal on unix: SIGHUP is how USERS_FILE, the whitelist and " +
			"TRANSPORT_ADVICE are re-read on a running server")
	}
	if len(ToggleDebug) == 0 {
		t.Error("no debug toggle on unix: SIGUSR1 is the zero-configuration way to turn " +
			"diagnostics on during an incident")
	}
}
