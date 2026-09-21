//go:build windows

package signals

import (
	"os"
	"os/signal"
	"testing"
)

// Windows has no way for a test to send itself a signal that Go will deliver,
// so the empty-list property is stated by the return value alone there.
func deliverHarmlessSignal(t *testing.T, ch chan os.Signal) bool {
	t.Helper()
	return false
}

func stopNotify(ch chan os.Signal) { signal.Stop(ch) }

// The two empty lists are the point of the Windows file: there is no SIGUSR1
// at all, and no SIGHUP is ever delivered, so promising either would be
// promising something that never happens.
func TestWindowsPromisesNoSignalItCannotReceive(t *testing.T) {
	if len(Reload) != 0 {
		t.Error("windows lists a reload signal; nothing sends SIGHUP there")
	}
	if len(ToggleDebug) != 0 {
		t.Error("windows lists a debug toggle; there is no SIGUSR1 there")
	}
}
