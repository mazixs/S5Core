//go:build !windows

package signals

import (
	"context"
	"os"
	"os/exec"
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

func TestHandleRunsTheActionOfItsSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{}, 1)
	Handle(ctx,
		Action{Signals: nil, Do: func() { t.Error("an action with no signals ran") }},
		Action{Signals: []os.Signal{syscall.SIGWINCH}, Do: func() { ran <- struct{}{} }},
	)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("signal self: %v", err)
	}
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the action did not run on its signal")
	}
}

// После отмены ctx сигнал перезагрузки не должен убивать процесс: идут дренаж
// соединений и финальный сброс трафика.
func TestASignalAfterShutdownDoesNotKillTheProcess(t *testing.T) {
	if os.Getenv("SIGNALS_CHILD") == "1" {
		ctx, cancel := context.WithCancel(context.Background())
		Handle(ctx, Action{Signals: Reload, Do: func() {}})
		cancel()
		time.Sleep(50 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
		time.Sleep(200 * time.Millisecond)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestASignalAfterShutdownDoesNotKillTheProcess$")
	cmd.Env = append(os.Environ(), "SIGNALS_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the process died on SIGHUP after shutdown: %v\n%s", err, out)
	}
}
