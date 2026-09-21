package signals

import (
	"os"
	"testing"
)

// signal.Notify(ch) with no signals subscribes to every signal there is. A
// platform that has nothing to listen for would therefore start listening for
// everything - including the ones Go's runtime uses - if the empty list were
// passed through. Notify exists to make that impossible, and this is the
// statement of it.
func TestAskingForNoSignalsAsksForNothing(t *testing.T) {
	ch := make(chan os.Signal, 1)
	if Notify(ch) {
		t.Fatal("Notify reported that it subscribed to an empty list of signals")
	}
	if delivered := deliverHarmlessSignal(t, ch); delivered {
		t.Fatal("a channel that asked for no signals received one; " +
			"signal.Notify with no signals means every signal")
	}
}

// The same call with a signal does subscribe, or the platform lists would be
// decoration.
func TestAskingForASignalSubscribes(t *testing.T) {
	sigs := ToggleDebug
	if len(sigs) == 0 {
		sigs = Terminate
	}
	if len(sigs) == 0 {
		t.Skip("this platform names no signals at all")
	}

	ch := make(chan os.Signal, 1)
	if !Notify(ch, sigs...) {
		t.Fatalf("Notify refused to subscribe to %v", sigs)
	}
	stopNotify(ch)
}

// Terminate is not optional anywhere: a process that cannot be asked to stop
// has to be killed, and killing it skips the traffic flush.
func TestEveryPlatformCanBeAskedToStop(t *testing.T) {
	if len(Terminate) == 0 {
		t.Fatal("this platform lists no termination signal, so a clean shutdown cannot be requested")
	}
}
