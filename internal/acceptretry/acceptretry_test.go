package acceptretry

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// The errors that are worth retrying are the ones about this moment rather
// than about the socket. Each of them used to be fatal to the listener.
func TestEveryMomentaryKernelErrorIsRetried(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS,
		syscall.ENOMEM, syscall.ECONNABORTED, syscall.EINTR, syscall.EAGAIN,
	} {
		if !Recoverable(errno) {
			t.Errorf("%v (%d) ends the listener, but the next accept can succeed", errno, uint(errno))
		}
		if !Recoverable(&net.OpError{Op: "accept", Err: errno}) {
			t.Errorf("%v wrapped in net.OpError - the form Accept actually returns - is not recognised", errno)
		}
	}

	// The opposite: a closed listener never comes back, and retrying it is
	// a spin at full speed.
	if Recoverable(net.ErrClosed) {
		t.Error("a closed listener is treated as retryable, which spins the accept loop")
	}
	if Recoverable(&net.OpError{Op: "accept", Err: net.ErrClosed}) {
		t.Error("a closed listener wrapped in net.OpError is treated as retryable")
	}
	if Recoverable(errors.New("some other failure")) {
		t.Error("an unknown failure is retried, so a permanent one loops forever")
	}
	if Recoverable(nil) {
		t.Error("no error is treated as a failure to retry")
	}
}

func TestTheWaitDoublesFromFiveMillisecondsToOneSecond(t *testing.T) {
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	d := time.Duration(0)
	for i, w := range want {
		d = Next(d)
		if d != w*time.Millisecond {
			t.Fatalf("wait %d is %v, want %v", i, d, w*time.Millisecond)
		}
	}
}
