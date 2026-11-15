package sockerr

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

// A deadline is a timeout wherever it surfaces, so is the system's ETIMEDOUT,
// and nothing else is.
func TestTimeoutIsADeadlineOrTheSystemGivingUp(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"system timeout", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ETIMEDOUT)}, true},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, false},
		{"end of stream", io.EOF, false},
		{"no error", nil, false},
	} {
		if got := Timeout(tc.err); got != tc.want {
			t.Errorf("%s: Timeout(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
