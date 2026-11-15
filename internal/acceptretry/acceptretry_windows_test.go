package acceptretry

import (
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// Accept on Windows creates the socket for AcceptEx first, and a process out
// of descriptors or buffers fails there with the Winsock code, wrapped as the
// net package returns it.
func TestWinsockShortagesAreRetried(t *testing.T) {
	for _, code := range []syscall.Errno{windows.WSAEMFILE, windows.WSAENOBUFS} {
		err := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("socket", code)}
		if !Recoverable(err) {
			t.Errorf("Winsock %d ends the listener, but the next accept can succeed", uint(code))
		}
	}
}
