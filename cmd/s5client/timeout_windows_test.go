package main

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// connect gives up on a silent server with WSAETIMEDOUT, for which
// net.Error.Timeout is false. The application is still told the wait ran out.
func TestAWinsockConnectTimeoutIsATimeout(t *testing.T) {
	err := tunnelFail(phaseDial, "dial: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", windows.WSAETIMEDOUT)})
	if !isTimeout(err) || replyForTunnelError(err) != socks5TTLExpired {
		t.Fatalf("%v is not reported as a timeout", err)
	}
}
