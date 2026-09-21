package s5server

import (
	"io"
	"net"
	"testing"
	"time"
)

// Hold the server's close until explicitly released. TCP connect and client
// close are not an acknowledgement that the handler released its limit slot.
func TestPortReadinessWaitsForTheServerToFinishTheProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	go func() { defer close(ready); waitForPort(t, port) }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("probe must half-close its write side: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("reported ready before the server closed the probe")
	default:
	}
	_ = conn.Close()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("did not observe server close")
	}
}
