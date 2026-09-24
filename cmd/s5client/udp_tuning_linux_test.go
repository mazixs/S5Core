package main

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// The client end of a UDP association retransmits early with the setting on
// and keeps the kernel's timer with it off. The client-to-server direction
// depends on the client's kernel alone: it is the sender that runs the timer.
func TestTheClientTunesItsUDPTunnel(t *testing.T) {
	for _, on := range []bool{true, false} {
		app, clientSide := tcpPair(t)
		tunnel, obfsSide := tcpPair(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleUDPAssociate(clientSide, obfsSide, "example.com", clientParams{UDPTunnelTCPTuning: on})
		}()
		if _, err := tunnel.Write(udpTunnelReply); err != nil {
			t.Fatal(err)
		}
		// The reply to the application comes after the tuning.
		readAppReply(t, app)
		raw, err := obfsSide.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var got int
		var gerr error
		_ = raw.Control(func(fd uintptr) {
			got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_THIN_LINEAR_TIMEOUTS)
		})
		if gerr != nil {
			t.Fatal(gerr)
		}
		want := 0
		if on {
			want = 1
		}
		if got != want {
			t.Fatalf("tuning %v: thin linear timeouts = %d, want %d", on, got, want)
		}
		_ = app.Close()
		_ = tunnel.Close()
		<-done
	}
}
