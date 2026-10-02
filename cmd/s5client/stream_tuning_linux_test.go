package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"golang.org/x/sys/unix"
)

// The tunnel of a CONNECT stream is closed by the kernel once what the client
// sent on it has gone unacknowledged for TUNNEL_DEAD_TIMEOUT, and with zero it
// keeps the kernel's rule. The socket is the client's own, so the test takes it
// from the dialler.
func TestTheClientBoundsTheTunnelOfAConnectStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  time.Duration
		want int
	}{
		{"set", 7 * time.Second, 7000},
		{"off", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const psk = "01234567890123456789012345678901"
			addr, done := startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil {
					return
				}
				if _, err := io.ReadFull(conn, make([]byte, len(clientRequest()))); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, conn)
			})
			defer done()

			var mu sync.Mutex
			var dialled net.Conn
			original := dialOutbound
			dialOutbound = func(ctx context.Context, network, a string) (net.Conn, error) {
				c, err := original(ctx, network, a)
				mu.Lock()
				dialled = c
				mu.Unlock()
				return c, err
			}
			t.Cleanup(func() { dialOutbound = original })

			app, local := tcpPair(t)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				handleClient(local, clientParams{ServerAddr: addr, PSK: psk, MTU: 1400, TunnelDeadTimeout: tc.set}, newDomainMatcher(nil))
			}()
			go func() {
				_, _ = app.Write([]byte{0x05, 0x01, 0x00})
				_, _ = app.Write(clientRequest())
			}()
			var reply [2 + 10]byte
			if _, err := io.ReadFull(app, reply[:]); err != nil {
				t.Fatal(err)
			}

			mu.Lock()
			tcp, ok := dialled.(*net.TCPConn)
			mu.Unlock()
			if !ok {
				t.Fatalf("the tunnel was dialled as %T, want a TCP connection", dialled)
			}
			raw, err := tcp.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var gerr error
			_ = raw.Control(func(fd uintptr) {
				got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
			})
			if gerr != nil {
				t.Fatal(gerr)
			}
			if got != tc.want {
				t.Fatalf("TCP_USER_TIMEOUT = %d ms, want %d", got, tc.want)
			}
			_ = app.Close()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("the relay did not end")
			}
		})
	}
}

// What the kernel does to a stream that nothing acknowledges is classified as
// a timeout through the obfuscation layer, which is what an operator reading
// closed_by looks for.
func TestADeadTunnelIsClassifiedAsATimeout(t *testing.T) {
	c, _ := tcpPair(t)
	tunnel, err := obfs.NewClientConn(c, obfs.Config{PSK: []byte("01234567890123456789012345678901"), MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	tuneStream(tunnel, 500*time.Millisecond)

	// The far end never reads, so the window closes and the writes stop; the
	// zero-window time is what the option bounds here (Linux 5.1 and newer).
	res := make(chan copyResult, 1)
	go func() { res <- relayCopy(tunnel, zeroes{}) }()
	select {
	case r := <-res:
		if got := relayClosedBy(r, true); got != closedByTimeout {
			t.Fatalf("closed_by %q for %v, want %q", got, r.err, closedByTimeout)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a tunnel that nothing acknowledges was still open after 20 s")
	}
}

type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) { clear(p); return len(p), nil }
