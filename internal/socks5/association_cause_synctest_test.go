package socks5

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// splitConn reads from one pipe and writes into another, so the client can
// end its direction while the server's writes stay blocked on a reader that
// never comes. The first SetDeadline in the past sleeps after waking the
// blocked write: in a bubble the sleep returns only once every other
// goroutine has run as far as it can, so the half woken by the deadline gets
// to errCh before the half that set it, whatever the scheduler would do.
type splitConn struct {
	in, out net.Conn
	armed   atomic.Bool
}

func (c *splitConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *splitConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *splitConn) LocalAddr() net.Addr         { return c.in.LocalAddr() }
func (c *splitConn) RemoteAddr() net.Addr        { return c.in.RemoteAddr() }

func (c *splitConn) Close() error {
	_ = c.out.Close()
	return c.in.Close()
}

func (c *splitConn) SetDeadline(d time.Time) error {
	_ = c.in.SetDeadline(d)
	err := c.out.SetDeadline(d)
	if !d.IsZero() && !d.After(time.Now()) && c.armed.CompareAndSwap(true, false) {
		time.Sleep(time.Millisecond)
	}
	return err
}

func (c *splitConn) SetReadDeadline(d time.Time) error  { return c.in.SetReadDeadline(d) }
func (c *splitConn) SetWriteDeadline(d time.Time) error { return c.out.SetWriteDeadline(d) }

// A client that closes its tunnel ended the association, even when the
// deadline that stops the other half wakes it with a timeout first: the
// cause goes to errCh before the deadline is set (Ч-9, udpTunnel.stop).
func TestAClosedTunnelIsEndedByTheClientNotByTheTimeoutItWakes(t *testing.T) {
	echo := udpEchoOnLoopback(t)
	synctest.Test(t, func(t *testing.T) {
		ends := make(chan string, 4)
		server, err := New(&Config{
			Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
			OnAssociationEnd: func(_, reason string) { ends <- reason },
		})
		if err != nil {
			t.Fatal(err)
		}
		clientIn, serverIn := net.Pipe()
		serverOut, clientOut := net.Pipe()
		sc := &splitConn{in: serverIn, out: serverOut}
		sess := session.NewRegistry(nil).Open("plain", false, session.SLA{Dial: time.Hour})
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = server.ServeConnContext(context.Background(), &sessionConn{Conn: sc, sess: sess})
		}()

		if _, err := clientIn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if _, err := io.ReadFull(clientOut, make([]byte, 2)); err != nil {
			t.Fatalf("greeting reply: %v", err)
		}
		if _, err := clientIn.Write([]byte{0x05, UDPTunnelCommand, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatalf("request: %v", err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(clientOut, reply); err != nil {
			t.Fatalf("reply: %v", err)
		}
		if reply[1] != successReply {
			t.Fatalf("tunnel refused: 0x%02x", reply[1])
		}

		dest := AddrSpec{IP: echo.Addr().AsSlice(), Port: int(echo.Port())}
		header := AppendAddr([]byte{0, 0, 0}, &dest)
		if _, err := clientIn.Write(tunnelFrameOf(header, []byte("ping"))); err != nil {
			t.Fatalf("datagram: %v", err)
		}
		// The answer comes back and its write into the tunnel blocks: nobody
		// reads clientOut from here on.
		synctest.Wait()

		sc.armed.Store(true)
		_ = clientIn.Close()
		<-done
		_ = clientOut.Close()

		select {
		case got := <-ends:
			if got != EndedByClient {
				t.Fatalf("a tunnel the client closed ended by %q, want %q", got, EndedByClient)
			}
		default:
			t.Fatal("no association end was reported")
		}
	})
}
