package s5server

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// Plan task Ф4-8, the part a stand cannot check on its own: a keepalive frame
// has to keep the server's idle timeout from firing. It is not obvious that it
// does - the frame carries no payload, so nothing about it reaches the relay,
// and if the deadline were refreshed by payload rather than by bytes arriving
// on the socket, an idle tunnel would still be dropped while the keepalive
// kept dutifully running.
//
// The timeouts here are milliseconds rather than the shipped seconds, and the
// connections are real sockets rather than a synctest bubble: the deadline
// being tested is held by the kernel, which fake time does not move.
func TestAKeepaliveKeepsTheServerFromTimingOut(t *testing.T) {
	echoAddr := startEchoServer(t)
	usersPath := testUsersFile(t)

	const obfsPort = "19446"
	startServer(t, Config{
		Port:           "19082",
		ListenIP:       "127.0.0.1",
		RequireAuth:    true,
		UsersFile:      usersPath,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 256,
		ObfsMTU:        1400,
		// The idle timeout under test. Everything else is scaled to it.
		ReadTimeout:  400 * time.Millisecond,
		WriteTimeout: 400 * time.Millisecond,
	})

	open := func(t *testing.T, keepMin, keepMax time.Duration) net.Conn {
		t.Helper()
		raw, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = raw.Close() })

		tunnel, err := obfs.NewClientConn(raw, obfs.Config{
			PSK:          []byte(testPSK),
			MaxPadding:   256,
			MTU:          1400,
			KeepaliveMin: keepMin,
			KeepaliveMax: keepMax,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		t.Cleanup(func() { _ = tunnel.Close() })

		if err := tunnel.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		if err := socks5Connect(tunnel, "alice", "secret1", echoAddr); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if err := echoOnce(tunnel, "open"); err != nil {
			t.Fatalf("the tunnel did not work before the idle period: %v", err)
		}
		return tunnel
	}

	// Silence longer than the idle timeout. With keepalive the tunnel must
	// still carry traffic afterwards; without it, it must not - otherwise the
	// test would pass for the wrong reason, on a server that had no timeout.
	const idle = 1200 * time.Millisecond

	t.Run("with keepalive", func(t *testing.T) {
		tunnel := open(t, 100*time.Millisecond, 200*time.Millisecond)
		time.Sleep(idle)
		if err := tunnel.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		if err := echoOnce(tunnel, "after"); err != nil {
			t.Fatalf("the tunnel was dropped despite the keepalive: %v", err)
		}
	})

	t.Run("without keepalive", func(t *testing.T) {
		tunnel := open(t, 0, 0)
		time.Sleep(idle)
		if err := tunnel.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		if err := echoOnce(tunnel, "after"); err == nil {
			t.Fatal("the tunnel survived the idle timeout without a keepalive, so the run above proves nothing")
		}
	})
}

// echoOnce sends a message through the tunnel and waits for it to come back.
func echoOnce(conn net.Conn, msg string) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return nil
}
