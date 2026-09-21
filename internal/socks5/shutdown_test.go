package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// wakeDelay is how long a read on a closed destination takes to come back.
// It stands for what a real socket does: Close unblocks the reader, but not
// on the same instruction. Without the delay both the old code and the new
// one look identical, because the difference between them is precisely
// whether the relay is waited for or merely left to finish on its own.
const wakeDelay = 100 * time.Millisecond

// slowCloseConn is a destination whose reads block until it is closed and
// then take wakeDelay to return. It counts how many reads are in flight, so
// a test can ask the one question that matters here: is anything still
// copying now that the handler has returned?
type slowCloseConn struct {
	closing   chan struct{}
	closeOnce sync.Once
	inFlight  atomic.Int64
	closed    atomic.Bool
}

func newSlowCloseConn() *slowCloseConn {
	return &slowCloseConn{closing: make(chan struct{})}
}

func (c *slowCloseConn) Read([]byte) (int, error) {
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	<-c.closing
	time.Sleep(wakeDelay)
	return 0, net.ErrClosed
}

func (c *slowCloseConn) Write(b []byte) (int, error) {
	select {
	case <-c.closing:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (c *slowCloseConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closing)
	})
	return nil
}

func (c *slowCloseConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *slowCloseConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *slowCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *slowCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *slowCloseConn) SetWriteDeadline(time.Time) error { return nil }

func quietServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

// connectTo issues a CONNECT and reads its reply on an already greeted
// connection.
func connectTo(t *testing.T, c net.Conn, cmd byte) {
	t.Helper()
	req := []byte{Socks5Version, cmd, 0, ipv4Address, 127, 0, 0, 1}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 9)
	req = append(req, port...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("request reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("request refused with %#x", reply[1])
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A cancelled context ends the relay, and ending it means both halves have
// stopped - not that they will stop shortly. The wait used to be skipped:
// the loop saw the cancelled context, returned, and left two goroutines
// copying through a connection its caller was in the middle of closing. The
// destination stayed open until a deferred close reached it, so a shutdown
// raced every live relay instead of ending it.
func TestACancelledRelayEndsBothHalvesBeforeReturning(t *testing.T) {
	target := newSlowCloseConn()
	server := quietServer(t, &Config{
		Dial: func(context.Context, string, string) (net.Conn, error) { return target, nil },
	})

	client, serverSide := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ServeConnContext(ctx, serverSide) }()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	greet(t, client)
	connectTo(t, client, ConnectCommand)

	// The relay is running: the half towards the client is reading from the
	// destination.
	waitFor(t, "the relay to start reading from the destination", func() bool {
		return target.inFlight.Load() == 1
	})

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return after its context was cancelled")
	}

	if n := target.inFlight.Load(); n != 0 {
		t.Errorf("%d relay reads are still running after the handler returned", n)
	}
	if !target.closed.Load() {
		t.Error("the destination is still open after the handler returned")
	}
}

// The same rule for the UDP-over-TCP tunnel (command 0x83). Both of its
// goroutines return in silence when the context is cancelled, and the
// handler waited for a message on a channel that nobody was left to send
// on. It hung there for good, holding a UDP socket whose close is deferred
// to that very function - so one client using 0x83 was enough to make
// Server.Stop wait forever.
func TestACancelledUDPTunnelReleasesItsHandler(t *testing.T) {
	server := quietServer(t, &Config{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.ServeContext(ctx, ln) }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, client)
	connectTo(t, client, UDPTunnelCommand)

	// Cancelling reaches the handlers; closing the listener is what ends the
	// accept loop, exactly as Server.Stop does it.
	cancel()
	_ = ln.Close()

	// ServeContext waits for its handlers, so its return is the proof that
	// the tunnel's handler returned too.
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the UDP tunnel handler never returned, so the server cannot stop")
	}
}

// And the goroutines the tunnel started are gone with it. The UDP half sat
// in ReadFromUDP on a socket that was never closed, which is a goroutine and
// a socket per tunnel, kept for the life of the process.
func TestACancelledUDPTunnelLeavesNoGoroutines(t *testing.T) {
	before := goroutineCount()

	for i := 0; i < 5; i++ {
		func() {
			server := quietServer(t, &Config{})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()

			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan error, 1)
			go func() { served <- server.ServeContext(ctx, ln) }()

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = client.Close() }()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))

			greet(t, client)
			connectTo(t, client, UDPTunnelCommand)

			cancel()
			_ = ln.Close()
			select {
			case <-served:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not return")
			}
		}()
	}

	// Five tunnels, two goroutines each: a leak shows up as ten, not as one.
	waitFor(t, "the tunnel goroutines to end", func() bool {
		return goroutineCount() <= before+2
	})
}

func goroutineCount() int {
	runtime.GC()
	return runtime.NumGoroutine()
}
