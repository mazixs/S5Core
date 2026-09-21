package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// sessionConn carries a session down to the SOCKS5 core, the way the listener
// pipeline does in production. ServeConnContext finds it through session.Of,
// so the test can watch the same state machine the server drives.
type sessionConn struct {
	net.Conn
	sess *session.Session
}

func (c *sessionConn) Session() *session.Session { return c.sess }

// Close mirrors the production listener pipeline, where the outermost wrapper
// (metricsConn) closes the session when the connection closes. ServeConn's
// own defer therefore drives the final Closed transition, exactly as it does
// on a real server.
func (c *sessionConn) Close() error {
	c.sess.Close()
	return c.Conn.Close()
}

// serveOverPipe runs one connection through the SOCKS5 server and returns the
// client end plus the session the server is driving on the server end.
func serveOverPipe(t *testing.T, conf *Config) (net.Conn, *session.Session) {
	t.Helper()
	// A dial budget long enough never to fire on its own: the tests that care
	// about the dialing state hold the dial open by hand.
	sess := session.NewRegistry(nil).Open("plain", false, session.SLA{Dial: time.Hour})
	return serveWithSession(t, conf, sess), sess
}

// serveWithSession runs one connection through the server with a session the
// caller controls, so a test can set the SLA and watch the transitions.
func serveWithSession(t *testing.T, conf *Config, sess *session.Session) net.Conn {
	t.Helper()
	server, err := New(conf)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	srv := &sessionConn{Conn: serverSide, sess: sess}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeConnContext(context.Background(), srv)
	}()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		<-done
	})
	return clientSide
}

// greet performs the no-auth handshake and returns once the server has
// answered it.
func greet(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{5, 1, NoAuth}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if reply[1] != NoAuth {
		t.Fatalf("server chose method %#x, want no-auth", reply[1])
	}
}

// waitForProtocol waits for the server to move the session to want, so the
// test never depends on how fast the handler goroutine gets scheduled.
func waitForProtocol(t *testing.T, sess *session.Session, want session.Protocol) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sess.Protocol() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("session never reached %s, it is in %s", want, sess.Protocol())
}

// A CONNECT that reaches the relay leaves the handshake behind: the protocol
// region is Relay and the connection is a stream, so the relay idle timeout
// applies and the handshake budget no longer does.
func TestConnectReachesTheRelayState(t *testing.T) {
	target, destination := net.Pipe()
	conf := &Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return destination, nil
		},
	}
	client, sess := serveOverPipe(t, conf)
	// Registered after serveOverPipe, so it runs before it: cleanups run last
	// in, first out, and the relay has to be torn down before ServeConn can
	// return.
	t.Cleanup(func() {
		_ = target.Close()
		_ = destination.Close()
	})

	greet(t, client)
	req := []byte{5, ConnectCommand, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], 8080)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("connect failed with reply %#x", reply[1])
	}

	waitForProtocol(t, sess, session.Relay)
	if sess.Kind() != session.Stream {
		t.Fatalf("a CONNECT is a %v, want a stream", sess.Kind())
	}
}

// The dialing state is where the bug report piled connections up: the client
// has sent CONNECT and is waiting for a reply the server cannot send until
// the destination answers. Holding the dial open makes that state observable.
func TestDialingIsVisibleWhileTheDialBlocks(t *testing.T) {
	release := make(chan struct{})
	dialed := make(chan struct{})
	conf := &Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(dialed)
			<-release
			return nil, context.Canceled
		},
	}
	client, sess := serveOverPipe(t, conf)
	t.Cleanup(func() { close(release) })

	greet(t, client)
	req := []byte{5, ConnectCommand, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], 8080)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}
	<-dialed
	waitForProtocol(t, sess, session.Dialing)
}

// The 0x83 tunnel carries UDP for as long as the application keeps it open,
// and is silent whenever the application has nothing to send: it becomes a
// tunnel, which is the kind that lives under no idle timeout.
func TestUDPTunnelBecomesATunnel(t *testing.T) {
	client, sess := serveOverPipe(t, &Config{BindIP: net.ParseIP("127.0.0.1")})

	greet(t, client)
	if _, err := client.Write([]byte{5, UDPTunnelCommand, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("tunnel request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("tunnel reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("tunnel refused with reply %#x", reply[1])
	}

	waitForProtocol(t, sess, session.Relay)
	if sess.Kind() != session.Tunnel {
		t.Fatalf("the 0x83 tunnel is a %v, want a tunnel", sess.Kind())
	}
}

// A UDP association uses its TCP connection as nothing but a lifetime marker:
// no bytes ever flow on it, so it is a tunnel too.
func TestUDPAssociateBecomesATunnel(t *testing.T) {
	client, sess := serveOverPipe(t, &Config{BindIP: net.ParseIP("127.0.0.1")})

	greet(t, client)
	if _, err := client.Write([]byte{5, AssociateCommand, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("associate request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("associate refused with reply %#x", reply[1])
	}

	waitForProtocol(t, sess, session.Relay)
	if sess.Kind() != session.Tunnel {
		t.Fatalf("a UDP association is a %v, want a tunnel", sess.Kind())
	}
}
