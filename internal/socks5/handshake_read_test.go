package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countingConn counts the reads that reach the socket. It is the number this
// test is about: every one of them is a syscall on a real connection, and a
// SOCKS5 handshake used to spend about a dozen of them reading fields of one
// and two bytes.
type countingConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(b)
}

// fullHandshake is what a client that does not wait between steps sends: the
// greeting, the username and password, and the CONNECT, in one write. Our own
// client does exactly this - the prologue, the greeting and the CONNECT go
// out in a single obfuscated frame, which is why the handshake costs no extra
// round trip (docs/gates/g4-first-frame.md).
func fullHandshake(user, pass string, port int) []byte {
	out := []byte{Socks5Version, 1, UserPassAuth}
	out = append(out, userAuthVersion, byte(len(user)))
	out = append(out, user...)
	out = append(out, byte(len(pass)))
	out = append(out, pass...)
	out = append(out, Socks5Version, ConnectCommand, 0, ipv4Address, 127, 0, 0, 1)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	return append(out, p...)
}

// Plan task Ф6-5: the server used to read the handshake field by field
// straight from the socket. A buffered read turns that into one.
func TestTheHandshakeCostsOneReadFromTheSocket(t *testing.T) {
	creds := StaticCredentials{"alice": "correct horse"}
	server, err := New(&Config{
		AuthMethods: []Authenticator{&UserPassAuthenticator{Credentials: creds}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// A destination that answers nothing and closes at once: this
			// test is about what happened before the dial.
			client, srv := net.Pipe()
			_ = srv.Close()
			return client, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clientSide, serverSide := net.Pipe()
	counted := &countingConn{Conn: serverSide}

	// atDial is the count at the moment the handshake is over: everything
	// after it belongs to the relay.
	atDial := make(chan int64, 1)
	server.config.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case atDial <- counted.reads.Load():
		default:
		}
		client, srv := net.Pipe()
		_ = srv.Close()
		return client, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeConnContext(context.Background(), counted)
	}()

	if err := clientSide.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// Drain whatever the server says back before writing: net.Pipe is
	// unbuffered, so a server blocked on its reply would never read the rest
	// of the handshake.
	go func() {
		_, _ = io.Copy(io.Discard, clientSide)
	}()
	if _, err := clientSide.Write(fullHandshake("alice", "correct horse", 9)); err != nil {
		t.Fatalf("write the handshake: %v", err)
	}

	var reads int64
	select {
	case reads = <-atDial:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never got as far as dialing")
	}
	_ = clientSide.Close()
	<-done

	// One read is what a buffered handshake costs when the client sends it in
	// one piece. Two would mean the buffer is smaller than a handshake; the
	// dozen it used to be is what this test exists to keep away.
	if reads > 2 {
		t.Fatalf("the handshake took %d reads from the socket, want at most 2", reads)
	}
	t.Logf("the handshake took %d read(s) from the socket", reads)
}

// A client that waits for each reply - which the RFC allows and some clients
// do - must still be served. The buffer must not turn three exchanges into a
// read that blocks waiting for bytes the client is not going to send until it
// hears back.
func TestAStepByStepClientIsStillServed(t *testing.T) {
	creds := StaticCredentials{"alice": "correct horse"}
	server, err := New(&Config{
		AuthMethods: []Authenticator{&UserPassAuthenticator{Credentials: creds}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A destination that echoes, so the relay has something to carry.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c)
	}()

	clientSide, serverSide := net.Pipe()
	go func() { _ = server.ServeConnContext(context.Background(), serverSide) }()
	if err := clientSide.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(clientSide, b); err != nil {
			t.Fatalf("read %d bytes: %v", n, err)
		}
		return b
	}

	// Greeting, then wait.
	if _, err := clientSide.Write([]byte{Socks5Version, 1, UserPassAuth}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if got := read(2); got[1] != UserPassAuth {
		t.Fatalf("the server chose method %d, want %d", got[1], UserPassAuth)
	}

	// Credentials, then wait.
	auth := []byte{userAuthVersion, 5}
	auth = append(auth, "alice"...)
	auth = append(auth, 13)
	auth = append(auth, "correct horse"...)
	if _, err := clientSide.Write(auth); err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if got := read(2); got[1] != authSuccess {
		t.Fatalf("authentication failed: %v", got)
	}

	// CONNECT, then wait.
	port := ln.Addr().(*net.TCPAddr).Port
	req := []byte{Socks5Version, ConnectCommand, 0, ipv4Address, 127, 0, 0, 1}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	if _, err := clientSide.Write(append(req, p...)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := read(10); got[1] != successReply {
		t.Fatalf("the server replied %d to CONNECT", got[1])
	}

	// And the relay carries bytes the buffer never saw.
	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatalf("write through the relay: %v", err)
	}
	if got := string(read(4)); got != "ping" {
		t.Fatalf("the relay echoed %q, want ping", got)
	}
}

// Bytes a client sends immediately after its CONNECT, before the reply, must
// reach the destination. They land in the handshake buffer, and a buffer that
// forgot them would lose the first write of every pipelining client.
func TestBytesSentWithTheRequestSurviveTheBuffer(t *testing.T) {
	creds := StaticCredentials{"alice": "correct horse"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		got <- string(b)
	}()

	server, err := New(&Config{
		AuthMethods: []Authenticator{&UserPassAuthenticator{Credentials: creds}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	go func() { _ = server.ServeConnContext(context.Background(), serverSide) }()
	go func() { _, _ = io.Copy(io.Discard, clientSide) }()

	if err := clientSide.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	payload := append(fullHandshake("alice", "correct horse", port), "ping"...)
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case s := <-got:
		if s != "ping" {
			t.Fatalf("the destination received %q, want ping", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the bytes sent with the request never reached the destination")
	}
}
