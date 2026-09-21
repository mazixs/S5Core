package obfs

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// Every test in this package used to push bytes one way: a client wrote, a
// server read. That left the reply direction unexercised, and it was broken -
// the server put a 32-byte salt of its own in front of its first frame, which
// the client neither expects nor can skip, so the first reply on any real
// connection desynced the stream. Over net.Pipe with no reply nobody noticed;
// over TCP every handshake timed out. These tests hold the reply direction
// down, on a real socket, in both shapes it takes: a request answered, and
// both ends talking at once.

func obfsPair(t *testing.T, cfg Config) (client, server net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- accepted{err: err}
			return
		}
		s, err := NewServerConn(raw, cfg)
		ch <- accepted{conn: s, err: err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client, err = NewClientConn(raw, cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	got := <-ch
	if got.err != nil {
		t.Fatalf("server: %v", got.err)
	}
	t.Cleanup(func() { _ = got.conn.Close() })

	deadline := time.Now().Add(10 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = got.conn.SetDeadline(deadline)
	return client, got.conn
}

func TestAServerReplyReachesTheClientOverARealSocket(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client, server := obfsPair(t, Config{PSK: psk, MaxPadding: 256, MTU: 1400})

	question := []byte{0x05, 0x01, 0x00}
	answer := []byte{0x05, 0x00}

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(question))
		if _, err := io.ReadFull(server, buf); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buf, question) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err := server.Write(answer)
		serverDone <- err
	}()

	if _, err := client.Write(question); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(answer))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("the client never got the reply: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
	if !bytes.Equal(got, answer) {
		t.Fatalf("the client read %v, want %v", got, answer)
	}
}

// A tunnel carries a conversation, not a request: both ends write while both
// ends read, over many frames, and the counters that drive nonce and length
// mask have to stay in step in each direction independently.
func TestBothDirectionsCarryTrafficAtOnce(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client, server := obfsPair(t, Config{PSK: psk, MaxPadding: 64, MTU: 512})

	const rounds = 200
	payload := bytes.Repeat([]byte("both ways, please. "), 40) // ~760 bytes, several frames

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		for i := 0; i < rounds; i++ {
			if _, err := io.ReadFull(server, buf); err != nil {
				serverDone <- err
				return
			}
			if !bytes.Equal(buf, payload) {
				serverDone <- io.ErrUnexpectedEOF
				return
			}
			if _, err := server.Write(payload); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	buf := make([]byte, len(payload))
	for i := 0; i < rounds; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("round %d: client write: %v", i, err)
		}
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatalf("round %d: client read: %v", i, err)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatalf("round %d: the reply came back changed", i)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// The reply stream must not open with anything fixed. The server's salt field
// is all zeroes until the client's arrives, so a server that announced a salt
// would open every reply with the same 32 bytes - a constant prefix in the
// direction the level-2 checklist does not sample.
func TestTheReplyStreamOpensWithAFrameNotASalt(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0, MTU: 1400}

	flight := firstFlight(t, cfg, []byte("hello"))

	wire := newScriptConn(flight)
	server, err := NewServerConn(wire, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if _, err := server.Write([]byte("hi")); err != nil {
		t.Fatalf("server write: %v", err)
	}

	reply := wire.out.Bytes()
	// Two payload bytes, no padding: the frame is exactly minCiphertext plus
	// the payload, behind its two-byte length. Anything longer means
	// something was prepended.
	want := 2 + minCiphertext + 2
	if len(reply) != want {
		t.Fatalf("the server's first write is %d bytes, want %d - a 32-byte salt in front would make it %d",
			len(reply), want, want+saltSize)
	}
	if bytes.HasPrefix(reply, make([]byte, saltSize)) {
		t.Fatal("the reply stream opens with zeroes")
	}
}
