package obfs

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestObfsConn_EncryptionAndPadding(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("a"), 32)
	cfg := Config{PSK: psk, MaxPadding: 64}

	obfsClient, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	obfsServer, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server obfs conn: %v", err)
	}

	originalMsg := []byte("hello world, testing S5Core obfuscation")

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		n, readErr := obfsServer.Read(buf)
		if readErr != nil {
			t.Errorf("server read error: %v", readErr)
		}
		if string(buf[:n]) != string(originalMsg) {
			t.Errorf("expected %q, got %q", string(originalMsg), string(buf[:n]))
		}
		close(done)
	}()

	n, err := obfsClient.Write(originalMsg)
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}
	if n != len(originalMsg) {
		t.Fatalf("expected to write %d bytes, wrote %d", len(originalMsg), n)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to read")
	}
}

// An empty write still puts a frame on the wire - the shape of the traffic
// should not depend on a caller passing a zero-length buffer - but it no
// longer surfaces as a zero-length read. A frame carrying no payload is what
// a keepalive is (Ф4-8), and the reader skips it and waits for the next one.
// Returning (0, nil) instead would make io.Copy spin and would let a keepalive
// look like a closed stream to a caller that checks n.
func TestAnEmptyWriteDoesNotReachTheReader(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("b"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	obfsServer, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server obfs conn: %v", err)
	}

	type read struct {
		n   int
		err error
	}
	reads := make(chan read, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := obfsServer.Read(buf)
		reads <- read{n, err}
	}()

	if _, err := obfsClient.Write([]byte{}); err != nil {
		t.Fatalf("write empty payload: %v", err)
	}

	select {
	case r := <-reads:
		t.Fatalf("the empty frame surfaced as a read of %d bytes (err %v)", r.n, r.err)
	case <-time.After(200 * time.Millisecond):
	}

	if _, err := obfsClient.Write([]byte("after")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	select {
	case r := <-reads:
		if r.err != nil {
			t.Fatalf("read after the empty frame: %v", r.err)
		}
		if r.n != len("after") {
			t.Fatalf("read %d bytes after the empty frame, want %d", r.n, len("after"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the read after the empty frame never returned")
	}
}

// TestAFrameLengthBelowTheFormatIsRejected replaces a test that fed a
// 4-byte header claiming 131073 bytes. There is no such header any more: the
// length is two masked bytes, so an oversize claim cannot be expressed and the
// check that matters is the other end of the range - a length too small to
// hold even the empty frame.
func TestAFrameLengthBelowTheFormatIsRejected(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("c"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	client, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}
	server, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server obfs conn: %v", err)
	}

	// One real frame first: it carries the salt, so both ends now hold the
	// session keys and the test can mask a length the way the client would.
	go func() { _, _ = client.Write([]byte("hello")) }()
	buf := make([]byte, 16)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("first frame: %v", err)
	}

	srv := server.(*conn)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(5)^srv.recvMask(srv.readCounter))

	readErr := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1024))
		readErr <- err
	}()
	if _, err := clientConn.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	select {
	case err := <-readErr:
		reason, ok := ReasonOf(err)
		if !ok || reason != ReasonShortFrame {
			t.Fatalf("got %v, want a short_frame failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the undersized frame to be rejected")
	}
}

func TestObfsConn_LargePayloadReassembly(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("e"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0, MTU: 1400}

	obfsClient, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	obfsServer, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	longMsg := bytes.Repeat([]byte("x"), 500)

	done := make(chan struct{})
	go func() {
		// Read in small chunks - internal buffer should handle reassembly
		var total []byte
		buf := make([]byte, 10)
		for len(total) < len(longMsg) {
			n, readErr := obfsServer.Read(buf)
			if readErr != nil {
				t.Errorf("read error: %v", readErr)
				break
			}
			total = append(total, buf[:n]...)
		}
		if !bytes.Equal(total, longMsg) {
			t.Errorf("reassembled data mismatch: got %d bytes, want %d", len(total), len(longMsg))
		}
		close(done)
	}()

	if _, err := obfsClient.Write(longMsg); err != nil {
		t.Fatalf("write error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
