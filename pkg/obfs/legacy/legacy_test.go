package legacy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testPSK = bytes.Repeat([]byte{0x42}, 32)

// recordingConn keeps what was written so a test can look at the wire.
type recordingConn struct {
	net.Conn
	wire bytes.Buffer
}

func (r *recordingConn) Write(b []byte) (int, error) {
	r.wire.Write(b)
	return r.Conn.Write(b)
}

func pair(t *testing.T, cfg Config) (client net.Conn, server net.Conn, clientWire *recordingConn) {
	t.Helper()
	a, b := net.Pipe()
	clientWire = &recordingConn{Conn: a}
	client, err := NewConn(clientWire, cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err = NewConn(b, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	return client, server, clientWire
}

func TestTheOldFormatRoundTrips(t *testing.T) {
	client, server, _ := pair(t, Config{PSK: testPSK, MaxPadding: 64})

	msg := []byte("CONNECT example.com:443")
	go func() { _, _ = client.Write(msg) }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}

	// The other way, and through a caller's buffer that is too small.
	reply := bytes.Repeat([]byte("r"), 300)
	go func() { _, _ = server.Write(reply) }()
	small := make([]byte, 100)
	var back []byte
	for len(back) < len(reply) {
		n, err := client.Read(small)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		back = append(back, small[:n]...)
	}
	if !bytes.Equal(back, reply) {
		t.Fatal("the reply came back changed")
	}
}

// TestTheWireIsTheOriginalWire is what makes the package worth having: a
// server built from the old code must be able to read what this writes.
// The layout is checked byte by byte against the original definition,
// with the ciphertext opened by a bare AES-GCM under the PSK.
func TestTheWireIsTheOriginalWire(t *testing.T) {
	client, server, wire := pair(t, Config{PSK: testPSK, MaxPadding: 16})

	msg := []byte("hello, old server")
	go func() { _, _ = client.Write(msg) }()
	if _, err := io.ReadFull(server, make([]byte, len(msg))); err != nil {
		t.Fatalf("read: %v", err)
	}

	frame := wire.wire.Bytes()
	if len(frame) < 4+12+16 {
		t.Fatalf("frame is %d bytes, too short for header, nonce and tag", len(frame))
	}
	frameLen := binary.BigEndian.Uint32(frame[:4])
	if int(frameLen) != len(frame)-4 {
		t.Fatalf("header says %d bytes follow, %d do", frameLen, len(frame)-4)
	}
	nonce, ciphertext := frame[4:16], frame[16:]

	block, err := aes.NewCipher(testPSK)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("the ciphertext does not open under the PSK with the wire nonce: %v", err)
	}
	payloadLen := int(binary.BigEndian.Uint16(plaintext[:2]))
	if payloadLen != len(msg) || !bytes.Equal(plaintext[2:2+payloadLen], msg) {
		t.Fatalf("plaintext %x does not carry %q under a 2-byte length", plaintext, msg)
	}
	padLen := int(binary.BigEndian.Uint16(plaintext[2+payloadLen:]))
	if 2+payloadLen+2+padLen != len(plaintext) {
		t.Fatalf("padding length %d does not account for the rest of %d bytes", padLen, len(plaintext))
	}
	if padLen > 16 {
		t.Fatalf("padding %d exceeds MaxPadding 16", padLen)
	}
}

func TestTheReaderRefusesWhatTheOriginalRefused(t *testing.T) {
	t.Run("a frame past the ceiling", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		server, err := NewConn(b, Config{PSK: testPSK})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], maxFrame+1)
			_, _ = a.Write(hdr[:])
		}()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = server.Read(make([]byte, 16))
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("got %v, want a frame-too-large error", err)
		}
	})

	t.Run("a frame under another key", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		client, err := NewConn(a, Config{PSK: testPSK})
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewConn(b, Config{PSK: bytes.Repeat([]byte{0x43}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = client.Write([]byte("x")) }()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = server.Read(make([]byte, 16))
		if err == nil || !strings.Contains(err.Error(), "decrypt") {
			t.Fatalf("got %v, want a decryption failure", err)
		}
	})

	t.Run("a key of the wrong size", func(t *testing.T) {
		a, _ := net.Pipe()
		defer a.Close()
		if _, err := NewConn(a, Config{PSK: []byte("short")}); err == nil {
			t.Fatal("a 5-byte PSK was accepted")
		}
	})

	t.Run("a write over 16 bits of length", func(t *testing.T) {
		client, _, _ := pair(t, Config{PSK: testPSK})
		if _, err := client.Write(make([]byte, maxPayload+1)); err == nil {
			t.Fatal("a 65536-byte write was accepted")
		}
	})
}
