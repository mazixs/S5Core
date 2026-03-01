package obfs

import (
	"bytes"
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

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	obfsServer, err := NewConn(serverConn, cfg)
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

func TestObfsConn_InvalidPSK(t *testing.T) {
	_, err := NewConn(nil, Config{PSK: []byte("short")})
	if err == nil {
		t.Fatal("expected error with invalid PSK length")
	}
}

func TestObfsConn_ZeroPadding(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("b"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	obfsServer, err := NewConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	msg := []byte("zero padding test")

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		n, readErr := obfsServer.Read(buf)
		if readErr != nil {
			t.Errorf("read error: %v", readErr)
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("mismatch: got %q", string(buf[:n]))
		}
		close(done)
	}()

	if _, err := obfsClient.Write(msg); err != nil {
		t.Fatalf("write error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestObfsConn_OversizedPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("c"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	oversized := make([]byte, 70000) // > 65535
	_, err = obfsClient.Write(oversized)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestObfsConn_CorruptedFrame(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("d"), 32)
	cfg := Config{PSK: psk, MaxPadding: 10}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Write valid frame from client
	go func() {
		_, _ = obfsClient.Write([]byte("test"))
	}()

	// Read raw bytes from pipe and corrupt them before feeding to obfs reader
	rawBuf := make([]byte, 4096)
	n, err := serverConn.Read(rawBuf)
	if err != nil {
		t.Fatalf("raw read error: %v", err)
	}

	// Corrupt a byte in the ciphertext area (after 4-byte header + 12-byte nonce)
	if n > 20 {
		rawBuf[20] ^= 0xFF
	}

	// Create a new pipe to feed corrupted data
	corruptedReader, corruptedWriter := net.Pipe()
	defer corruptedReader.Close()
	defer corruptedWriter.Close()

	go func() {
		_, _ = corruptedWriter.Write(rawBuf[:n])
	}()

	obfsCorrupted, err := NewConn(corruptedReader, cfg)
	if err != nil {
		t.Fatalf("failed to create corrupted reader: %v", err)
	}

	buf := make([]byte, 1024)
	_, err = obfsCorrupted.Read(buf)
	if err == nil {
		t.Fatal("expected decryption error for corrupted frame")
	}
}

func TestObfsConn_WireIsEncrypted(t *testing.T) {
	// Verify that SOCKS5 signature bytes never appear on the wire
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("e"), 32)
	cfg := Config{PSK: psk, MaxPadding: 32}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	socks5Handshake := []byte{0x05, 0x01, 0x00} // SOCKS5 greeting

	go func() {
		_, _ = obfsClient.Write(socks5Handshake)
	}()

	// Read raw wire bytes
	rawBuf := make([]byte, 4096)
	n, err := serverConn.Read(rawBuf)
	if err != nil {
		t.Fatalf("raw read error: %v", err)
	}

	wireData := rawBuf[:n]
	if bytes.Contains(wireData, socks5Handshake) {
		t.Fatal("SOCKS5 signature found on wire — obfuscation failed!")
	}

	// Also check for the 0x05 byte at common positions (should not be at predictable spots)
	// Header is 4 bytes (frame size), then 12 bytes nonce, then ciphertext
	// The plaintext 0x05 should NOT appear in ciphertext
	if len(wireData) > 16 && wireData[16] == 0x05 {
		t.Log("Warning: first ciphertext byte matches SOCKS5 version byte (could be coincidence)")
	}
}

func TestObfsConn_MultipleMessages(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("f"), 32)
	cfg := Config{PSK: psk, MaxPadding: 16}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	obfsServer, err := NewConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	messages := []string{"first", "second", "third message with more data"}

	done := make(chan struct{})
	go func() {
		for _, msg := range messages {
			buf := make([]byte, 1024)
			n, readErr := obfsServer.Read(buf)
			if readErr != nil {
				t.Errorf("read error: %v", readErr)
				break
			}
			if string(buf[:n]) != msg {
				t.Errorf("expected %q, got %q", msg, string(buf[:n]))
			}
		}
		close(done)
	}()

	for _, msg := range messages {
		if _, err := obfsClient.Write([]byte(msg)); err != nil {
			t.Fatalf("write error: %v", err)
		}
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestObfsConn_ShortBuffer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("g"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	obfsServer, err := NewConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	longMsg := bytes.Repeat([]byte("x"), 500)

	done := make(chan struct{})
	go func() {
		// Read in small chunks — internal buffer should handle reassembly
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
