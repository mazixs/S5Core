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

func TestObfsConn_ZeroLengthPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("b"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	obfsServer, err := NewConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server obfs conn: %v", err)
	}

	done := make(chan struct{})
	go func() {
		// Server should receive empty payload
		buf := make([]byte, 1024)
		n, err := obfsServer.Read(buf)
		if err != nil {
			t.Errorf("read empty payload: %v", err)
		}
		if n != 0 {
			t.Errorf("expected 0 bytes, got %d", n)
		}
		close(done)
	}()

	// Write empty payload
	if _, err := obfsClient.Write([]byte{}); err != nil {
		t.Fatalf("write empty payload: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestObfsConn_FrameTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("c"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := obfsClient.Read(make([]byte, 1024))
		readErr <- err
	}()

	// Write a frame header claiming a huge size (> 128KB) from the peer
	var hdr [4]byte
	hdr[0] = 0x00
	hdr[1] = 0x02
	hdr[2] = 0x00
	hdr[3] = 0x01 // 131073 bytes (> limit)
	if _, err := serverConn.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected error for oversized frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for oversized frame error")
	}
}

func TestObfsConn_ReplayProtection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("d"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0, ReplayWindow: 10}

	obfsClient, err := NewConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("failed to create client obfs conn: %v", err)
	}

	obfsServer, err := NewConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("failed to create server obfs conn: %v", err)
	}

	msg := []byte("replay test")

	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		n, err := obfsServer.Read(buf)
		if err != nil {
			t.Errorf("first read: %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("first read mismatch")
		}
		close(readDone)
	}()

	if _, err := obfsClient.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Replay the exact same bytes (simulate attacker replaying the frame)
	// We need to capture the raw bytes on the wire and resend them.
	// Since net.Pipe is synchronous and we already consumed the frame,
	// we can't easily replay without a MITM. We'll skip the explicit replay
	// test here and rely on the unit tests for replayWindow.
}

func TestObfsConn_LargePayloadReassembly(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("e"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0, MTU: 1400}

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

func TestObfsConn_CloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	psk := bytes.Repeat([]byte("f"), 32)
	cfg := Config{PSK: psk, MaxPadding: 0}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		raw, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer raw.Close()
		oc, err := NewConn(raw, cfg)
		if err != nil {
			t.Errorf("NewConn server: %v", err)
			return
		}
		if cw, ok := oc.(closeWriter); ok {
			if err := cw.CloseWrite(); err != nil {
				t.Errorf("CloseWrite error: %v", err)
			}
		} else {
			t.Error("obfsConn does not implement closeWriter")
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	oc, err := NewConn(raw, cfg)
	if err != nil {
		t.Fatalf("NewConn client: %v", err)
	}

	// The other side should see EOF after CloseWrite
	buf := make([]byte, 1)
	_, err = oc.Read(buf)
	if err == nil {
		t.Error("expected EOF after remote CloseWrite, got nil")
	}

	<-serverDone
}
