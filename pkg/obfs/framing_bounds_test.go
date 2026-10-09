package obfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestMTUUpperBoundaryRoundTripsWithoutLengthWrap(t *testing.T) {
	for _, mtu := range []int{-1, MinMTU - 1, MaxMTU + 1, 70000} {
		if c, err := NewClientConn(&countingConn{}, Config{PSK: []byte(benchPSK), MTU: mtu}); err == nil {
			c.Close()
			t.Errorf("invalid MTU %d accepted", mtu)
		}
	}
	raw := &countingConn{}
	client, err := NewClientConn(raw, Config{PSK: fuzzPSK, MTU: MaxMTU})
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{0x67}, MaxMTU-frameOverhead)
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for _, size := range frameSizes(t, raw.bytes(), client) {
		if size > MaxMTU {
			t.Fatalf("frame size %d", size)
		}
	}
	server := newFuzzServer(t, raw.bytes(), nil, MaxMTU, nil)
	got, err := server.readAll(t, MaxMTU/4096+2)
	if !errors.Is(err, io.EOF) || !bytes.Equal(got, want) {
		t.Fatalf("delivered %d/%d, %v", len(got), len(want), err)
	}
}

func TestAuthenticatedPadLengthMustMatchTheActualTail(t *testing.T) {
	raw := &countingConn{}
	client, err := NewClientConn(raw, Config{PSK: fuzzPSK})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	c := client.(*conn)
	wire := raw.bytes()
	offset := len(c.wirePrologue)
	length := int(binary.BigEndian.Uint16(wire[offset:]) ^ c.sendMask(0))
	plaintext, err := c.aeadSend.Open(nil, c.sendNonce(0), wire[offset+2:offset+2+length], nil)
	if err != nil {
		t.Fatal(err)
	}
	dataLen := int(binary.BigEndian.Uint16(plaintext[1:]))
	padOffset := 3 + dataLen
	actual := binary.BigEndian.Uint16(plaintext[padOffset:])
	binary.BigEndian.PutUint16(plaintext[padOffset:], actual+1)
	ciphertext := c.aeadSend.Seal(nil, c.sendNonce(0), plaintext, nil)
	copy(wire[offset+2:], ciphertext)
	server := newFuzzServer(t, wire, nil, 0, nil)
	defer server.conn.Close()
	buf := make([]byte, 32)
	if n, err := server.conn.Read(buf); n != 0 || err == nil {
		t.Fatalf("bad authenticated padding delivered %d bytes: %v", n, err)
	}
	if len(server.failures) != 1 {
		t.Fatalf("bad PadLen not reported once: %d", len(server.failures))
	}
}

func TestAnAuthenticatedIdleTimeoutDoesNotLatchTheNextFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, peer := net.Pipe()
		defer peer.Close()
		var failures []*FrameError
		server, err := NewServerConn(raw, Config{PSK: fuzzPSK, OnFailure: func(e *FrameError) { failures = append(failures, e) }})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		client, err := NewClientConn(peer, Config{PSK: fuzzPSK})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := client.Write([]byte("ok")); done <- err }()
		buf := make([]byte, 2)
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		_, err = server.Read(buf)
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() || len(failures) != 0 {
			t.Fatalf("idle: %v, failures %d", err, len(failures))
		}
		_ = server.SetReadDeadline(time.Time{})
		_ = peer.Close()
		if _, err = server.Read(buf); !errors.Is(err, io.ErrUnexpectedEOF) || len(failures) != 1 {
			t.Fatalf("real failure masked: %v, failures %d", err, len(failures))
		}
	})
}
