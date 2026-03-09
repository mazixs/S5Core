package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

func TestMatchDomain(t *testing.T) {
	patterns := []string{"example.com", "*.google.com"}

	tests := []struct {
		fqdn    string
		matched bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true}, // case insensitive
		{"other.com", false},
		{"sub.example.com", false},    // not wildcard for example.com
		{"google.com", true},          // *.google.com also matches google.com
		{"www.google.com", true},      // wildcard match
		{"deep.sub.google.com", true}, // deep wildcard
		{"notgoogle.com", false},
	}

	for _, tt := range tests {
		result := matchDomain(tt.fqdn, patterns)
		if result != tt.matched {
			t.Errorf("matchDomain(%q, %v) = %v, want %v", tt.fqdn, patterns, result, tt.matched)
		}
	}
}

func TestMatchDomain_EmptyPatterns(t *testing.T) {
	if matchDomain("example.com", nil) {
		t.Error("expected no match with empty patterns")
	}
	if matchDomain("example.com", []string{}) {
		t.Error("expected no match with empty patterns")
	}
}

func TestSocks5Handshake_ReadsFragmentedFrames(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type result struct {
		req  []byte
		cmd  byte
		fqdn string
		err  error
	}

	resCh := make(chan result, 1)
	go func() {
		req, cmd, fqdn, err := socks5Handshake(serverConn)
		resCh <- result{
			req:  append([]byte(nil), req...),
			cmd:  cmd,
			fqdn: fqdn,
			err:  err,
		}
	}()

	greeting := []byte{0x05, 0x01, 0x00}
	for _, b := range greeting {
		if _, err := clientConn.Write([]byte{b}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
	}

	var greetingResp [2]byte
	if _, err := io.ReadFull(clientConn, greetingResp[:]); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if !bytes.Equal(greetingResp[:], []byte{0x05, 0x00}) {
		t.Fatalf("unexpected greeting response: %v", greetingResp)
	}

	req := []byte{
		0x05, 0x01, 0x00, 0x03, 0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	}
	chunks := [][]byte{
		req[:2],
		req[2:5],
		req[5:11],
		req[11:],
	}
	for _, chunk := range chunks {
		if _, err := clientConn.Write(chunk); err != nil {
			t.Fatalf("write request chunk: %v", err)
		}
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("socks5Handshake: %v", res.err)
	}
	if res.cmd != 0x01 {
		t.Fatalf("unexpected command: %d", res.cmd)
	}
	if res.fqdn != "example.com" {
		t.Fatalf("unexpected fqdn: %q", res.fqdn)
	}
	if !bytes.Equal(res.req, req) {
		t.Fatalf("unexpected raw request: got %v want %v", res.req, req)
	}
}

func TestDialObfsTunnel_PipelinesConnectWithoutAuth(t *testing.T) {
	const psk = "01234567890123456789012345678901"

	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}

	addr, done := startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		if !bytes.Equal(greeting[:], []byte{0x05, 0x01, 0x00}) {
			t.Fatalf("unexpected greeting: %v", greeting)
		}

		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		gotConnect := make([]byte, len(connectReq))
		if _, err := io.ReadFull(conn, gotConnect); err != nil {
			t.Fatalf("expected pipelined CONNECT before greeting response: %v", err)
		}
		if !bytes.Equal(gotConnect, connectReq) {
			t.Fatalf("unexpected CONNECT request: got %v want %v", gotConnect, connectReq)
		}

		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			t.Fatalf("write greeting response: %v", err)
		}
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatalf("write connect response: %v", err)
		}
	})
	defer done()

	obfsConn, err := dialObfsTunnel(clientParams{
		ServerAddr: addr,
		PSK:        psk,
		MTU:        1400,
	}, connectReq)
	if err != nil {
		t.Fatalf("dialObfsTunnel: %v", err)
	}
	_ = obfsConn.Close()
}

func TestDialObfsTunnel_PipelinesConnectAfterAuthSelection(t *testing.T) {
	const psk = "01234567890123456789012345678901"
	const user = "alice"
	const pass = "secret"

	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}
	authReq := buildUserPassAuthPacket(user, pass)

	addr, done := startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
		var greeting [4]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		if !bytes.Equal(greeting[:], []byte{0x05, 0x02, 0x00, 0x02}) {
			t.Fatalf("unexpected greeting: %v", greeting)
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			t.Fatalf("write method selection: %v", err)
		}

		gotAuth := make([]byte, len(authReq))
		if _, err := io.ReadFull(conn, gotAuth); err != nil {
			t.Fatalf("read auth request: %v", err)
		}
		if !bytes.Equal(gotAuth, authReq) {
			t.Fatalf("unexpected auth request: got %v want %v", gotAuth, authReq)
		}

		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		gotConnect := make([]byte, len(connectReq))
		if _, err := io.ReadFull(conn, gotConnect); err != nil {
			t.Fatalf("expected pipelined CONNECT before auth response: %v", err)
		}
		if !bytes.Equal(gotConnect, connectReq) {
			t.Fatalf("unexpected CONNECT request: got %v want %v", gotConnect, connectReq)
		}

		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			t.Fatalf("write auth response: %v", err)
		}
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatalf("write connect response: %v", err)
		}
	})
	defer done()

	obfsConn, err := dialObfsTunnel(clientParams{
		ServerAddr: addr,
		ProxyUser:  user,
		ProxyPass:  pass,
		PSK:        psk,
		MTU:        1400,
	}, connectReq)
	if err != nil {
		t.Fatalf("dialObfsTunnel: %v", err)
	}
	_ = obfsConn.Close()
}

func startTestObfsServer(t *testing.T, psk string, handler func(t *testing.T, conn net.Conn)) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)

		rawConn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer rawConn.Close()

		conn, err := obfs.NewConn(rawConn, obfs.Config{
			PSK: []byte(psk),
			MTU: 1400,
		})
		if err != nil {
			t.Errorf("obfs.NewConn: %v", err)
			return
		}

		handler(t, conn)
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-doneCh
	}
}
