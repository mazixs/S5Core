package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// target listens on loopback; each connection gets the banner, if any, and
// then an echo of what it sends.
func target(t *testing.T, banner string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if banner != "" {
					if _, err := c.Write([]byte(banner)); err != nil {
						return
					}
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

// socksConnect opens a SOCKS5 CONNECT through the client at proxy and sends
// early in the same write as the request, as a pipelining application does.
func socksConnect(t *testing.T, proxy, dest string, early []byte) (net.Conn, []byte) {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", dest)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	msg := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01}
	msg = append(msg, addr.IP.To4()...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(addr.Port))
	if _, err := c.Write(append(msg, early...)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2+10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("no SOCKS5 answer: %v", err)
	}
	return c, resp[2:]
}

// An application that resets its connection before the server has answered
// ended the connection itself: that is not a failed setup, and the transport
// keeps its standing.
func TestAnApplicationGoneBeforeTheReplyIsNotAFailedSetup(t *testing.T) {
	logs := captureLogs(t)
	side := pipeServer(t)
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	failedBefore := minutes.failed.Load()

	app, local := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(local, cfg, nil)
	}()
	if _, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(app, make([]byte, 2+10)); err != nil {
		t.Fatalf("no early success: %v", err)
	}
	server := serverReadsRequest(t, <-side, cfg)
	go func() { _, _ = io.Copy(io.Discard, server) }()

	if err := app.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = app.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived the application")
	}

	out := logs.String()
	if !strings.Contains(out, "closed_by=app") || strings.Contains(out, "Tunnel setup") {
		t.Fatalf("an application gone before the reply was logged as:\n%s", out)
	}
	if got := minutes.failed.Load() - failedBefore; got != 0 {
		t.Fatalf("it was counted as %d failed setups", got)
	}
}

// The real server, over both transports, keeps the bytes that arrive behind
// CONNECT before it has answered (internal/socks5, Request.bufConn), and a
// refusal reaches the application as a reset after the early success.
func TestOptimisticConnectThroughTheServer(t *testing.T) {
	paths := streamPaths(t, 5*time.Second)
	echo := target(t, "")
	greeter := target(t, "220 ready\r\n")
	closed := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		return addr
	}()

	for _, mode := range []string{"obfs-optimistic", "wss-optimistic"} {
		t.Run(mode, func(t *testing.T) {
			t.Run("client speaks first", func(t *testing.T) {
				c, reply := socksConnect(t, paths[mode], echo, []byte("ping"))
				if !bytes.Equal(reply, successReply) {
					t.Fatalf("reply %v, want %v", reply, successReply)
				}
				got := make([]byte, len("ping"))
				if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
					t.Fatalf("echo %q, err %v", got, err)
				}
			})
			t.Run("server speaks first", func(t *testing.T) {
				c, reply := socksConnect(t, paths[mode], greeter, nil)
				if !bytes.Equal(reply, successReply) {
					t.Fatalf("reply %v, want %v", reply, successReply)
				}
				got := make([]byte, len("220 ready\r\n"))
				if _, err := io.ReadFull(c, got); err != nil || string(got) != "220 ready\r\n" {
					t.Fatalf("banner %q, err %v", got, err)
				}
			})
			t.Run("refused target", func(t *testing.T) {
				c, reply := socksConnect(t, paths[mode], closed, []byte("ping"))
				if !bytes.Equal(reply, successReply) {
					t.Fatalf("reply %v, want the early success", reply)
				}
				_, err := c.Read(make([]byte, 16))
				if err == nil || errors.Is(err, io.EOF) {
					t.Fatalf("the application saw %v; a refusal must not look like a clean end", err)
				}
			})
		})
	}
}
