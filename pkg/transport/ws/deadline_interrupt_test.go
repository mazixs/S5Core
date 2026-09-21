package ws

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
)

type signalledWriteConn struct {
	net.Conn
	writes chan struct{}
}

func (c *signalledWriteConn) Write(p []byte) (int, error) {
	select {
	case c.writes <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

// An unbuffered peer makes any frame write block, including a close frame.
func blockedPeer(t *testing.T) (*Conn, <-chan struct{}) {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	raw := &signalledWriteConn{Conn: near, writes: make(chan struct{}, 1)}
	handshake := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(far))
		if err != nil {
			handshake <- err
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, err = fmt.Fprintf(far, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		handshake <- err
	}()
	dialer := websocket.Dialer{NetDialContext: func(context.Context, string, string) (net.Conn, error) { return raw, nil }}
	w, resp, err := dialer.DialContext(context.Background(), "ws://local/ws", nil)
	if resp != nil {
		resp.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	<-raw.writes // handshake
	c := Wrap(w)
	t.Cleanup(func() { c.Close() })
	return c, raw.writes
}

func TestWriteDeadlineInterruptsPendingWebSocketWrite(t *testing.T) {
	c, started := blockedPeer(t)
	written := make(chan error, 1)
	go func() { _, err := c.Write([]byte("payload")); written <- err }()
	<-started
	deadline := make(chan error, 1)
	go func() { deadline <- c.SetWriteDeadline(time.Now()) }()
	select {
	case err := <-deadline:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("setting deadline waited for writer")
	}
	select {
	case err := <-written:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt write")
	}
}

func TestWebSocketCloseDoesNotWriteToSilentPeer(t *testing.T) {
	c, _ := blockedPeer(t)
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for peer to read")
	}
}

func TestWriteDeadlineCanBeClearedAndExtended(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, started := blockedPeer(t)
		written := make(chan error, 1)
		c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		go func() { _, err := c.Write([]byte("payload")); written <- err }()
		<-started
		c.SetWriteDeadline(time.Now().Add(time.Hour))
		time.Sleep(75 * time.Millisecond)
		c.SetWriteDeadline(time.Time{})
		select {
		case err := <-written:
			t.Fatalf("old deadline fired: %v", err)
		default:
		}
		select {
		case err := <-written:
			t.Fatalf("cleared deadline fired: %v", err)
		default:
		}
		c.SetWriteDeadline(time.Now())
		select {
		case err := <-written:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("write remained blocked")
		}
	})
}

func TestExpiredIdleWriteDeadlineCanBeCleared(t *testing.T) {
	client, server := wsPair(t)
	client.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := client.Write([]byte("blocked")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("past deadline: %v", err)
	}
	client.SetWriteDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		_, err := io.ReadFull(server, buf)
		if err == nil && string(buf) != "ok" {
			err = fmt.Errorf("payload: %q", buf)
		}
		done <- err
	}()
	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleared idle deadline poisoned connection")
	}
}
