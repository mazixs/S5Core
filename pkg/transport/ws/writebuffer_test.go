package ws

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingConn keeps what gorilla hands the socket: the size of every server
// Write and every byte the client sent. It has no writev, so a message gorilla
// assembles from two buffers arrives as two Writes, exactly as it does on a
// tls.Conn, where each Write is its own TLS record.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
	read   bytes.Buffer
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(b))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.read.Write(b[:n])
	c.mu.Unlock()
	return n, err
}

type recordingListener struct {
	net.Listener
	conns chan *recordingConn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c}
	l.conns <- rc
	return rc, nil
}

func recordedPair(t *testing.T, maxFrame int) (client, server *Conn, wire *recordingConn) {
	t.Helper()
	up := NewUpgrader(UpgraderOpts{Path: "/ws", WriteBufferSize: maxFrame})
	accepted := make(chan *Conn, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		accepted <- c
	}))
	rl := &recordingListener{Listener: srv.Listener, conns: make(chan *recordingConn, 1)}
	srv.Listener = rl
	srv.Start()
	t.Cleanup(srv.Close)

	client, err := Dial(DialOpts{URL: strings.Replace(srv.URL, "http", "ws", 1) + "/ws", WriteBufferSize: maxFrame})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server = <-accepted
	t.Cleanup(func() { _ = server.Close() })
	return client, server, <-rl.conns
}

// wsFrames parses the client's side of the stream after the upgrade request
// and reports, per frame, whether it closed its message.
func wsFrames(t *testing.T, stream []byte) (final []bool) {
	t.Helper()
	end := bytes.Index(stream, []byte("\r\n\r\n"))
	if end < 0 {
		t.Fatal("no upgrade request in the recorded stream")
	}
	b := stream[end+4:]
	for len(b) >= 2 {
		fin, masked, n := b[0]&0x80 != 0, b[1]&0x80 != 0, int(b[1]&0x7f)
		h := 2
		switch n {
		case 126:
			n, h = int(binary.BigEndian.Uint16(b[2:4])), 4
		case 127:
			n, h = int(binary.BigEndian.Uint64(b[2:10])), 10
		}
		if masked {
			h += 4
		}
		if len(b) < h+n {
			t.Fatalf("truncated frame: header %d, payload %d, %d bytes left", h, n, len(b))
		}
		final = append(final, fin)
		b = b[h+n:]
	}
	return final
}

// A shaped message is one write on both ends even when WS_MAX_FRAME is above
// gorilla's default buffer. Before, a 6000-byte message left the server as a
// 4096-byte write plus the rest and the client as two WebSocket fragments:
// every large frame opened with the same TLS record length, the very mode the
// shaper's upper bound exists not to create (R09).
func TestALargeShapedFrameLeavesAsOneWrite(t *testing.T) {
	const maxFrame = 8192
	client, server, wire := recordedPair(t, maxFrame)
	sizes := []int{4097, 5000, 6000, 7777, maxFrame}

	wire.mu.Lock()
	wire.writes = nil
	wire.mu.Unlock()
	go func() {
		for _, n := range sizes {
			_, _ = server.Write(make([]byte, n))
		}
	}()
	got := make([]byte, maxFrame)
	for _, n := range sizes {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(client, got[:n]); err != nil {
			t.Fatal(err)
		}
	}
	wire.mu.Lock()
	writes := append([]int(nil), wire.writes...)
	wire.mu.Unlock()
	if len(writes) != len(sizes) {
		t.Errorf("server: %d messages took %d socket writes %v; each should be one", len(sizes), len(writes), writes)
	}

	for _, n := range sizes {
		if _, err := client.Write(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range sizes {
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(server, got[:n]); err != nil {
			t.Fatal(err)
		}
	}
	wire.mu.Lock()
	final := wsFrames(t, wire.read.Bytes())
	wire.mu.Unlock()
	if len(final) != len(sizes) {
		t.Errorf("client: %d messages left as %d WebSocket frames; each should be one", len(sizes), len(final))
	}
	for i, f := range final {
		if !f {
			t.Errorf("client frame %d is a fragment, not a whole message", i)
		}
	}
}

// The default band keeps the buffer it had: sizing follows WS_MAX_FRAME only
// upwards, so a narrower band does not shrink it.
func TestTheWriteBufferNeverShrinksBelowTheDefault(t *testing.T) {
	for _, maxFrame := range []int{0, 1024, DefaultMaxFrame} {
		if got := writeBufferSize(maxFrame); got != DefaultMaxFrame {
			t.Errorf("writeBufferSize(%d) = %d, want %d", maxFrame, got, DefaultMaxFrame)
		}
	}
	if got := writeBufferSize(9000); got != 9000 {
		t.Errorf("writeBufferSize(9000) = %d", got)
	}
}
