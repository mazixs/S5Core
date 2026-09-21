package tlsdecoy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

type upgradeWriteSignal struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *upgradeWriteSignal) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type upgradeResponse struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *upgradeResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

// Hijacking removes the socket from net/http's close set before the upgrade
// response is written. net.Pipe deterministically stops that response write.
func TestCloseInterruptsHijackedUpgradeResponse(t *testing.T) {
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(Config{Addr: "127.0.0.1:0", CertFile: cert, KeyFile: key, WSPath: "/ws"})
	if err != nil {
		t.Fatal(err)
	}
	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close(); _ = far.Close(); _ = l.Close() })
	raw := &upgradeWriteSignal{Conn: near, started: make(chan struct{})}
	ctx := context.Background()
	if l.server.BaseContext != nil {
		ctx = l.server.BaseContext(l.tlsListener)
	}
	if l.server.ConnContext != nil {
		ctx = l.server.ConnContext(ctx, raw)
	}
	req := httptest.NewRequest(http.MethodGet, "http://local/ws", nil).WithContext(ctx)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.server.Handler.ServeHTTP(&upgradeResponse{ResponseRecorder: httptest.NewRecorder(), conn: raw}, req)
	}()
	<-raw.started
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for the hijacked upgrade response")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("upgrade handler survived Close")
	}
}

// Actual TCP/TLS and body delivery, with an upstream that stops sending after
// a verified prefix. The watchdog detects a hang; it is not a latency target.
func TestCloseCancelsStreamingDecoy(t *testing.T) {
	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	cleanupUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(payload); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(cleanupUpstream)
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(Config{Addr: "127.0.0.1:0", CertFile: cert, KeyFile: key, WSPath: "/ws", DecoyUpstream: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupUpstream(); _ = l.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + l.Addr().String() + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("decoy changed the payload")
	}
	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("verified %d bytes over TLS; Close returned in %s (local failure reproduction)", len(got), time.Since(start))
	case <-time.After(2 * time.Second):
		t.Fatal("Close waits for the streaming decoy instead of canceling it")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request was left running after Close")
	}
	if n, err := resp.Body.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("stream remained open after Close: n=%d err=%v", n, err)
	}
}

func TestCloseDrainsUnacceptedWebSockets(t *testing.T) {
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(Config{Addr: "127.0.0.1:0", CertFile: cert, KeyFile: key, WSPath: "/ws"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// One more than the queue can hold leaves an upgraded handler waiting
	// to hand over its connection when Close begins.
	peers := make([]*ws.Conn, 0, cap(l.conns)+1)
	for range cap(l.conns) + 1 {
		peer, err := ws.Dial(ws.DialOpts{URL: "wss://" + l.Addr().String() + "/ws", TLSConfig: &tls.Config{InsecureSkipVerify: true}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		peers = append(peers, peer)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for i, peer := range peers {
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatalf("unaccepted peer %d remained open", i)
		} else if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
			t.Fatalf("unaccepted peer %d timed out instead of closing: %v", i, err)
		}
	}
}
