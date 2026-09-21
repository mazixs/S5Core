package tlsdecoy

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mazixs/S5Core/internal/testcert"
)

// upgradeAndReadHeaders performs a WebSocket upgrade and returns the server's
// response headers.
func upgradeAndReadHeaders(t *testing.T, addr string, offer []string) http.Header {
	t.Helper()
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
		Subprotocols:     offer,
		HandshakeTimeout: 5 * time.Second,
	}
	conn, resp, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("upgrade: %v (status %d)", err, status)
	}
	defer func() { _ = conn.Close() }()
	return resp.Header
}

// Plan task Ф6-5: an unset WS_SUBPROTOCOL used to become a list holding one
// empty string, which is not "no requirement" - it asks the client to offer an
// empty Sec-WebSocket-Protocol and puts an empty one in the reply. Neither is
// what an ordinary WebSocket server does, and a header no other server sends
// is exactly the kind of trace this transport exists to avoid.
func TestNoSubprotocolMeansNoSubprotocolHeader(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	l, err := NewListener(Config{
		Addr:     "127.0.0.1:0",
		CertFile: certFile,
		KeyFile:  keyFile,
		WSPath:   "/ws",
		// Subprotocols deliberately unset, which is what an empty
		// WS_SUBPROTOCOL has to produce.
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Accept whatever arrives, so the upgrade completes.
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()

	headers := upgradeAndReadHeaders(t, l.Addr().String(), nil)
	if got, ok := headers["Sec-Websocket-Protocol"]; ok {
		t.Fatalf("the server answered with Sec-WebSocket-Protocol: %q", got)
	}
}

// With a subprotocol configured the server names it back, which is what a
// client that offered it expects.
func TestAConfiguredSubprotocolIsEchoed(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	l, err := NewListener(Config{
		Addr:         "127.0.0.1:0",
		CertFile:     certFile,
		KeyFile:      keyFile,
		WSPath:       "/ws",
		Subprotocols: []string{"chat"},
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()

	headers := upgradeAndReadHeaders(t, l.Addr().String(), []string{"chat"})
	if got := headers.Get("Sec-Websocket-Protocol"); got != "chat" {
		t.Fatalf("the server answered with subprotocol %q, want chat", got)
	}
}
