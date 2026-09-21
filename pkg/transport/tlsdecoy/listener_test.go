package tlsdecoy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

func TestListener_DecoyAndWS(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	l, err := NewListener(Config{
		Addr:      "127.0.0.1:0",
		CertFile:  certFile,
		KeyFile:   keyFile,
		WSPath:    "/ws",
		DecoyHTML: "<html><body>decoy</body></html>",
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer l.Close()

	addr := l.Addr().String()

	// Test decoy endpoint (skip TLS verification for self-signed cert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("decoy get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decoy status: %d", resp.StatusCode)
	}
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	if !strings.Contains(string(body[:n]), "decoy") {
		t.Fatalf("decoy body mismatch: %s", string(body[:n]))
	}

	// Test unknown path -> 404
	resp2, err := client.Get("https://" + addr + "/admin")
	if err != nil {
		t.Fatalf("unknown path get: %v", err)
	}
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status: %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Test WS connection
	wsURL := "wss://" + addr + "/ws"
	wsConn, err := ws.Dial(ws.DialOpts{
		URL:       wsURL,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer wsConn.Close()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	// Echo test
	msg := []byte("hello from ws over tls")
	if _, err := wsConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 512)
	rn, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:rn]) != string(msg) {
		t.Fatalf("echo mismatch: %s", string(buf[:rn]))
	}
}

// Close used to close the handover channel while an upgrade handler could be
// sending on it: "send on closed channel", a panic that takes the process
// down, on the path every shutdown runs. Upgrades and closes are driven at
// each other here so the race detector has something to look at.
func TestClosingWhileUpgradesAreInFlightDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	for round := 0; round < 20; round++ {
		l, err := NewListener(Config{
			Addr:     "127.0.0.1:0",
			CertFile: certFile,
			KeyFile:  keyFile,
			WSPath:   "/ws",
		})
		if err != nil {
			t.Fatalf("new listener: %v", err)
		}
		url := "wss://" + l.Addr().String() + "/ws"

		// Nobody accepts: the handover channel fills up and the handlers end
		// up blocked in exactly the window Close used to break.
		var dialers sync.WaitGroup
		for i := 0; i < 8; i++ {
			dialers.Add(1)
			go func() {
				defer dialers.Done()
				conn, err := ws.Dial(ws.DialOpts{
					URL:       url,
					TLSConfig: &tls.Config{InsecureSkipVerify: true},
				})
				if err == nil {
					_ = conn.Close()
				}
			}()
		}

		// Close lands in the middle of them rather than after.
		time.Sleep(time.Millisecond)
		if err := l.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// Closing twice is what Start and Stop between them actually do.
		if err := l.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
		dialers.Wait()

		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close returned %v, want net.ErrClosed", err)
		}
	}
}

// A path that net/http cannot register used to be a panic during startup,
// reported as a mux problem rather than as the configuration mistake it is.
func TestABadWebSocketPathIsAConfigurationError(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tests := []struct {
		name string
		path string
		says string
	}{
		{"empty", "", "empty"},
		{"no leading slash", "ws", "must start with /"},
		{"root", "/", "decoy"},
		{"favicon", "/favicon.ico", "decoy"},
		{"subtree", "/ws/", "subtree"},
		{"whitespace", "/we b", "whitespace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("path %q panicked instead of returning an error: %v", tt.path, r)
				}
			}()

			l, err := NewListener(Config{
				Addr:     "127.0.0.1:0",
				CertFile: certFile,
				KeyFile:  keyFile,
				WSPath:   tt.path,
			})
			if err == nil {
				_ = l.Close()
				t.Fatalf("path %q was accepted", tt.path)
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("error %q does not explain the problem (looking for %q)", err, tt.says)
			}
		})
	}
}

// The decoy is the part of this transport that faces the open internet, so a
// client that opens a socket and says nothing must not hold it forever.
func TestTheDecoyHasRequestTimeouts(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	l, err := NewListener(Config{
		Addr:     "127.0.0.1:0",
		CertFile: certFile,
		KeyFile:  keyFile,
		WSPath:   "/ws",
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if l.server.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset: a slow header stream holds the connection forever")
	}
	if l.server.ReadTimeout == 0 || l.server.WriteTimeout == 0 {
		t.Error("ReadTimeout/WriteTimeout are unset")
	}
	if l.server.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset: kept-alive connections are never reclaimed")
	}
}
