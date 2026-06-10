package tlsdecoy

import (
	"crypto/tls"
	"net/http"
	"strings"
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
