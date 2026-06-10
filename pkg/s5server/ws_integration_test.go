package s5server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

func TestWSStealth_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Start an echo target server
	echoAddr := startEchoServer(t)

	// Start s5server with WS stealth transport (OS-assigned port)
	cfg := Config{
		Port:             "0",
		RequireAuth:      false,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		ObfsEnabled:      true,
		ObfsPSK:          testPSK,
		ObfsMaxPadding:   32,
		ObfsMTU:          1400,
		WSEnabled:        true,
		WSAddr:           "127.0.0.1:0",
		WSCertFile:       certFile,
		WSKeyFile:        keyFile,
		WSPath:           "/ws",
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer srv.Stop()

	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("server error: %v", err)
		}
	}()

	// Wait for WS listener to be ready
	var wsAddr string
	for i := 0; i < 300; i++ {
		wsAddr = srv.WSAddr()
		if wsAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wsAddr == "" {
		t.Fatalf("WS listener not ready after 3s (wsListen=%v)", srv.wsListen)
	}

	wsURL := "wss://" + wsAddr + "/ws"

	// 1. Verify decoy endpoint
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := httpClient.Get("https://" + wsAddr + "/")
	if err != nil {
		t.Fatalf("decoy get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decoy status: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Verify unknown path -> 404
	resp2, err := httpClient.Get("https://" + wsAddr + "/admin")
	if err != nil {
		t.Fatalf("unknown path get: %v", err)
	}
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status: %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// 3. Connect via WS + obfs + SOCKS5
	wsConn, err := ws.Dial(ws.DialOpts{
		URL:       wsURL,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer wsConn.Close()

	obfsConn, err := obfs.NewConn(wsConn, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 32,
		MTU:        1400,
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	defer obfsConn.Close()

	// SOCKS5 handshake (no auth)
	if _, err := obfsConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(obfsConn, greetResp[:]); err != nil {
		t.Fatalf("greeting read: %v", err)
	}
	if greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		t.Fatalf("bad greeting response: %v", greetResp)
	}

	// CONNECT to echo server
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := net.LookupPort("tcp", portStr)
	ip := net.ParseIP(host)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := obfsConn.Write(req); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	respBuf := make([]byte, 10)
	if _, err := io.ReadFull(obfsConn, respBuf); err != nil {
		t.Fatalf("connect read: %v", err)
	}
	if respBuf[1] != 0x00 {
		t.Fatalf("connect failed: %d", respBuf[1])
	}

	// Echo test
	msg := []byte("hello through ws stealth")
	if _, err := obfsConn.Write(msg); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(obfsConn, back); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(back) != string(msg) {
		t.Fatalf("echo mismatch: %s", string(back))
	}
}
