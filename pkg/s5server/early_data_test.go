package s5server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// earlyStand runs a server with both an obfuscated and a WSS listener.
func earlyStand(t *testing.T, earlyData string) (obfsPort, wsURL, echo string) {
	t.Helper()
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	echo = startEchoServer(t)
	cfg := Config{
		ListenIP:       "127.0.0.1",
		Port:           reservePort(t),
		ObfsEnabled:    true,
		ObfsPort:       reservePort(t),
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 64,
		ObfsMTU:        1400,
		WSEnabled:      true,
		WSAddr:         "127.0.0.1:0",
		WSCertFile:     certFile,
		WSKeyFile:      keyFile,
		WSPath:         "/ws",
		WSEarlyData:    earlyData,
	}
	srv := startServer(t, cfg)
	deadline := time.Now().Add(3 * time.Second)
	for srv.WSAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.WSAddr() == "" {
		t.Fatal("the WS listener did not start")
	}
	return cfg.ObfsPort, "wss://" + srv.WSAddr() + "/ws", echo
}

// adviceThrough runs CONNECT through transport and returns the advice the
// server sent with its reply.
func adviceThrough(t *testing.T, transport net.Conn, echo string) obfs.Advice {
	t.Helper()
	t.Cleanup(func() { _ = transport.Close() })
	got := make(chan obfs.Advice, 1)
	tunnel, err := obfs.NewClientConn(transport, obfs.Config{
		PSK: []byte(testPSK), MaxPadding: 64, MTU: 1400,
		OnAdvice: func(a obfs.Advice) { got <- a },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("connect: %v", err)
	}
	msg := []byte("through the tunnel")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(tunnel, back); err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("echo: %q, %v", back, err)
	}
	select {
	case a := <-got:
		return a
	default:
		t.Fatal("no advice arrived with the SOCKS5 reply")
		return obfs.Advice{}
	}
}

func dialWSS(t *testing.T, url string) net.Conn {
	t.Helper()
	c, err := ws.DialContext(context.Background(), ws.DialOpts{URL: url, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	return ws.NewShapedConn(c, ws.DefaultMinFrame, ws.DefaultMaxFrame, 0)
}

func TestOnlyTheWSListenerAnnouncesEarlyData(t *testing.T) {
	obfsPort, wsURL, echo := earlyStand(t, "")

	if a := adviceThrough(t, dialWSS(t, wsURL), echo); a.Capabilities != obfs.CapWSEarlyData {
		t.Fatalf("the WS listener sent capabilities %#x, want early data", a.Capabilities)
	}
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if a := adviceThrough(t, raw, echo); a.Capabilities != 0 {
		t.Fatalf("the obfuscated listener sent capabilities %#x, want none", a.Capabilities)
	}

	_, offURL, offEcho := earlyStand(t, WSEarlyDataOff)
	if a := adviceThrough(t, dialWSS(t, offURL), offEcho); a.Capabilities != 0 {
		t.Fatalf("with WS_EARLY_DATA=off the WS listener sent capabilities %#x", a.Capabilities)
	}
}

// earlyWS is a WebSocket client that holds what is written before its first
// read and sends it with the upgrade request in one TLS record. The server
// then has the frames in its buffer when it takes the connection over:
// the early path, whatever the scheduling.
type earlyWS struct {
	*tls.Conn
	host     string
	held     []byte
	br       *bufio.Reader
	upgraded bool
	rest     []byte
}

func dialEarlyWS(t *testing.T, url string) *earlyWS {
	t.Helper()
	host := strings.TrimSuffix(strings.TrimPrefix(url, "wss://"), "/ws")
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, DynamicRecordSizingDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return &earlyWS{Conn: c, host: host, br: bufio.NewReader(c)}
}

func maskedFrame(p []byte) []byte {
	frame := []byte{0x82}
	if len(p) <= 125 {
		frame = append(frame, 0x80|byte(len(p)))
	} else {
		frame = binary.BigEndian.AppendUint16(append(frame, 0x80|126), uint16(len(p)))
	}
	key := [4]byte{0x1b, 0x2c, 0x3d, 0x4e}
	frame = append(frame, key[:]...)
	for i, b := range p {
		frame = append(frame, b^key[i&3])
	}
	return frame
}

func (e *earlyWS) Write(p []byte) (int, error) {
	if !e.upgraded {
		e.held = append(e.held, maskedFrame(p)...)
		return len(p), nil
	}
	if _, err := e.Conn.Write(maskedFrame(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (e *earlyWS) Read(p []byte) (int, error) {
	if !e.upgraded {
		req := "GET /ws HTTP/1.1\r\nHost: " + e.host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
		if _, err := e.Conn.Write(append([]byte(req), e.held...)); err != nil {
			return 0, err
		}
		resp, err := http.ReadResponse(e.br, nil)
		if err != nil {
			return 0, fmt.Errorf("upgrade: %w", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			return 0, fmt.Errorf("upgrade answered %d", resp.StatusCode)
		}
		e.upgraded = true
	}
	for len(e.rest) == 0 {
		var h [2]byte
		if _, err := io.ReadFull(e.br, h[:]); err != nil {
			return 0, err
		}
		n := int(h[1] & 0x7f)
		if n == 126 {
			var b [2]byte
			if _, err := io.ReadFull(e.br, b[:]); err != nil {
				return 0, err
			}
			n = int(binary.BigEndian.Uint16(b[:]))
		}
		e.rest = make([]byte, n)
		if _, err := io.ReadFull(e.br, e.rest); err != nil {
			return 0, err
		}
	}
	n := copy(p, e.rest)
	e.rest = e.rest[n:]
	return n, nil
}

func TestTheWSListenerTakesATunnelSentBeforeItsAnswer(t *testing.T) {
	_, wsURL, echo := earlyStand(t, WSEarlyDataAuto)
	// The opening, the hello and the greeting all leave with the request.
	if a := adviceThrough(t, dialEarlyWS(t, wsURL), echo); a.Capabilities != obfs.CapWSEarlyData {
		t.Fatalf("capabilities %#x over an early tunnel", a.Capabilities)
	}
}

func TestWithEarlyDataOffTheWSListenerRefusesATunnelSentBeforeItsAnswer(t *testing.T) {
	_, wsURL, _ := earlyStand(t, WSEarlyDataOff)
	c := dialEarlyWS(t, wsURL)
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("an opening"))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("WS_EARLY_DATA=off and the early frames were taken")
	}
}

func TestWSEarlyDataTakesOnlyItsTwoValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WSEnabled = true
	cfg.WSCertFile, cfg.WSKeyFile = "cert", "key"
	cfg.ObfsPSK = testPSK
	for _, v := range []string{"", WSEarlyDataAuto, WSEarlyDataOff} {
		cfg.WSEarlyData = v
		if err := ValidateConfig(cfg); err != nil && strings.Contains(err.Error(), "WS_EARLY_DATA") {
			t.Errorf("%q was refused: %v", v, err)
		}
	}
	cfg.WSEarlyData = "on"
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "WS_EARLY_DATA") {
		t.Errorf("\"on\" was accepted: %v", err)
	}
}
