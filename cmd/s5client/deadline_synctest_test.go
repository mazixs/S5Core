package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф3-1. The field report said: "no answer, ever, and not one WARN in
// the log". The cause was structural - the client had no deadline anywhere, so
// a server that accepted the TCP connection and then stayed silent left the
// application blocked forever with nothing written down. These tests pin both
// halves of the fix: the application gets a SOCKS5 error at a known moment,
// and the log says which phase went quiet.
//
// They run inside a testing/synctest bubble, so the 15-second handshake
// timeout costs no wall clock and the assertion can be exact. net.Pipe is the
// transport for the same reason it is in pkg/s5server/timeouts_synctest_test.go.

const testPSK32 = "0123456789abcdef0123456789abcdef"

// silentServer makes dialServer hand back one end of a pipe whose other end
// never sends anything - a server that accepts and then says nothing.
func silentServer(t *testing.T) {
	t.Helper()
	original := dialServer
	t.Cleanup(func() { dialServer = original })

	dialServer = func(cfg clientParams) (net.Conn, error) {
		local, remote := net.Pipe()
		t.Cleanup(func() {
			_ = local.Close()
			_ = remote.Close()
		})
		// Drain whatever the client sends, and answer nothing. Without a
		// reader the client would block on its own Write instead, which is a
		// different failure than the one under test.
		go func() {
			_, _ = io.Copy(io.Discard, remote)
		}()
		return local, nil
	}
}

// captureLogs redirects slog to a buffer for the duration of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// connectRequest is what a browser sends for example.com:443.
func connectRequest() []byte {
	req := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	req = append(req, []byte("example.com")...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 443)
	return append(req, port[:]...)
}

func testClientParams() clientParams {
	return clientParams{
		ServerAddr:       "198.51.100.1:1443",
		PSK:              testPSK32,
		MaxPadding:       32,
		MTU:              1400,
		DialTimeout:      10 * time.Second,
		HandshakeTimeout: 15 * time.Second,
	}
}

func TestSilentServerFailsTheApplicationAtTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		silentServer(t)
		logs := captureLogs(t)
		cfg := testClientParams()

		app, client := net.Pipe()
		defer func() { _ = app.Close() }()

		done := make(chan struct{})
		go func() {
			defer close(done)
			handleClient(client, cfg, nil)
		}()

		// net.Pipe is unbuffered and the client answers the greeting before it
		// has read the CONNECT, so the write has to run alongside the read.
		writeErr := make(chan error, 1)
		go func() {
			_, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...))
			writeErr <- err
		}()
		var greetResp [2]byte
		if _, err := io.ReadFull(app, greetResp[:]); err != nil {
			t.Fatalf("greeting response: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("application write: %v", err)
		}

		start := time.Now()
		reply := make([]byte, 10)
		if _, err := io.ReadFull(app, reply); err != nil {
			t.Fatalf("the application never got a reply: %v", err)
		}
		waited := time.Since(start)
		<-done

		if waited != cfg.HandshakeTimeout {
			t.Fatalf("the application waited %v, want exactly %v", waited, cfg.HandshakeTimeout)
		}
		if reply[0] != 0x05 || reply[1] != socks5TTLExpired {
			t.Fatalf("reply was %v, want SOCKS5 TTL expired (0x06)", reply[:2])
		}

		out := logs.String()
		if !strings.Contains(out, "level=WARN") {
			t.Fatalf("no WARN was logged:\n%s", out)
		}
		if !strings.Contains(out, "phase="+string(phaseGreeting)) {
			t.Fatalf("the log does not name the phase that went silent:\n%s", out)
		}
		if !strings.Contains(out, "dest=example.com") {
			t.Fatalf("the log does not name the destination:\n%s", out)
		}
	})
}

// The deadline covers setup only. A tunnel that is established and then quiet
// for a long time is a normal tunnel, and killing it would be a worse bug than
// the one being fixed.
func TestEstablishedTunnelDoesNotInheritTheSetupDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testClientParams()

		original := dialServer
		t.Cleanup(func() { dialServer = original })

		serverSide := make(chan net.Conn, 1)
		dialServer = func(clientParams) (net.Conn, error) {
			local, remote := net.Pipe()
			t.Cleanup(func() {
				_ = local.Close()
				_ = remote.Close()
			})
			serverSide <- remote
			return local, nil
		}

		app, client := net.Pipe()
		defer func() { _ = app.Close() }()

		done := make(chan struct{})
		go func() {
			defer close(done)
			handleClient(client, cfg, nil)
		}()

		// net.Pipe is unbuffered and the client answers the greeting before it
		// has read the CONNECT, so the write has to run alongside the read.
		writeErr := make(chan error, 1)
		go func() {
			_, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...))
			writeErr <- err
		}()
		var greetResp [2]byte
		if _, err := io.ReadFull(app, greetResp[:]); err != nil {
			t.Fatalf("greeting response: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("application write: %v", err)
		}

		server := obfsServerSide(t, <-serverSide, cfg)

		// The client pipelines greeting and CONNECT; answer both.
		if _, err := io.ReadFull(server, make([]byte, 3+len(connectRequest()))); err != nil {
			t.Fatalf("server read of greeting and CONNECT: %v", err)
		}
		if _, err := server.Write([]byte{0x05, 0x00}); err != nil {
			t.Fatalf("server greeting reply: %v", err)
		}
		if _, err := server.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatalf("server CONNECT reply: %v", err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(app, reply); err != nil {
			t.Fatalf("application reply: %v", err)
		}
		if reply[1] != 0x00 {
			t.Fatalf("CONNECT was refused: 0x%02x", reply[1])
		}

		// Far longer than the handshake timeout, with no traffic at all.
		time.Sleep(10 * cfg.HandshakeTimeout)
		synctest.Wait()

		if _, err := server.Write([]byte("late but welcome")); err != nil {
			t.Fatalf("server write after a long idle period: %v", err)
		}
		got := make([]byte, len("late but welcome"))
		if _, err := io.ReadFull(app, got); err != nil {
			t.Fatalf("the idle tunnel was dropped: %v", err)
		}
		if string(got) != "late but welcome" {
			t.Fatalf("relayed %q", got)
		}

		// Close both ends so the two relay goroutines finish: inside a bubble a
		// relay that waits forever is reported as a deadlock, which is exactly
		// what it would be here.
		_ = server.Close()
		_ = app.Close()
		<-done
	})
}

// obfsServerSide wraps the server end of the pipe the way the real server does.
func obfsServerSide(t *testing.T, raw net.Conn, cfg clientParams) net.Conn {
	t.Helper()
	conn, err := newObfsConnForTest(raw, cfg)
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	return conn
}

func newObfsConnForTest(raw net.Conn, cfg clientParams) (net.Conn, error) {
	return obfs.NewServerConn(raw, obfs.Config{
		PSK:        []byte(cfg.PSK),
		MaxPadding: cfg.MaxPadding,
		MTU:        cfg.MTU,
		Scheme:     &veil.Clocked{Accepts: everyCipher()},
	})
}
