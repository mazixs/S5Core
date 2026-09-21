package s5server

import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/userstore"
)

// A quota that counts TCP and not UDP is not a quota. This is the whole path -
// a real account file, a real store, no telemetry configured - because the
// defect the SDK had was exactly that the billing ran through the metrics: a
// deployment without a Prometheus exporter transferred UDP for free, and its
// users.json went on reporting the quota untouched.
//
// Finding F03 of docs/reports/code-quality-audit-2026-09-20.md.

// udpQuotaStand is a running server with one account on a small quota, and a
// UDP service to send to.
type udpQuotaStand struct {
	srv   *Server
	addr  string
	echo  *net.UDPConn
	limit int64
}

func newUDPQuotaStand(t *testing.T, limit int64) *udpQuotaStand {
	t.Helper()

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	// A sink, not an echo: it answers nothing. The association then spends
	// its quota on what the client sent and on nothing else, so this test
	// fails if the direction from the client is the one that is not counted.
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := echo.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	path := filepath.Join(t.TempDir(), "users.json")
	writeUsers(t, path, []userstore.UserAccount{
		{
			ID: "1", Username: "bob", Password: "secret", Enabled: true,
			TrafficLimitBytes: limit,
		},
	})

	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.Port = reservePort(t)
	cfg.RequireAuth = true
	cfg.UsersFile = path
	// No Telemetry: the accounting must not depend on it.
	srv := startServer(t, cfg)

	return &udpQuotaStand{
		srv:   srv,
		addr:  net.JoinHostPort(cfg.ListenIP, cfg.Port),
		echo:  echo,
		limit: limit,
	}
}

// tunnel opens a 0x83 association as bob and returns the connection carrying
// it. Both UDP modes share the accounting; the tunnelled one is used here
// because it needs no second socket to observe.
func (s *udpQuotaStand) tunnel(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	auth := []byte{0x01, 3}
	auth = append(auth, "bob"...)
	auth = append(auth, 6)
	auth = append(auth, "secret"...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("auth: %v", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if authReply[1] != 0 {
		t.Fatalf("authentication refused: 0x%02x", authReply[1])
	}

	if _, err := conn.Write([]byte{0x05, socks5.UDPTunnelCommand, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("associate refused: 0x%02x", reply[1])
	}
	return conn
}

func (s *udpQuotaStand) frame(payload []byte) []byte {
	port := s.echo.LocalAddr().(*net.UDPAddr).Port
	body := socks5.BuildUDPHeader(
		&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: port}, payload)
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame
}

// UDP traffic reaches the account's own counter, so the quota that bounds a
// TCP session bounds a UDP association too - and it does so on a server with
// no telemetry at all.
func TestUDPTrafficSpendsTheAccountsQuotaWithoutTelemetry(t *testing.T) {
	const limit = 32 * 1024
	stand := newUDPQuotaStand(t, limit)
	conn := stand.tunnel(t)

	if got := stand.srv.userStore.SessionStatus("bob"); got != userstore.SessionAllowed {
		t.Fatalf("the account started at %v, want allowed", got)
	}

	// Enough datagrams to cross the quota several times over, sent in one go
	// so the test does not depend on how fast the echo answers.
	payload := make([]byte, 1200)
	frame := stand.frame(payload)
	sent := 0
	for sent < 100*1024 {
		if _, err := conn.Write(frame); err != nil {
			break // the server ended the association, which is the point
		}
		sent += len(payload)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if stand.srv.userStore.SessionStatus("bob") == userstore.SessionQuotaExceeded {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := stand.srv.userStore.SessionStatus("bob"); got != userstore.SessionQuotaExceeded {
		t.Fatalf("after %d bytes of UDP the account is %v, want its quota spent; "+
			"UDP traffic is not reaching the account", sent, got)
	}

	// And the association it was spent by is gone: the connection carrying it
	// is closed by the server.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if isTimeoutErr(err) {
				t.Fatal("the association is still open after the quota ran out")
			}
			return // closed, as it must be
		}
		if _, err := io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(lenBuf))); err != nil {
			if isTimeoutErr(err) {
				t.Fatal("the association is still open after the quota ran out")
			}
			return
		}
	}
}

func isTimeoutErr(err error) bool {
	type timeout interface{ Timeout() bool }
	t, ok := err.(timeout)
	return ok && t.Timeout()
}
