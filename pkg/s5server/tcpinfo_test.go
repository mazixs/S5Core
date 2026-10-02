package s5server

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// A connection the server closes is unreadable a moment later, and the journal
// writes why after the close, so the state of the socket has to be taken by
// the Close that ends it.
func TestTheStateOfTheSocketIsTakenWhenTheConnectionCloses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel gives the state of a socket on Linux only")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	conn := countAccepted(accepted, nil, nil, TransportPlain).(*metricsConn)
	if conn.tcp.Load() != nil {
		t.Fatal("the state was taken before the close")
	}
	_ = conn.Close()
	info := conn.tcp.Load()
	if info == nil {
		t.Fatal("the close did not keep the state of the socket")
	}
	if info.Retransmits != 0 {
		t.Errorf("a connection that never lost a segment has %d retransmits", info.Retransmits)
	}
}

// The state of the socket reaches the journal only if the hook that writes the
// line gets the outermost wrapper and runs after its Close. A wrapper added
// over metricsConn would drop the fields without failing the tests of either
// half, so this one goes through a real server.
func TestASilentConnectionCarriesTheStateOfItsSocketInTheJournal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel gives the state of a socket on Linux only")
	}
	echo := startEchoServer(t)
	path := filepath.Join(t.TempDir(), "sessions.jsonl")
	cfg := Config{
		ListenIP:       "127.0.0.1",
		Port:           reservePort(t),
		ReadTimeout:    300 * time.Millisecond,
		SessionLog:     SessionLogAll,
		SessionLogFile: path,
	}
	srv := startServer(t, cfg)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+cfg.Port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5ConnectNoAuth(conn, echo); err != nil {
		t.Fatal(err)
	}
	// The client says nothing more, and the server gives up on it.
	if _, err := io.Copy(io.Discard, conn); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read until the server closed: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); srv.connsEnded.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}

	var silent map[string]any
	for _, l := range eventsOf(readJournal(t, path), "conn_end") {
		if l["end"] == socks5.ClosedByServerTimeout {
			silent = l
		}
	}
	if silent == nil {
		t.Fatalf("no conn_end ended by %s", socks5.ClosedByServerTimeout)
	}
	for _, f := range []string{"tcp_rtt_ms", "tcp_unacked", "tcp_retransmits", "tcp_since_data_ms", "tcp_since_ack_ms"} {
		if _, ok := silent[f]; !ok {
			t.Errorf("the line of a silent connection lacks %s: %v", f, silent)
		}
	}
}
