package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// A CONNECT to a closed port on this host is answered with 0x05, connection
// refused, by the first attempt: the kernel resets it, and the answer does not
// wait for the backups.
func TestAConnectToAClosedPortIsRefused(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()

	server, err := New(&Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() { _ = server.ServeContext(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	req := []byte{0x05, ConnectCommand, 0x00, ipv4Address, 127, 0, 0, 1}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	start := time.Now()
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != 0x05 {
		t.Fatalf("REP 0x%02x, want 0x05", reply[1])
	}
	// A refusal that waited for two backups would come at backupAfter[1].
	if took := time.Since(start); took >= backupAfter[1] {
		t.Fatalf("refused after %v, want before the second backup at %v", took, backupAfter[1])
	}
}
