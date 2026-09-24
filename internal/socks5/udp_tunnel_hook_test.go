package socks5

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
)

// Only a tunnel of datagrams is handed to OnUDPTunnel. The CONNECT relay and
// the RFC 1928 association carry what earlier retransmission is wrong for:
// a bulk transfer pays for it with duplicates and a collapsed window
// (internal/tcptune).
func TestOnlyATunnelOfDatagramsIsHandedToTheHook(t *testing.T) {
	var mu sync.Mutex
	var handed []net.Conn
	server, err := New(&Config{
		BindIP: net.ParseIP("127.0.0.1"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnUDPTunnel: func(c net.Conn) {
			mu.Lock()
			handed = append(handed, c)
			mu.Unlock()
		},
	})
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
	addr := ln.Addr().String()

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := target.Addr().(*net.TCPAddr).Port
	connect := []byte{0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	associateThrough(t, addr, ConnectCommand, connect)
	associateThrough(t, addr, AssociateCommand, []byte{0x01, 0, 0, 0, 0, 0, 0})
	tunnel, _ := associateThrough(t, addr, UDPTunnelCommand, []byte{0x01, 0, 0, 0, 0, 0, 0})

	// The hook runs before the reply that opens the tunnel, so all three
	// replies in hand mean all three decisions are made.
	mu.Lock()
	defer mu.Unlock()
	if len(handed) != 1 {
		t.Fatalf("the hook got %d connections, want the tunnel only", len(handed))
	}
	if handed[0].RemoteAddr().String() != tunnel.LocalAddr().String() {
		t.Fatalf("the hook got %v, want the tunnel from %v", handed[0].RemoteAddr(), tunnel.LocalAddr())
	}
}
