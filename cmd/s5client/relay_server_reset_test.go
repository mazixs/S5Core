package main

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/s5server"
)

func TestTargetResetReachesTheApplicationAcrossTheRealObfsServer(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	reset := make(chan struct{})
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err = io.ReadFull(c, make([]byte, 3)); err != nil {
			return
		}
		_, _ = c.Write([]byte("partial response"))
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
		close(reset)
	}()
	addr, cfg := startTunnelServerWith(t, func(c *s5server.Config) { c.DenyPrivateDest = false })
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := obfs.NewClientConn(raw, obfs.Config{PSK: []byte(cfg.ObfsPSK), MaxPadding: cfg.ObfsMaxPadding, MTU: cfg.ObfsMTU})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = tunnel.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(tunnel, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	port := target.Addr().(*net.TCPAddr).Port
	if _, err = tunnel.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err = io.ReadFull(tunnel, reply); err != nil || reply[1] != 0 {
		t.Fatalf("CONNECT %x, %v", reply, err)
	}
	app, relay := tcpPair(t)
	done := relayPair(t, relay, tunnel)
	if _, err = app.Write([]byte("get")); err != nil {
		t.Fatal(err)
	}
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(app)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("truncated target response ended cleanly: %v", err)
	}
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("target did not reset")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle application kept the client handler")
	}
}
