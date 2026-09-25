package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/s5server"
)

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

func TestClientNativeAndOldServerFallback(t *testing.T) {
	for _, native := range []bool{true, false} {
		name := "old server"
		if native {
			name = "native server"
		}
		t.Run(name, func(t *testing.T) {
			plain, obfsPort := freeTCPPort(t), freeTCPPort(t)
			cfg := s5server.DefaultConfig()
			cfg.ListenIP, cfg.Port, cfg.ObfsPort = "127.0.0.1", plain, obfsPort
			cfg.RequireAuth = false
			cfg.ObfsEnabled = true
			cfg.ObfsPSK = "01234567890123456789012345678901"
			cfg.ObfsMTU = 1400
			if native {
				cfg.UDPPort = "0"
			}
			srv, err := s5server.NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- srv.Start(ctx) }()
			t.Cleanup(func() { cancel(); _ = srv.Stop(); <-done })
			addr := net.JoinHostPort("127.0.0.1", obfsPort)
			deadline := time.Now().Add(2 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
				if err == nil {
					_ = c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("server did not listen", err)
				}
				time.Sleep(time.Millisecond)
			}
			echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				var b [2048]byte
				for {
					n, peer, err := echo.ReadFromUDPAddrPort(b[:])
					if err != nil {
						return
					}
					_, _ = echo.WriteToUDPAddrPort(b[:n], peer)
				}
			}()

			clientCfg := clientParams{ServerAddr: addr, PSK: cfg.ObfsPSK, MTU: 1400, MaxPadding: 32, Transport: "obfs", UDPNative: true, HandshakeTimeout: 3 * time.Second}
			req := []byte{5, socks5.UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}
			stream, _, err := dialTunnel(clientCfg, req)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			app, handlerSide := tcpPair(t)
			go handleUDPAssociate(handlerSide, stream, "", clientCfg, req)
			reply := readAppReply(t, app)
			if reply[1] != 0 {
				t.Fatalf("application refused: %x", reply)
			}
			local := boundUDPPort(t, reply)
			sender := appSocket(t)
			payload := socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("tick"))
			// The first tick can legitimately use TCP before the UDP probe ACK.
			for i := 0; i < 3; i++ {
				if _, err := sender.WriteToUDP(payload, local); err != nil {
					t.Fatal(err)
				}
				_ = sender.SetReadDeadline(time.Now().Add(3 * time.Second))
				var b [2048]byte
				n, _, err := sender.ReadFromUDP(b[:])
				if err != nil {
					t.Fatalf("tick %d: %v", i, err)
				}
				if !bytes.HasSuffix(b[:n], []byte("tick")) {
					t.Fatalf("tick %d response %x", i, b[:n])
				}
			}
		})
	}
}
