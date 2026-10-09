package socks5

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPAnswerFrameLimitKeepsTheStreamSynchronized(t *testing.T) {
	for _, family := range []string{"udp4", "udp6"} {
		for _, fallback := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/native_fallback=%t", family, fallback), func(t *testing.T) {
				ip, header, maxUDP := net.ParseIP("127.0.0.1"), 10, 65507
				if family == "udp6" {
					ip, header, maxUDP = net.ParseIP("::1"), 22, 65527
				}
				egress, err := newRotatingUDP(ip)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				a, b := net.Pipe()
				var drops atomic.Uint64
				server, err := New(&Config{OnUDPDrop: func(reason string) {
					if reason != UDPDropFrameOversize {
						t.Errorf("unexpected drop: %s", reason)
					}
					drops.Add(1)
				}})
				if err != nil {
					t.Fatal(err)
				}
				tunnel := &udpTunnel{s: server, req: &Request{}, tunnelCtx: ctx, cancel: cancel,
					tcpConn: a, egress: egress, acct: &udpAccount{}, count: new(NativeCounters), errCh: make(chan error, 1)}
				writerDone := make(chan struct{})
				if fallback {
					tunnel.native = newScriptedNative()
					tunnel.startFallback()
					go func() { defer close(writerDone); _ = tunnel.fallback.Run() }()
				} else {
					close(writerDone)
				}
				done := make(chan struct{})
				go func() { defer close(done); tunnel.answers() }()
				defer func() {
					cancel()
					if tunnel.fallback != nil {
						tunnel.fallback.Stop()
					}
					_ = a.Close()
					_ = b.Close()
					_ = egress.Close()
					<-done
					<-writerDone
				}()
				sender, err := net.ListenUDP(family, &net.UDPAddr{IP: ip})
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
				send := func(payload []byte) {
					t.Helper()
					if _, err := sender.WriteToUDP(payload, egress.current().LocalAddr().(*net.UDPAddr)); err != nil {
						t.Fatal(err)
					}
				}
				check := func(payload []byte) {
					t.Helper()
					frame := readTCPAnswer(t, b)
					if len(frame) != header+len(payload) || !bytes.Equal(frame[header:], payload) {
						t.Fatalf("frame body %d bytes, want %d with intact payload", len(frame), header+len(payload))
					}
				}
				largest := bytes.Repeat([]byte{'x'}, min(65535-header, maxUDP))
				send(largest)
				check(largest)
				if family == "udp6" {
					// One byte over the tunnel boundary and the largest IPv6 UDP
					// payload both fit UDP but must be dropped as whole frames.
					send(bytes.Repeat([]byte{'y'}, 65536-header))
					send(bytes.Repeat([]byte{'z'}, maxUDP))
				}
				next := []byte("next game packet")
				send(next)
				check(next)
				wantDrops := uint64(0)
				if family == "udp6" {
					wantDrops = 2
				}
				if drops.Load() != wantDrops {
					t.Fatalf("frame drops %d, want %d", drops.Load(), wantDrops)
				}
			})
		}
	}
}
