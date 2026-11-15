package socks5

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/diagnostics"
	"github.com/mazixs/S5Core/internal/session"
)

// loopbackPair is the two ends of one TCP connection over the loopback.
func loopbackPair(tb testing.TB) (dialed, accepted net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer ln.Close()
	dialed, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	if accepted, err = ln.Accept(); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = dialed.Close(); _ = accepted.Close() })
	return dialed, accepted
}

// startLatency turns the latency recorder on, its log line off, and waits
// until it selects a socket. It returns the recorder's directory and its
// stop.
func startLatency(tb testing.TB) (dir string, stop func()) {
	tb.Helper()
	logger := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	tb.Cleanup(func() { slog.SetDefault(logger) })
	dir = filepath.Join(tb.TempDir(), "diag")
	tb.Setenv("S5_DIAGNOSTICS_DIR", dir)
	stop = diagnostics.StartLatency()
	tb.Cleanup(stop)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		c, _ := loopbackPair(tb)
		observed := diagnostics.ObserveConn(c, "probe", "tcp")
		_ = observed.Close()
		if observed != c {
			return dir, stop
		}
	}
	tb.Fatal("the latency recorder did not start")
	return "", nil
}

// What the latency recorder's wrappers cost the relay of a CONNECT, 64 KiB
// from the destination to the client per op over the loopback: off, with the
// client's socket recorded, and with the destination recorded beside it.
func BenchmarkConnectRelay(b *testing.B) {
	for _, mode := range []string{"off", "client", "client+destination"} {
		b.Run(mode, func(b *testing.B) {
			if mode != "off" {
				startLatency(b)
			}
			clientFar, clientSocket := loopbackPair(b)
			targetSocket, targetFar := loopbackPair(b)
			client, target := clientSocket, targetSocket
			if mode != "off" {
				client = diagnostics.ObserveConn(clientSocket, "outer", "plain")
			}
			if mode == "client+destination" {
				target = diagnostics.ObserveRelated(client, targetSocket, "target")
			}
			if (client != clientSocket) != (mode != "off") || (target != targetSocket) != (mode == "client+destination") {
				b.Fatal("the recorder did not take the sockets")
			}
			server, err := New(&Config{})
			if err != nil {
				b.Fatal(err)
			}
			go func() {
				_ = server.relayConnect(context.Background(), client, &Request{
					bufConn: client, session: auditRelaySession(session.SLA{}),
				}, target)
			}()
			payload := make([]byte, 64<<10)
			got := make([]byte, len(payload))
			next := make(chan struct{})
			defer close(next)
			go func() {
				for range next {
					if _, err := targetFar.Write(payload); err != nil {
						return
					}
				}
			}()
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				next <- struct{}{}
				if _, err := io.ReadFull(clientFar, got); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
