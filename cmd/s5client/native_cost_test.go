package main

import (
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// gameRoundTrip opens an association to an echo target and returns one game
// datagram there and back, from the application's socket, without allocating
// on the side of the test.
func gameRoundTrip(tb testing.TB, clientCfg clientParams) (roundTrip func() error, metered *meteredConn) {
	echo := udpEcho(tb)
	sender, local, metered := openAssociation(tb, clientCfg)
	to := local.AddrPort()
	question := socksDatagram(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, make([]byte, 200))
	inbound := make([]byte, 2048)
	_ = sender.SetReadDeadline(time.Now().Add(10 * time.Minute))
	return func() error {
		if _, err := sender.WriteToUDPAddrPort(question, to); err != nil {
			return err
		}
		_, _, err := sender.ReadFromUDPAddrPort(inbound)
		return err
	}, metered
}

// untilNative returns once a round trip leaves the control connection alone:
// the first datagrams go by 0x83 while the probe is in flight.
func untilNative(tb testing.TB, roundTrip func() error, metered *meteredConn) {
	tb.Helper()
	for i := 0; i < 100; i++ {
		r, w := metered.read.Load(), metered.written.Load()
		if err := roundTrip(); err != nil {
			tb.Fatal(err)
		}
		if metered.read.Load() == r && metered.written.Load() == w {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatal("native UDP never carried a datagram")
}

// A game datagram through a native association and its answer allocate
// nothing anywhere in the process: AllocsPerRun counts every goroutine, so
// the number covers the client's loop, the server's hub and association and
// the target, not only the client. The hub alone is held by
// TestADatagramThroughTheHubCostsNoAllocations in pkg/nativeudp.
func TestANativeDatagramCostsNoAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops pooled buffers")
	}
	quietLogs(t)
	addr, cfg := startTunnelServer(t, true)
	roundTrip, metered := gameRoundTrip(t, nativeParams(addr, cfg.ObfsPSK))
	untilNative(t, roundTrip, metered)

	r, w := metered.read.Load(), metered.written.Load()
	got := testing.AllocsPerRun(1000, func() {
		if err := roundTrip(); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Errorf("one native datagram each way allocates %.2f times, want 0", got)
	}
	if metered.read.Load() != r || metered.written.Load() != w {
		t.Errorf("the measured datagrams crossed the control connection: read %d, written %d",
			metered.read.Load()-r, metered.written.Load()-w)
	}
}

// BenchmarkAssociationRoundTrip is a game datagram through the whole stack,
// native against 0x83 on the same server, under ./scripts/bench.sh
// (PKG=./cmd/s5client/). The number includes the loopback and four sockets,
// so only a difference between two runs on one machine means anything.
func BenchmarkAssociationRoundTrip(b *testing.B) {
	quietLogs(b)
	addr, cfg := startTunnelServer(b, true)
	for _, c := range []struct {
		name   string
		native bool
	}{{"native", true}, {"0x83", false}} {
		b.Run(c.name, func(b *testing.B) {
			clientCfg := nativeParams(addr, cfg.ObfsPSK)
			clientCfg.UDPNative = c.native
			roundTrip, metered := gameRoundTrip(b, clientCfg)
			if c.native {
				untilNative(b, roundTrip, metered)
			} else if err := roundTrip(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := roundTrip(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
