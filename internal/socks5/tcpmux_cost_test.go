package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// The server's side of 0x83 runs once per datagram in each direction, and on a
// server with one vCPU it runs for every game and call it carries at once.
// What it costs per datagram is an assertion here, as it is for the client
// (TestADatagramCostsNoAllocations in cmd/s5client/udp_client_test.go).

// datagramStand is a 0x83 tunnel through an in-process server to a UDP echo
// on the loopback: the frame the test sends into the tunnel, and the frame the
// echo's answer must come back as.
type datagramStand struct {
	tunnel   net.Conn
	question []byte
	answer   []byte
}

// datagramStandUp opens the tunnel. The echo speaks through the netip API,
// which allocates nothing, so what an allocation count sees is the server.
func datagramStandUp(tb testing.TB, dest func(echo netip.AddrPort) *AddrSpec) *datagramStand {
	tb.Helper()
	echoAddr := udpEchoOnLoopback(tb)

	server, err := New(&Config{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resolver: loopbackResolver{},
	})
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() { _ = server.ServeContext(ctx, ln) }()

	tunnel, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { _ = tunnel.Close() })
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	opening := []byte{Socks5Version, 1, NoAuth, Socks5Version, UDPTunnelCommand, 0, ipv4Address, 0, 0, 0, 0, 0, 0}
	if _, err := tunnel.Write(opening); err != nil {
		tb.Fatalf("opening the tunnel: %v", err)
	}
	replies := make([]byte, 2+10)
	if _, err := io.ReadFull(tunnel, replies); err != nil {
		tb.Fatalf("the server never answered 0x83: %v", err)
	}
	if replies[1] != NoAuth || replies[3] != successReply {
		tb.Fatalf("the server refused the tunnel: % x", replies)
	}
	_ = tunnel.SetDeadline(time.Now().Add(10 * time.Minute))

	payload := bytes.Repeat([]byte("g"), 120)
	return &datagramStand{
		tunnel:   tunnel,
		question: tunnelFrameOf(AppendUDPHeader(nil, dest(echoAddr)), payload),
		answer:   tunnelFrameOf(AppendUDPHeader(nil, &AddrSpec{IP: echoAddr.Addr().AsSlice(), Port: int(echoAddr.Port())}), payload),
	}
}

// udpEchoOnLoopback answers every datagram to its sender. It speaks through
// the netip API, which allocates nothing.
func udpEchoOnLoopback(tb testing.TB) netip.AddrPort {
	tb.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatalf("echo socket: %v", err)
	}
	tb.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return echo.LocalAddr().(*net.UDPAddr).AddrPort()
}

func tunnelFrameOf(header, payload []byte) []byte {
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(header)+len(payload)))
	frame = append(frame, header...)
	return append(frame, payload...)
}

// roundTrip sends the question through the tunnel and reads the answer back
// into got, which is the size of the answer.
func (s *datagramStand) roundTrip(tb testing.TB, got []byte) {
	if _, err := s.tunnel.Write(s.question); err != nil {
		tb.Fatalf("writing into the tunnel: %v", err)
	}
	if _, err := io.ReadFull(s.tunnel, got); err != nil {
		tb.Fatalf("the answer never came back through the tunnel: %v", err)
	}
}

// raceDetector is set by race_detector_test.go under -race, which is how CI
// runs the tests.
var raceDetector bool

// raceBudget is what a datagram may allocate. Under the race detector
// sync.Pool drops a quarter of what is put back, so the pooled frame buffers
// cost about one allocation per round trip there (measured 1.09); one more on
// every datagram still fails.
func raceBudget() float64 {
	if raceDetector {
		return 1
	}
	return 0
}

func toTheEcho(echo netip.AddrPort) *AddrSpec {
	return &AddrSpec{IP: echo.Addr().AsSlice(), Port: int(echo.Port())}
}

func toTheEchoByName(echo netip.AddrPort) *AddrSpec {
	// loopbackResolver answers 127.0.0.1 for every name.
	return &AddrSpec{FQDN: "echo.test", Port: int(echo.Port())}
}

// TestADatagramThroughTheServerCostsNoAllocations holds the per-datagram cost
// of both halves of the server's 0x83 path: the frame read, the header, the
// question put to the rules, the send, the read from the internet and the
// frame written back. A destination given by name goes through the lookup
// queue, whose answer is cached, and is held to the same budget.
func TestADatagramThroughTheServerCostsNoAllocations(t *testing.T) {
	for _, c := range []struct {
		name string
		dest func(netip.AddrPort) *AddrSpec
	}{
		{"an IP address", toTheEcho},
		{"a name", toTheEchoByName},
	} {
		t.Run(c.name, func(t *testing.T) {
			stand := datagramStandUp(t, c.dest)
			got := make([]byte, len(stand.answer))
			roundTrip := func() {
				stand.roundTrip(t, got)
				if !bytes.Equal(got, stand.answer) {
					t.Fatalf("the tunnel brought back % x, want % x", got, stand.answer)
				}
			}

			// One round trip first: the frame buffers come from a pool, the
			// name's answer from a lookup, and neither is what a datagram
			// costs.
			roundTrip()

			// AllocsPerRun truncates to whole allocations per run, so a pool
			// that a garbage collection emptied and that fills itself again
			// does not fail this; one allocation on every datagram does.
			if got := testing.AllocsPerRun(200, roundTrip); got > raceBudget() {
				t.Errorf("one datagram through the server allocates %.0f times, want %.0f", got, raceBudget())
			}
		})
	}
}

// BenchmarkServerDatagramRoundTrip is the same path under benchstat. The time
// includes the loopback, the echo and both sockets, so only the difference
// between two runs on one machine means anything.
func BenchmarkServerDatagramRoundTrip(b *testing.B) {
	for _, c := range []struct {
		name string
		dest func(netip.AddrPort) *AddrSpec
	}{
		{"ip", toTheEcho},
		{"name", toTheEchoByName},
	} {
		b.Run(c.name, func(b *testing.B) {
			stand := datagramStandUp(b, c.dest)
			got := make([]byte, len(stand.answer))
			stand.roundTrip(b, got)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stand.roundTrip(b, got)
			}
		})
	}
}

// BenchmarkServerDatagramAt64Hz is the same round trip at a game's pace, next
// to the loopback alone. Between datagrams the cores go idle, and what the
// wake-ups cost is most of what a proxy adds to a game stream on the loopback
// (docs/benchmarks/udp-over-tcp.md). The number is p50-ns; run it with
// -benchtime=400x, the time per operation is mostly the pause.
func BenchmarkServerDatagramAt64Hz(b *testing.B) {
	const gap = time.Second / 64
	p50 := func(b *testing.B, roundTrip func()) {
		roundTrip()
		took := make([]time.Duration, 0, b.N)
		for b.Loop() {
			time.Sleep(gap)
			start := time.Now()
			roundTrip()
			took = append(took, time.Since(start))
		}
		slices.Sort(took)
		b.ReportMetric(float64(took[len(took)/2].Nanoseconds()), "p50-ns")
	}
	b.Run("loopback", func(b *testing.B) {
		echo := udpEchoOnLoopback(b)
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatalf("client socket: %v", err)
		}
		b.Cleanup(func() { _ = c.Close() })
		question, answer := make([]byte, 200), make([]byte, 2048)
		p50(b, func() {
			if _, err := c.WriteToUDPAddrPort(question, echo); err != nil {
				b.Fatalf("send: %v", err)
			}
			if _, _, err := c.ReadFromUDPAddrPort(answer); err != nil {
				b.Fatalf("receive: %v", err)
			}
		})
	})
	b.Run("server", func(b *testing.B) {
		stand := datagramStandUp(b, toTheEcho)
		got := make([]byte, len(stand.answer))
		p50(b, func() { stand.roundTrip(b, got) })
	})
}
