package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The UDP path of the client is the one loop in it that runs per datagram, and
// it runs on the machine with the least to spare: an ARM router under
// GOMEMLIMIT=32MiB (docs/benchmarks/arm-router.md). What it costs per datagram
// is therefore an assertion here, not a note in a benchmark.

// udpTunnelUp brings the client's UDP handler to the state where datagrams
// flow: the server has answered 0x83, the application has been told the port
// to send to, and it has a socket to send from.
func udpTunnelUp(t testing.TB) (sender *net.UDPConn, local netip.AddrPort, tunnel net.Conn) {
	t.Helper()

	app, tunnel, _ := startUDPAssociate(t)
	if _, err := tunnel.Write(udpTunnelReply); err != nil {
		t.Fatalf("answering the 0x83 command: %v", err)
	}
	reply := readAppReply(t, app)
	if reply[1] != 0x00 {
		t.Fatalf("the client refused a tunnel the server accepted: reply % x", reply)
	}
	return appSocket(t), addrPortOf(t, boundUDPPort(t, reply)), tunnel
}

// appSocket is a socket on the loopback address the application made its
// SOCKS5 connection from, which is the only address the client accepts
// datagrams from.
func appSocket(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("application socket: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// quietLogs sends the handler's own logging nowhere for the duration of a
// benchmark. It writes through the standard logger, which goes to the same
// stream the iteration counts do, and benchstat cannot read a line with a log
// entry in the middle of it.
func quietLogs(t testing.TB) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

func addrPortOf(t testing.TB, a *net.UDPAddr) netip.AddrPort {
	t.Helper()
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		t.Fatalf("the client bound an address that is not an IP: %v", a)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
}

// readFrame reads one length-prefixed frame off the tunnel.
func readFrame(t testing.TB, tunnel net.Conn, size int) []byte {
	t.Helper()
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, size+2)
	if _, err := io.ReadFull(tunnel, buf); err != nil {
		t.Fatalf("the datagram never reached the server: %v", err)
	}
	return buf
}

func TestTheAnswerGoesToThePortTheApplicationLastSentFrom(t *testing.T) {
	first, local, tunnel := udpTunnelUp(t)
	second := appSocket(t)

	// An application is free to open a second socket - a resolver asking two
	// questions at once does exactly that - and the answer belongs to
	// whichever asked last, because that is the only thing the tunnel says
	// about it: the inner SOCKS5 header names the remote host, not the local
	// port.
	for _, sender := range []*net.UDPConn{first, second} {
		question := datagram("question")
		if _, err := sender.WriteToUDPAddrPort(question, local); err != nil {
			t.Fatalf("sending a datagram: %v", err)
		}
		if got, want := readFrame(t, tunnel, len(question)), tunnelFrame(question); !bytes.Equal(got, want) {
			t.Fatalf("the server got % x, want % x", got, want)
		}

		answer := datagram("answer")
		if _, err := tunnel.Write(tunnelFrame(answer)); err != nil {
			t.Fatalf("answering through the tunnel: %v", err)
		}
		_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := sender.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("the answer never reached the socket that asked: %v", err)
		}
		if !bytes.Equal(buf[:n], answer) {
			t.Fatalf("the application got % x, want % x", buf[:n], answer)
		}
	}
}

func TestADatagramFromAnotherAddressIsNotTunnelled(t *testing.T) {
	sender, local, tunnel := udpTunnelUp(t)

	// 127.0.0.2 is the same machine and a different address, which is the
	// case the check exists for: anything on the host can find the port the
	// client announced, and only the application that opened the association
	// may use it.
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("no second loopback address to send from: %v", err)
	}
	defer func() { _ = stranger.Close() }()

	if _, err := stranger.WriteToUDPAddrPort(datagram("from a stranger"), local); err != nil {
		t.Fatalf("sending from the stranger: %v", err)
	}
	// The application's own datagram is sent after it and read first: what
	// comes out of the tunnel says which of the two was forwarded, without a
	// sleep deciding it.
	mine := datagram("from the application")
	if _, err := sender.WriteToUDPAddrPort(mine, local); err != nil {
		t.Fatalf("sending from the application: %v", err)
	}
	if got, want := readFrame(t, tunnel, len(mine)), tunnelFrame(mine); !bytes.Equal(got, want) {
		t.Fatalf("the first frame out of the tunnel is % x, want the application's own % x", got, want)
	}

	// And nothing follows it.
	_ = tunnel.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var extra [1]byte
	if n, err := tunnel.Read(extra[:]); err == nil {
		t.Fatalf("the stranger's datagram reached the server too (%d more bytes)", n)
	}
}

// TestADatagramCostsNoAllocations holds the cost of the per-datagram path.
//
// Both ends of the measurement are allocation-free by construction: the test
// speaks to its sockets through the netip API, so what AllocsPerRun counts is
// the client's loop and the kernel path under it. Before review finding R11 a
// round trip cost seven allocations: four went on rendering both addresses to
// strings to compare them, although the answer is fixed when the association
// is made, and three on the address the answer goes back to, copied on every
// datagram although it had not changed.
func TestADatagramCostsNoAllocations(t *testing.T) {
	sender, local, tunnel := udpTunnelUp(t)

	question := datagram("question")
	answer := tunnelFrame(datagram("answer"))
	outbound := make([]byte, len(question)+2)
	inbound := make([]byte, 2048)
	_ = tunnel.SetReadDeadline(time.Now().Add(30 * time.Second))

	roundTrip := func() {
		if _, err := sender.WriteToUDPAddrPort(question, local); err != nil {
			t.Fatalf("sending a datagram: %v", err)
		}
		if _, err := io.ReadFull(tunnel, outbound); err != nil {
			t.Fatalf("the datagram never reached the server: %v", err)
		}
		if _, err := tunnel.Write(answer); err != nil {
			t.Fatalf("answering through the tunnel: %v", err)
		}
		_ = sender.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, _, err := sender.ReadFromUDPAddrPort(inbound); err != nil {
			t.Fatalf("the answer never reached the application: %v", err)
		}
	}

	// One round trip first: the frame buffers come from a pool, and the cost
	// of filling it is not the cost of a datagram.
	roundTrip()

	// The budget is one: the address is stored again whenever it changes, and
	// a pool that a garbage collection emptied fills itself once more.
	if got := testing.AllocsPerRun(100, roundTrip); got > 1 {
		t.Errorf("one datagram through the client allocates %.1f times, want at most one", got)
	}
}

// BenchmarkUDPDatagramRoundTrip is the same path under ./scripts/bench.sh, so
// a change to it is compared rather than asserted: the number here includes
// two sockets and the loopback, and only the difference between two runs on
// the same machine means anything.
func BenchmarkUDPDatagramRoundTrip(b *testing.B) {
	quietLogs(b)
	sender, local, tunnel := udpTunnelUp(b)

	question := datagram("question")
	answer := tunnelFrame(datagram("answer"))
	outbound := make([]byte, len(question)+2)
	inbound := make([]byte, 2048)
	_ = tunnel.SetReadDeadline(time.Now().Add(10 * time.Minute))
	_ = sender.SetReadDeadline(time.Now().Add(10 * time.Minute))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sender.WriteToUDPAddrPort(question, local); err != nil {
			b.Fatalf("sending a datagram: %v", err)
		}
		if _, err := io.ReadFull(tunnel, outbound); err != nil {
			b.Fatalf("the datagram never reached the server: %v", err)
		}
		if _, err := tunnel.Write(answer); err != nil {
			b.Fatalf("answering through the tunnel: %v", err)
		}
		if _, _, err := sender.ReadFromUDPAddrPort(inbound); err != nil {
			b.Fatalf("the answer never reached the application: %v", err)
		}
	}
}
