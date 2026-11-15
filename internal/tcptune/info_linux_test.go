package tcptune

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A connection that has just moved data both ways is the healthy case the
// numbers are read against: no timer firing, and the time since the peer last
// spoke is a moment, not seconds. Unacked is not asserted: the last segment
// of the exchange may still be waiting for its acknowledgement.
func TestInfoOfALivePath(t *testing.T) {
	c, s := tcpPair(t)
	b := []byte{0}
	for range 5 {
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Read(b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	info, ok := InfoOf(s)
	if !ok {
		t.Fatal("no TCP info for a live socket")
	}
	if info.Retransmits != 0 {
		t.Errorf("a healthy path shows trouble: %+v", info)
	}
	if info.SinceData > 2*time.Second || info.SinceAck > 2*time.Second {
		t.Errorf("a path that has just spoken is silent for seconds: %+v", info)
	}
	if info.RTT <= 0 {
		t.Errorf("no round trip measured: %+v", info)
	}
	// Each answer acknowledges the bytes it answers: the count is read once
	// the answer is in, so no acknowledgement can still be on its way.
	sent, ok := InfoOf(c)
	if !ok || !sent.BytesAckedKnown || sent.BytesAcked < 5 {
		t.Fatalf("five bytes answered, %d acknowledged (known: %v)", sent.BytesAcked, sent.BytesAckedKnown)
	}
	more := make([]byte, 100)
	if _, err := c.Write(more); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s, more); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(b); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(b); err != nil {
		t.Fatal(err)
	}
	if after, ok := InfoOf(c); !ok || after.BytesAcked < sent.BytesAcked+100 {
		t.Errorf("100 more bytes answered, the count went from %d to %d", sent.BytesAcked, after.BytesAcked)
	}
}

// The read that every closing tunnel and every taken spare makes costs the
// garbage collector nothing, through the wrappers too.
func TestInfoOfDoesNotAllocate(t *testing.T) {
	c, _ := tcpPair(t)
	for _, tc := range []struct {
		name string
		conn net.Conn
	}{
		{"socket", c},
		{"wrapped", netConnWrapper{c}},
		{"wrapped twice", netConnWrapper{unwrapWrapper{netConnWrapper{c}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ok bool
			if n := testing.AllocsPerRun(100, func() { _, ok = InfoOf(tc.conn) }); n != 0 || !ok {
				t.Fatalf("%v allocations per read (info: %v)", n, ok)
			}
		})
	}
}

// A kernel writes only the part of struct tcp_info it knows: one without
// tcpi_bytes_acked leaves a zero there that is not a count.
func TestATruncatedTCPInfoLeavesBytesAckedUnknown(t *testing.T) {
	ti := unix.TCPInfo{
		State: StateEstablished, Retransmits: 2, Unacked: 3, Rtt: 25000,
		Last_data_recv: 1500, Last_ack_recv: 700, Bytes_acked: 4096,
	}
	base := Info{RTT: 25 * time.Millisecond, Unacked: 3, Retransmits: 2,
		SinceData: 1500 * time.Millisecond, SinceAck: 700 * time.Millisecond, State: StateEstablished}
	counted := base
	counted.BytesAcked, counted.BytesAckedKnown = 4096, true
	for _, tc := range []struct {
		name string
		n    uint32
		want Info
		ok   bool
	}{
		{"a current kernel", uint32(unsafe.Sizeof(ti)), counted, true},
		{"ends at tcpi_bytes_acked", infoBytesAckedLen, counted, true},
		{"one byte short of it", infoBytesAckedLen - 1, base, true},
		{"older, ending at tcpi_max_pacing_rate", uint32(unsafe.Offsetof(ti.Bytes_acked)), base, true},
		{"ending at tcpi_total_retrans", uint32(unsafe.Offsetof(ti.Pacing_rate)), base, true},
		{"ends at tcpi_rtt", infoBaseLen, base, true},
		{"without tcpi_rtt", infoBaseLen - 1, Info{}, false},
		{"an int, as an emulator answers", 4, Info{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeInfo(&ti, tc.n)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("%d bytes read as %+v (ok %v), want %+v (ok %v)", tc.n, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// syscallOnly is a socket the walk finds only as a syscall.Conn.
type syscallOnly struct {
	net.Conn
	sc syscall.Conn
}

func (s syscallOnly) SyscallConn() (syscall.RawConn, error) { return s.sc.SyscallConn() }

func TestInfoOfASocketThatIsNotATCPConn(t *testing.T) {
	c, s := tcpPair(t)
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	info, ok := InfoOf(syscallOnly{Conn: s, sc: s})
	if !ok || info.State != StateEstablished || !info.BytesAckedKnown {
		t.Fatalf("a socket reached as a syscall.Conn reads as %+v, ok=%v", info, ok)
	}
}

func TestAUDPSocketHasNoTCPInfo(t *testing.T) {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if info, ok := InfoOf(u); ok {
		t.Fatalf("a UDP socket has TCP info: %+v", info)
	}
}

func BenchmarkInfoOf(b *testing.B) {
	c, _ := tcpPair(b)
	var conn net.Conn = netConnWrapper{c}
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := InfoOf(conn); !ok {
			b.Fatal("no TCP info for a live socket")
		}
	}
}

func TestAClosedSocketHasNoInfo(t *testing.T) {
	_, s := tcpPair(t)
	_ = s.Close()
	if info, ok := InfoOf(s); ok {
		t.Fatalf("a closed socket has TCP info: %+v", info)
	}
}

func TestAPeerThatClosedLeavesTheSocketOutOfEstablished(t *testing.T) {
	c, s := tcpPair(t)
	if info, ok := InfoOf(c); !ok || info.State != StateEstablished {
		t.Fatalf("a live socket is in state %d, ok=%v", info.State, ok)
	}
	// Bytes ahead of the FIN, as a TLS close_notify would be: the state
	// still says the peer is gone.
	if _, err := s.Write([]byte("alert")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, ok := InfoOf(c)
		if ok && info.State != StateEstablished {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket is still established after the peer closed: %+v", info)
		}
		time.Sleep(time.Millisecond)
	}
}
