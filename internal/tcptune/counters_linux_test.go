package tcptune

import (
	"errors"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Every field Linux 4.19 and later fills.
const linuxCounters = CounterRTT | CounterRTTVar | CounterMinRTT | CounterRTO | CounterSinceData |
	CounterSinceAck | CounterState | CounterRetransmits | CounterUnacked | CounterTotalRetrans |
	CounterCongestionWindow | CounterNotSentBytes | CounterBytesAcked | CounterBytesReceived |
	CounterBytesSent | CounterBytesRetrans

func TestCountersOfALiveSocket(t *testing.T) {
	c, s := tcpPair(t)
	exchange(t, c, s, 1000)
	got, err := CountersOf(netConnWrapper{c})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Known(linuxCounters) {
		t.Fatalf("fields %b, want at least %b", got.Has, linuxCounters)
	}
	if got.Known(CounterInFlightBytes | CounterCongestionWindowBytes | CounterTimeoutEpisodes) {
		t.Errorf("Windows fields on Linux: %b", got.Has)
	}
	if got.RTT <= 0 || got.MinRTT <= 0 || got.RTO <= 0 || got.CongestionWindow == 0 {
		t.Errorf("no round trip or window measured: %+v", got)
	}
	if got.BytesSent < 1000 || got.BytesAcked < 1000 || got.BytesReceived < 1000 || got.State != StateEstablished {
		t.Errorf("1000 bytes each way read as %+v", got)
	}
	if got.Retransmits != 0 || got.SinceData > 2*time.Second {
		t.Errorf("a healthy path shows trouble: %+v", got)
	}
	// The same read as InfoOf.
	info, ok := InfoOf(c)
	if !ok || info.State != got.State || !info.BytesAckedKnown {
		t.Errorf("InfoOf reads %+v (ok %v)", info, ok)
	}
}

func TestCountersOfDoesNotAllocate(t *testing.T) {
	c, _ := tcpPair(t)
	for _, conn := range []net.Conn{c, netConnWrapper{unwrapWrapper{netConnWrapper{c}}}} {
		var err error
		if n := testing.AllocsPerRun(100, func() { _, err = CountersOf(conn) }); n != 0 || err != nil {
			t.Fatalf("%v allocations per read (%v)", n, err)
		}
	}
}

func TestCountersOfAClosedSocket(t *testing.T) {
	_, s := tcpPair(t)
	_ = s.Close()
	if c, err := CountersOf(s); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a closed socket gives %+v (%v)", c, err)
	}
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if c, err := CountersOf(u); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("a UDP socket gives %+v (%v)", c, err)
	}
	if _, err := countersOf(syscallOnly{Conn: u, sc: u}); err == nil {
		t.Fatal("a UDP socket reached as a syscall.Conn has counters")
	}
}

// A field is set only where the kernel's answer reaches its end.
func TestATruncatedTCPInfoSetsOnlyTheFieldsItReaches(t *testing.T) {
	var ti unix.TCPInfo
	end := func(off, size uintptr) uint32 { return uint32(off + size) }
	base := CounterRTT | CounterRTO | CounterSinceData | CounterSinceAck | CounterState | CounterRetransmits | CounterUnacked
	old := base | CounterRTTVar | CounterCongestionWindow | CounterTotalRetrans
	for _, tc := range []struct {
		name string
		n    uint32
		want CounterField
	}{
		{"a current kernel", uint32(unsafe.Sizeof(ti)), linuxCounters | CounterSendWindow | CounterReceiveWindow},
		{"ends at tcpi_rtt", infoBaseLen, base},
		{"before tcpi_bytes_acked", uint32(unsafe.Offsetof(ti.Bytes_acked)), old},
		{"ends at tcpi_bytes_received", end(unsafe.Offsetof(ti.Bytes_received), unsafe.Sizeof(ti.Bytes_received)), old | CounterBytesAcked | CounterBytesReceived},
		{"ends at tcpi_min_rtt", end(unsafe.Offsetof(ti.Min_rtt), unsafe.Sizeof(ti.Min_rtt)), old | CounterBytesAcked | CounterBytesReceived | CounterNotSentBytes | CounterMinRTT},
		{"one byte short of tcpi_bytes_retrans", end(unsafe.Offsetof(ti.Bytes_retrans), unsafe.Sizeof(ti.Bytes_retrans)) - 1, linuxCounters &^ CounterBytesRetrans},
		{"ends at tcpi_snd_wnd", end(unsafe.Offsetof(ti.Snd_wnd), unsafe.Sizeof(ti.Snd_wnd)), linuxCounters | CounterSendWindow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := decodeCounters(&ti, tc.n)
			if !ok || c.Has != tc.want {
				t.Fatalf("%d bytes: fields %b (ok %v), want %b", tc.n, c.Has, ok, tc.want)
			}
		})
	}
	if c, ok := decodeCounters(&ti, infoBaseLen-1); ok {
		t.Fatalf("an answer without tcpi_rtt reads as %+v", c)
	}
}

func TestDecodeCountersMapsEveryField(t *testing.T) {
	ti := unix.TCPInfo{
		State: StateEstablished, Retransmits: 1, Rto: 204000, Unacked: 2, Last_data_recv: 30,
		Last_ack_recv: 40, Rtt: 5000, Rttvar: 2500, Snd_cwnd: 10, Total_retrans: 3,
		Bytes_acked: 100, Bytes_received: 200, Notsent_bytes: 300, Min_rtt: 4000,
		Bytes_sent: 400, Bytes_retrans: 50, Snd_wnd: 65535, Rcv_wnd: 65000,
	}
	got, ok := decodeCounters(&ti, uint32(unsafe.Sizeof(ti)))
	want := Counters{
		Has: linuxCounters | CounterSendWindow | CounterReceiveWindow,
		RTT: 5 * time.Millisecond, RTTVar: 2500 * time.Microsecond, MinRTT: 4 * time.Millisecond,
		RTO: 204 * time.Millisecond, SinceData: 30 * time.Millisecond, SinceAck: 40 * time.Millisecond,
		BytesAcked: 100, BytesReceived: 200, BytesSent: 400, BytesRetrans: 50,
		Unacked: 2, TotalRetrans: 3, CongestionWindow: 10, NotSentBytes: 300,
		SendWindow: 65535, ReceiveWindow: 65000, Retransmits: 1, State: StateEstablished,
	}
	if !ok || got != want {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}
