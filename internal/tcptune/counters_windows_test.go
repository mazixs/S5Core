package tcptune

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTCPInfoV0MapsItsFields(t *testing.T) {
	var b tcpInfoV0
	binary.LittleEndian.PutUint32(b[0:], 4) // TcpConnectionEstablished: another numbering
	for off, v := range map[int]uint32{20: 32000, 24: 21000, 28: 1024, 32: 14600, 36: 65535, 40: 64000, 68: 300, 80: 2} {
		binary.LittleEndian.PutUint32(b[off:], v)
	}
	binary.LittleEndian.PutUint64(b[48:], 1<<33)
	binary.LittleEndian.PutUint64(b[56:], 7000)
	want := Counters{
		Has: CounterRTT | CounterMinRTT | CounterInFlightBytes | CounterCongestionWindowBytes |
			CounterSendWindow | CounterReceiveWindow | CounterBytesSent | CounterBytesReceived |
			CounterBytesRetrans | CounterTimeoutEpisodes,
		RTT: 32 * time.Millisecond, MinRTT: 21 * time.Millisecond, InFlightBytes: 1024,
		CongestionWindowBytes: 14600, SendWindow: 65535, ReceiveWindow: 64000,
		BytesSent: 1 << 33, BytesReceived: 7000, BytesRetrans: 300, TimeoutEpisodes: 2,
	}
	if got := decodeTCPInfoV0(&b); got != want {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}

func TestCountersOfALiveSocketOnWindows(t *testing.T) {
	c, s := tcpPair(t)
	exchange(t, c, s, 1000)
	got, err := CountersOf(netConnWrapper{c})
	if err != nil {
		t.Fatal(err)
	}
	if got.RTT < 0 || got.BytesSent < 1000 || got.BytesReceived < 1000 || got.Known(CounterState) {
		t.Errorf("1000 bytes each way read as %+v", got)
	}
	if info, ok := InfoOf(c); ok {
		t.Errorf("InfoOf answers on Windows: %+v", info)
	}
	for _, conn := range []net.Conn{c, netConnWrapper{unwrapWrapper{netConnWrapper{c}}}} {
		if n := testing.AllocsPerRun(100, func() { _, err = CountersOf(conn) }); n != 0 || err != nil {
			t.Fatalf("%v allocations per read (%v)", n, err)
		}
	}
	if _, err := countersOf(syscallOnly{Conn: s, sc: s}); err != nil {
		t.Errorf("a socket reached as a syscall.Conn: %v", err)
	}
	_ = c.Close()
	if got, err := CountersOf(c); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a closed socket gives %+v (%v)", got, err)
	}
}
