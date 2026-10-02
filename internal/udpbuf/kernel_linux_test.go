package udpbuf

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Without CAP_NET_ADMIN a socket gets twice the smaller of Want and
// rmem_max; with it, twice Want. Either way Full says which.
func TestASocketGetsWhatTheCeilingAllows(t *testing.T) {
	c, err := ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := Grow(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.Limit <= 0 {
		t.Fatalf("rmem_max not read: %+v", got)
	}
	capped := 2 * min(Want, got.Limit)
	if got.Bytes != capped && got.Bytes != 2*Want {
		t.Fatalf("got %d bytes with rmem_max %d, want %d or %d", got.Bytes, got.Limit, capped, 2*Want)
	}
	if got.Full != (got.Bytes >= 2*Want) {
		t.Fatalf("Full = %v for %d bytes", got.Full, got.Bytes)
	}
	t.Logf("%+v", got)
}

func TestProbeAnswersForEverySocket(t *testing.T) {
	probe, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := Grow(c)
	if err != nil {
		t.Fatal(err)
	}
	if got != probe {
		t.Fatalf("a dialled socket got %+v, the probe %+v", got, probe)
	}
}

// The count is the namespace's, so other sockets may add to it; an overflow
// here must add at least what it dropped.
func TestAnOverflowIsCounted(t *testing.T) {
	if _, err := os.Stat("/proc/net/snmp"); err != nil {
		t.Skipf("no /proc/net/snmp: %v", err)
	}
	before, ok := ReceiveDrops()
	if !ok {
		t.Fatal("no receive drop count on Linux")
	}
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rx.Close() }()
	raw, _ := rx.SyscallConn()
	// The kernel raises a tiny request to its minimum, a couple of datagrams.
	_ = raw.Control(func(fd uintptr) { _ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1) })
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Close() }()
	const sent = 200
	for range sent {
		if _, err := tx.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 2000)
	read := 0
	for {
		_ = rx.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := rx.Read(buf); err != nil {
			break
		}
		read++
	}
	after, _ := ReceiveDrops()
	if dropped := uint64(sent - read); after-before < dropped {
		t.Fatalf("read %d of %d, the count grew by %d", read, sent, after-before)
	}
}

const snmp = `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 100
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 16664114 3611 29566 10382177 29565 7 0 266594 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 0 0 99 0 0 0 0
`

func TestTheCountersAreReadFromTheirTables(t *testing.T) {
	if n, ok := parseSNMP(snmp); !ok || n != 29565 {
		t.Fatalf("Udp RcvbufErrors = %d %v, want 29565", n, ok)
	}
	if n, ok := parseSNMP6("Udp6InDatagrams \t 5\nUdp6RcvbufErrors                \t41\nUdpLite6RcvbufErrors 3\n"); !ok || n != 41 {
		t.Fatalf("Udp6RcvbufErrors = %d %v, want 41", n, ok)
	}
	for _, bad := range []string{"", "Udp: InDatagrams\n", "Udp: RcvbufErrors\nUdp: x\n", "UdpLite: RcvbufErrors\nUdpLite: 5\n"} {
		if n, ok := parseSNMP(bad); ok {
			t.Fatalf("%q parsed as %d", bad, n)
		}
	}
}
