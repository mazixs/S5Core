package udpbuf

import (
	"net"
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
