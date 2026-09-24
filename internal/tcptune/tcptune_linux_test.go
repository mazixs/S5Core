package tcptune

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTheTunnelSocketGetsItsOptions(t *testing.T) {
	c, _ := tcpPair(t)
	skipped, err := ForDatagrams(netConnWrapper{c})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range options {
		if why, ok := skipped[o.name]; ok {
			t.Logf("%s: the kernel refused it (%v), which is allowed", o.name, why)
			continue
		}
		var got int
		var gerr error
		_ = raw.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, o.opt) })
		if gerr != nil {
			t.Fatalf("%s: read back: %v", o.name, gerr)
		}
		// The timer floor is kept in jiffies; a tick is at most 10 ms.
		if got != o.value && (o.opt != tcpRTOMinUS || got < o.value-10_000 || got > o.value+10_000) {
			t.Fatalf("%s = %d, want %d", o.name, got, o.value)
		}
	}
}

func TestTheOtherEndIsNotTouched(t *testing.T) {
	c, s := tcpPair(t)
	if _, err := ForDatagrams(c); err != nil {
		t.Fatal(err)
	}
	raw, _ := s.SyscallConn()
	var got int
	_ = raw.Control(func(fd uintptr) {
		got, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_THIN_LINEAR_TIMEOUTS)
	})
	if got != 0 {
		t.Fatalf("the peer's socket has thin timeouts %d; only the tuned one should", got)
	}
}

// An option read back is not yet a timer that moved. After a few round trips
// on loopback the tuned end's RTO sits at its floor and the other end's at
// the kernel's 200 ms. The accepted end is the tuned one here, as on the
// server.
func TestTheTimerFollowsTheFloor(t *testing.T) {
	c, s := tcpPair(t)
	skipped, err := ForDatagrams(s)
	if err != nil {
		t.Fatal(err)
	}
	if why, ok := skipped["TCP_RTO_MIN_US"]; ok {
		t.Skipf("the kernel has no timer floor option: %v", why)
	}
	b := []byte{0}
	for range 20 {
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
	rto := func(conn *net.TCPConn) time.Duration {
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var info *unix.TCPInfo
		var gerr error
		_ = raw.Control(func(fd uintptr) { info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
		if gerr != nil {
			t.Fatal(gerr)
		}
		return time.Duration(info.Rto) * time.Microsecond
	}
	if got := rto(s); got >= 100*time.Millisecond {
		t.Fatalf("tuned end: RTO %v, want near the 20 ms floor", got)
	}
	if got := rto(c); got < 200*time.Millisecond {
		t.Fatalf("untuned end: RTO %v, want the kernel's 200 ms or more", got)
	}
}

// The tuning changes how soon TCP retransmits, not how long it keeps trying.
// Both are read from the same options on Linux: the cap of the timer and the
// user timeout set the time after which the kernel closes the connection with
// ETIMEDOUT, so the tuned socket must keep the values of an untuned one.
func TestTheTunedSocketGivesUpNoSooner(t *testing.T) {
	c, s := tcpPair(t)
	if _, err := ForDatagrams(s); err != nil {
		t.Fatal(err)
	}
	read := func(conn *net.TCPConn, opt int) (int, error) {
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var v int
		var gerr error
		_ = raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt) })
		return v, gerr
	}
	for _, o := range []struct {
		name string
		opt  int
	}{{"TCP_RTO_MAX_MS", tcpRTOMaxMS}, {"TCP_USER_TIMEOUT", unix.TCP_USER_TIMEOUT}} {
		want, err := read(c, o.opt)
		if err != nil {
			t.Logf("%s: the kernel does not have it (%v)", o.name, err)
			continue
		}
		if got, _ := read(s, o.opt); got != want {
			t.Fatalf("%s = %d on the tuned socket, %d on an untuned one", o.name, got, want)
		}
	}
}
