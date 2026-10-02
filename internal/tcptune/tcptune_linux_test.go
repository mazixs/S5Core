package tcptune

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const tcpRTOMaxMS = 44 // TCP_RTO_MAX_MS, not in golang.org/x/sys yet

func readOpt(t *testing.T, conn *net.TCPConn, opt int) (int, error) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt) })
	return v, gerr
}

// The values are written here, not taken from the table, so that a changed
// or dropped row is a failure. Linux 2.6.34 and later all have thin
// timeouts; only the floor (6.15) may be refused.
func TestTheTunnelSocketGetsItsOptions(t *testing.T) {
	c, _ := tcpPair(t)
	skipped, err := ForDatagrams(netConnWrapper{c})
	if err != nil {
		t.Fatal(err)
	}
	if why, ok := skipped["TCP_THIN_LINEAR_TIMEOUTS"]; ok {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS refused: %v", why)
	}
	if got, err := readOpt(t, c, unix.TCP_THIN_LINEAR_TIMEOUTS); err != nil || got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS = %d (%v), want 1", got, err)
	}
	if why, ok := skipped["TCP_RTO_MIN_US"]; ok {
		t.Logf("TCP_RTO_MIN_US: the kernel refused it (%v), which is allowed", why)
		return
	}
	got, err := readOpt(t, c, tcpRTOMinUS)
	// The kernel keeps the floor in jiffies; a tick is at most 10 ms.
	if err != nil || got < 10_000 || got > 30_000 {
		t.Fatalf("TCP_RTO_MIN_US = %d (%v), want 20000", got, err)
	}
}

func TestTheOtherEndIsNotTouched(t *testing.T) {
	c, s := tcpPair(t)
	if _, err := ForDatagrams(c); err != nil {
		t.Fatal(err)
	}
	if got, _ := readOpt(t, s, unix.TCP_THIN_LINEAR_TIMEOUTS); got != 0 {
		t.Fatalf("the peer's socket has thin timeouts %d; only the tuned one should", got)
	}
}

// An option read back is not yet a timer that moved. After a few round trips
// on loopback the tuned end's RTO sits at its floor, well below the untuned
// end's. The base is measured, not assumed to be 200 ms: a host sysctl
// (net.ipv4.tcp_rto_min_us) or a route's rto_min lowers it for both ends. The
// accepted end is the tuned one here, as on the server.
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
	base, tuned := rto(c), rto(s)
	if base < 100*time.Millisecond {
		t.Skipf("the untuned end already has RTO %v: this host lowers the floor for every socket", base)
	}
	if tuned*2 > base {
		t.Fatalf("tuned end: RTO %v, untuned %v; want the tuned one near the 20 ms floor", tuned, base)
	}
}

// The tuning changes how soon TCP retransmits, not how long it keeps trying.
// From the cap of the timer and the user timeout the kernel derives when it
// closes a retransmitting connection with ETIMEDOUT, so the tuned socket must
// keep the values of an untuned one.
func TestTheTunedSocketGivesUpNoSooner(t *testing.T) {
	c, s := tcpPair(t)
	if _, err := ForDatagrams(s); err != nil {
		t.Fatal(err)
	}
	for _, o := range []struct {
		name string
		opt  int
	}{{"TCP_RTO_MAX_MS", tcpRTOMaxMS}, {"TCP_USER_TIMEOUT", unix.TCP_USER_TIMEOUT}} {
		want, err := readOpt(t, c, o.opt)
		if err != nil {
			t.Logf("%s: the kernel does not have it (%v)", o.name, err)
			continue
		}
		if got, _ := readOpt(t, s, o.opt); got != want {
			t.Fatalf("%s = %d on the tuned socket, %d on an untuned one", o.name, got, want)
		}
	}
}

func TestTheTunerSaysTheSocketIsClosed(t *testing.T) {
	c, _ := tcpPair(t)
	_ = c.Close()
	var log bytes.Buffer
	Tuner(debugLogger(&log))(c)
	if out := log.String(); !strings.Contains(out, "could not tune the socket") || !strings.Contains(out, "use of closed network connection") {
		t.Fatalf("log: %q", out)
	}
}

func TestAStreamIsClosedWhenNothingIsAcknowledged(t *testing.T) {
	c, _ := tcpPair(t)
	if err := ForStream(netConnWrapper{c}, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got, err := readOpt(t, c, unix.TCP_USER_TIMEOUT); err != nil || got != 500 {
		t.Fatalf("TCP_USER_TIMEOUT = %d (%v), want 500", got, err)
	}

	// The peer never reads, so its window closes. Linux 5.1 and newer counts
	// the time spent on a zero window against the option as well, which gets
	// ETIMEDOUT without a path that loses segments: that needs root.
	werr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1<<20)
		for {
			if _, err := c.Write(buf); err != nil {
				werr <- err
				return
			}
		}
	}()
	select {
	case err := <-werr:
		if !errors.Is(err, syscall.ETIMEDOUT) {
			t.Fatalf("the stream ended with %v, want ETIMEDOUT", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a stream that nothing acknowledges was still open after 20 s")
	}
}
