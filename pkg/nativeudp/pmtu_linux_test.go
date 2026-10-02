package nativeudp

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func discovery(t *testing.T, c *net.UDPConn, level, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return v
}

// Both ends set DF and ignore the kernel's cache of the path's MTU: a
// datagram longer than the path is lost, not fragmented (docs/veil-spec.md,
// 10.7). A hub on a wildcard address carries both families, and takes both.
func TestNativeSocketsDoNotFragment(t *testing.T) {
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if got := discovery(t, hub.conn, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER); got != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("the hub on IPv4 discovers the MTU in mode %d", got)
	}
	client := dialHub(t, hub)
	if err := DontFragment(client); err != nil {
		t.Fatal(err)
	}
	if got := discovery(t, client, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER); got != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("the client discovers the MTU in mode %d", got)
	}
	wildcard, err := Listen(":0", nil)
	if err != nil {
		t.Skipf("no wildcard socket: %v", err)
	}
	defer wildcard.Close()
	if got := discovery(t, wildcard.conn, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER); got != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("the wildcard hub discovers the IPv4 MTU in mode %d", got)
	}
	if wildcard.conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
		if got := discovery(t, wildcard.conn, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER); got != unix.IPV6_PMTUDISC_PROBE {
			t.Fatalf("the wildcard hub discovers the IPv6 MTU in mode %d", got)
		}
	}
}
