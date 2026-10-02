package nativeudp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// DontFragment sets DF on every datagram of c and has the kernel ignore what
// it learnt of the path's MTU: a datagram longer than the path is lost rather
// than fragmented, and the probes find the limit (docs/veil-spec.md, 10.7). A
// dual-stack socket takes both families, and only a refusal of both fails.
func DontFragment(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var v4, v6 error
	if err := rc.Control(func(fd uintptr) {
		v4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		v6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	}); err != nil {
		return err
	}
	if v4 != nil && v6 != nil {
		return errors.Join(v4, v6)
	}
	return nil
}
