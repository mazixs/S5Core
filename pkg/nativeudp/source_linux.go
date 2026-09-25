package nativeudp

import (
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// sourceFamily says which control message tells a hub on a wildcard address
// where a datagram was sent, and where its answer leaves from.
type sourceFamily int

const (
	sourceOff sourceFamily = iota
	source4
	source6
)

// sourceSpace holds either control message.
const sourceSpace = 64

// askForDestination turns on the destination address of every datagram. A Go
// socket on a wildcard address is dual-stack, and there IPV6_PKTINFO covers
// IPv4 as well, with the address v4-mapped; IP_PKTINFO is for a socket that
// is IPv4 only.
func askForDestination(c *net.UDPConn) sourceFamily {
	raw, err := c.SyscallConn()
	if err != nil {
		return sourceOff
	}
	family := sourceOff
	_ = raw.Control(func(fd uintptr) {
		if unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1) == nil {
			family = source6
		} else if unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1) == nil {
			family = source4
		}
	})
	return family
}

func destinationOf(oob []byte) (netip.Addr, bool) {
	for len(oob) > 0 {
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			break
		}
		switch {
		case h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO && len(data) >= unix.SizeofInet6Pktinfo:
			return netip.AddrFrom16([16]byte(data[:16])), true
		case h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) >= unix.SizeofInet4Pktinfo:
			// ipi_spec_dst, the local address, which for a broadcast is the
			// interface's rather than the broadcast address.
			return netip.AddrFrom4([4]byte(data[4:8])), true
		}
		oob = rest
	}
	return netip.Addr{}, false
}

// sourceControl sends a datagram from src. The interface is left to the
// routing table, so policy routing still chooses the way out.
func sourceControl(family sourceFamily, src netip.Addr) []byte {
	switch family {
	case source6:
		return unix.PktInfo6(&unix.Inet6Pktinfo{Addr: src.As16()})
	case source4:
		if src.Unmap().Is4() {
			return unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: src.Unmap().As4()})
		}
	}
	return nil
}

func readFrom(c *net.UDPConn, b, oob []byte) (int, int, netip.AddrPort, error) {
	n, oobn, _, peer, err := c.ReadMsgUDPAddrPort(b, oob)
	return n, oobn, peer, err
}

func writeTo(c *net.UDPConn, b, oob []byte, peer netip.AddrPort) error {
	_, _, err := c.WriteMsgUDPAddrPort(b, oob, peer)
	return err
}
