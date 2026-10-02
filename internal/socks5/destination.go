package socks5

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// carrierGradeNAT is the shared address space of RFC 6598: a provider's inner
// network, and where some clouds keep their metadata service.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// nat64 is the well-known prefix of RFC 6052: the last four bytes are an IPv4
// address that a NAT64 gateway dials on the sender's behalf.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// privateDestination says whether ip is an address of the server's own
// machine or of the network behind it: loopback, link-local (the metadata
// service of a cloud is 169.254.169.254), unspecified, multicast, private
// (RFC 1918 and the unique local addresses of IPv6) and carrier-grade NAT,
// and the IPv4 address inside a NAT64 one. A client of a proxy has no
// business there unless the operator says so (Config.DenyPrivateDest,
// docs/plan/draft.md, Ч-27).
func privateDestination(ip netip.Addr) bool {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || carrierGradeNAT.Contains(ip)
}

// ownAddressesTTL is how long the list of the server's interface addresses is
// trusted: a server whose address changes is refused for at most this long.
const ownAddressesTTL = time.Minute

// ownAddresses is the addresses of the server's interfaces, which include its
// public one. A connection to it leaves by the loopback, where a firewall that
// guards the machine from outside usually lets it through to every service the
// machine runs.
type ownAddresses struct {
	read func() []netip.Addr
	snap atomic.Pointer[ownSnapshot]
}

type ownSnapshot struct {
	taken time.Time
	set   map[netip.Addr]struct{}
}

func newOwnAddresses() *ownAddresses { return &ownAddresses{read: interfaceAddresses} }

func interfaceAddresses() []netip.Addr {
	addrs, _ := net.InterfaceAddrs()
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func (o *ownAddresses) has(ip netip.Addr) bool {
	s := o.snap.Load()
	if s == nil || time.Since(s.taken) > ownAddressesTTL {
		addrs := o.read()
		s = &ownSnapshot{taken: time.Now(), set: make(map[netip.Addr]struct{}, len(addrs))}
		for _, a := range addrs {
			s.set[a] = struct{}{}
		}
		o.snap.Store(s)
	}
	_, ok := s.set[ip.Unmap()]
	return ok
}

// deniedDestination is privateDestination, or an address of the server
// itself, under the server's setting.
func (s *Server) deniedDestination(ip netip.Addr) bool {
	return s.config.DenyPrivateDest && (privateDestination(ip) || s.own.has(ip))
}

// refuseDatagram says whether a datagram to dest is dropped, and tells the
// log once per association (said) that the setting is why. A game that stops
// working after an upgrade has to find out from somewhere.
func (s *Server) refuseDatagram(dest netip.Addr, said *atomic.Bool) bool {
	if !s.deniedDestination(dest) {
		return false
	}
	if said.CompareAndSwap(false, true) {
		s.config.Logger.Info("socks: udp datagrams to the server's own network are dropped; ALLOW_PRIVATE_DEST=true allows them")
	}
	return true
}
