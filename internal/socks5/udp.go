package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

// errFragmentedDatagram is what a datagram gets for asking to be reassembled.
// It is a named error because the UDP loops log it and the tests name it; the
// client sees nothing, because a dropped datagram is the RFC's answer.
var errFragmentedDatagram = fmt.Errorf("fragmented datagrams are not supported")

// ParseUDPHeader parses a SOCKS5 UDP request header (RFC 1928, Section 7)
// It returns the header length (to strip it), the destination AddrSpec, and an
// error. A datagram whose FRAG is not zero is an error: nothing here
// reassembles, so there is no whole datagram to forward.
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func ParseUDPHeader(payload []byte) (headerLen int, dstAddr *AddrSpec, err error) {
	if len(payload) < 4 {
		return 0, nil, fmt.Errorf("udp payload too short")
	}

	// Reserved MUST be 0x0000
	if payload[0] != 0x00 || payload[1] != 0x00 {
		return 0, nil, fmt.Errorf("invalid reserved bytes in udp header")
	}

	// FRAG is refused rather than ignored (audit finding F18). RFC 1928,
	// section 7: an implementation that does not reassemble MUST drop a
	// datagram whose FRAG is not zero, and this one does not reassemble.
	//
	// Ignoring it was a deliberate choice once, for clients that write
	// something other than zero there, and it was the wrong one: a fragment
	// is a piece of a datagram, so forwarding it sends the target a piece of
	// a message as though it were the whole of one. A DNS query cut in two
	// is not a shorter query, and the standby bit (0x80) is not a client
	// being sloppy - it asks for reassembly this server will never do.
	// Dropping it makes the client's own timeout report the truth.
	if payload[2] != 0x00 {
		return 0, nil, fmt.Errorf("%w: FRAG is %#x", errFragmentedDatagram, payload[2])
	}

	atyp := payload[3]
	addr := &AddrSpec{}
	headerLen = 4 // RSV(2) + FRAG(1) + ATYP(1)

	switch atyp {
	case ipv4Address:
		if len(payload) < headerLen+4+2 {
			return 0, nil, fmt.Errorf("udp payload too short for ipv4")
		}
		addr.IP = net.IP(payload[headerLen : headerLen+4])
		headerLen += 4
	case ipv6Address:
		if len(payload) < headerLen+16+2 {
			return 0, nil, fmt.Errorf("udp payload too short for ipv6")
		}
		addr.IP = net.IP(payload[headerLen : headerLen+16])
		headerLen += 16
	case fqdnAddress:
		if len(payload) < headerLen+1 {
			return 0, nil, fmt.Errorf("udp payload too short for domain length")
		}
		domainLen := int(payload[headerLen])
		if len(payload) < headerLen+1+domainLen+2 {
			return 0, nil, fmt.Errorf("udp payload too short for domain")
		}
		addr.FQDN = string(payload[headerLen+1 : headerLen+1+domainLen])
		headerLen += 1 + domainLen
	default:
		return 0, nil, errUnrecognizedAddrType
	}

	// Port
	addr.Port = int(binary.BigEndian.Uint16(payload[headerLen : headerLen+2]))
	headerLen += 2

	return headerLen, addr, nil
}

// udpHeaderLen is how many bytes the header for src takes: RSV(2) + FRAG(1)
// + ATYP(1) + address + PORT(2).
func udpHeaderLen(src *AddrSpec) int {
	switch {
	case src.FQDN != "":
		return 4 + 1 + len(src.FQDN) + 2
	case src.IP.To4() != nil:
		return 4 + net.IPv4len + 2
	case src.IP.To16() != nil:
		return 4 + net.IPv6len + 2
	default:
		return 4 + net.IPv4len + 2
	}
}

// AppendUDPHeader appends the SOCKS5 UDP header (RFC 1928, Section 7) for src
// to dst and returns the extended slice.
//
// It allocates nothing when dst has the room, and it does not modify src.
// Both mattered on the UDP path (plan task Ф6-5): the header used to be built
// into a fresh slice per datagram, sized with the payload, so a busy tunnel
// allocated up to 64 KiB per packet; and normalising the address to four
// bytes was done by writing back into the caller's AddrSpec, which is a
// datagram encoder reaching into its argument.
func AppendUDPHeader(dst []byte, src *AddrSpec) []byte {
	// RSV(2) + FRAG(1)
	dst = append(dst, 0x00, 0x00, 0x00)

	switch {
	case src.FQDN != "":
		dst = append(dst, fqdnAddress, byte(len(src.FQDN)))
		dst = append(dst, src.FQDN...)
	case src.IP.To4() != nil:
		dst = append(dst, ipv4Address)
		dst = append(dst, src.IP.To4()...)
	case src.IP.To16() != nil:
		dst = append(dst, ipv6Address)
		dst = append(dst, src.IP.To16()...)
	default:
		// An address that is neither is written as the zero IPv4 address,
		// which is what this encoder has always done.
		dst = append(dst, ipv4Address)
		dst = append(dst, net.IPv4zero.To4()...)
	}

	return binary.BigEndian.AppendUint16(dst, uint16(src.Port))
}

// AppendUDPHeaderFromAddr is AppendUDPHeader for a *net.UDPAddr, which is what
// the relay actually has. It exists to keep the relay from building an
// AddrSpec and a copy of the IP for every datagram, purely to describe an
// address it already holds.
func AppendUDPHeaderFromAddr(dst []byte, addr *net.UDPAddr) []byte {
	spec := AddrSpec{IP: addr.IP, Port: addr.Port}
	return AppendUDPHeader(dst, &spec)
}

// BuildUDPHeader constructs a SOCKS5 UDP header (RFC 1928, Section 7)
// and the datagram behind it, in one new slice.
func BuildUDPHeader(src *AddrSpec, data []byte) []byte {
	out := make([]byte, 0, udpHeaderLen(src)+len(data))
	out = AppendUDPHeader(out, src)
	return append(out, data...)
}
