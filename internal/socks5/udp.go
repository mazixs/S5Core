package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ParseUDPHeader parses a SOCKS5 UDP request header (RFC 1928, Section 7)
// It returns the header length (to strip it), the destination AddrSpec, and an error.
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

	// Fragment Number (FRAG) currently unsupported (only handle unfragmented 0x00)
	// Some non-compliant clients send garbage here, so we just ignore it instead of erroring out.
	// We still treat it as a single packet.

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

// BuildUDPHeader constructs a SOCKS5 UDP header (RFC 1928, Section 7)
// to prepend to a UDP packet.
func BuildUDPHeader(src *AddrSpec, data []byte) []byte {
	var atyp byte
	var addrLen int

	if src.FQDN != "" {
		atyp = fqdnAddress
		addrLen = 1 + len(src.FQDN)
	} else if ip := src.IP.To4(); ip != nil {
		atyp = ipv4Address
		addrLen = net.IPv4len
		src.IP = ip // Ensure 4-byte representation
	} else if ip := src.IP.To16(); ip != nil {
		atyp = ipv6Address
		addrLen = net.IPv6len
		src.IP = ip
	} else {
		// Fallback to empty IPv4
		atyp = ipv4Address
		addrLen = net.IPv4len
		src.IP = net.IPv4zero
	}

	// RSV(2) + FRAG(1) + ATYP(1) + ADDR(?) + PORT(2) + DATA
	headerLen := 4 + addrLen + 2
	out := make([]byte, headerLen+len(data))

	// RSV(2) + FRAG(1)
	out[0] = 0x00
	out[1] = 0x00
	out[2] = 0x00

	// ATYP
	out[3] = atyp
	pos := 4

	// ADDR
	if atyp == fqdnAddress {
		out[pos] = byte(len(src.FQDN))
		pos++
		copy(out[pos:], src.FQDN)
		pos += len(src.FQDN)
	} else {
		copy(out[pos:], src.IP)
		pos += len(src.IP)
	}

	// PORT
	binary.BigEndian.PutUint16(out[pos:], uint16(src.Port))
	pos += 2

	// DATA
	copy(out[pos:], data)

	return out
}
