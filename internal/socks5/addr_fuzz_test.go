package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// The address of a SOCKS5 message is read by two parsers: readAddrSpec for
// the TCP request and ParseUDPHeader for every datagram. They read the same
// encoding (RFC 1928, sections 5 and 7), and AppendAddr writes it for both.
// The targets below hold the three to one another.

// canonicalAddr reports whether AppendAddr writes back exactly the bytes the
// address was read from. Two spellings are not canonical: an empty name, which
// AppendAddr writes as 0.0.0.0 (it is neither a name nor an IP), and an
// IPv4-mapped IPv6 address, which it writes as IPv4.
func canonicalAddr(atyp byte, a *AddrSpec) bool {
	switch atyp {
	case fqdnAddress:
		return a.FQDN != ""
	case ipv6Address:
		return a.IP.To4() == nil
	}
	return true
}

// sameAddr compares two addresses the way the relay uses them: the name, the
// IP as an address rather than as a byte spelling, and the port. An address
// with neither a name nor an IP stands for 0.0.0.0, as AppendAddr writes it.
func sameAddr(a, b *AddrSpec) bool {
	ipA, ipB := a.IP, b.IP
	if a.FQDN == "" && ipA == nil {
		ipA = net.IPv4zero
	}
	if b.FQDN == "" && ipB == nil {
		ipB = net.IPv4zero
	}
	if a.FQDN != b.FQDN || a.Port != b.Port {
		return false
	}
	if a.FQDN != "" {
		return true
	}
	return ipA.Equal(ipB)
}

func addrSeeds() [][]byte {
	return [][]byte{
		AppendAddr(nil, &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 53}),
		AppendAddr(nil, &AddrSpec{IP: net.ParseIP("2001:db8::1"), Port: 443}),
		AppendAddr(nil, &AddrSpec{FQDN: "example.com", Port: 80}),
		AppendAddr(nil, &AddrSpec{FQDN: string(bytes.Repeat([]byte("a"), 255)), Port: 65535}),
		AppendAddr(nil, nil),
		{fqdnAddress, 0, 0, 80},
		{ipv6Address, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1, 0, 53},
		{fqdnAddress, 255},
		{ipv4Address, 1, 2, 3},
		{0x02},
		{},
	}
}

// FuzzParseUDPHeader holds the datagram header parser to its format:
//   - FRAG other than zero is always refused, and refused as a fragment;
//   - an accepted header is RSV=0, FRAG=0 and a length inside the datagram;
//   - AppendUDPHeader of the parsed address parses back to the same address,
//     with the header length AppendUDPHeader wrote, and to the very same bytes
//     when the input was spelled canonically;
//   - the payload behind the header is untouched by the round trip.
func FuzzParseUDPHeader(f *testing.F) {
	for _, addr := range addrSeeds() {
		f.Add(append([]byte{0, 0, 0}, append(addr, "payload"...)...))
	}
	f.Add([]byte{0, 0, 0x80, ipv4Address, 1, 2, 3, 4, 0, 53})
	f.Add([]byte{0, 1, 0, ipv4Address, 1, 2, 3, 4, 0, 53})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		hdrLen, addr, err := ParseUDPHeader(data)

		if len(data) >= 4 && data[0] == 0 && data[1] == 0 && data[2] != 0 {
			if !errors.Is(err, errFragmentedDatagram) {
				t.Fatalf("FRAG %#x was not refused as a fragment: err=%v", data[2], err)
			}
		}
		if err != nil {
			if addr != nil || hdrLen != 0 {
				t.Fatalf("a refusal returned (%d, %v)", hdrLen, addr)
			}
			return
		}

		if data[0] != 0 || data[1] != 0 || data[2] != 0 {
			t.Fatalf("accepted a header with RSV/FRAG %x", data[:3])
		}
		if hdrLen < 4+1+2 || hdrLen > len(data) {
			t.Fatalf("header length %d for a datagram of %d bytes", hdrLen, len(data))
		}
		if addr.FQDN != "" && addr.IP != nil {
			t.Fatalf("an address with both a name and an IP: %+v", addr)
		}

		payload := data[hdrLen:]
		enc := AppendUDPHeader(nil, addr)
		if len(enc) != udpHeaderLen(addr) {
			t.Fatalf("AppendUDPHeader wrote %d bytes, udpHeaderLen says %d", len(enc), udpHeaderLen(addr))
		}
		if canonicalAddr(data[3], addr) && !bytes.Equal(enc, data[:hdrLen]) {
			t.Fatalf("a canonical header did not re-encode to itself:\n in %x\nout %x", data[:hdrLen], enc)
		}

		again := BuildUDPHeader(addr, payload)
		hdrLen2, addr2, err := ParseUDPHeader(again)
		if err != nil {
			t.Fatalf("the re-encoded header %x was refused: %v", enc, err)
		}
		if hdrLen2 != len(enc) {
			t.Fatalf("the re-encoded header parsed as %d bytes, it is %d", hdrLen2, len(enc))
		}
		if !sameAddr(addr, addr2) {
			t.Fatalf("round trip changed the address: %+v -> %+v", addr, addr2)
		}
		if !bytes.Equal(again[hdrLen2:], payload) {
			t.Fatalf("round trip changed the payload")
		}
	})
}

// FuzzReadAddrSpec holds the request address reader to the datagram header
// parser: the same bytes behind RSV and FRAG must be accepted by both or by
// neither, name the same address and take the same length. It also checks
// that the reader stops at the end of the address, that an unknown ATYP is
// the only protocol error, and that a canonical address re-encodes to itself.
func FuzzReadAddrSpec(f *testing.F) {
	for _, addr := range addrSeeds() {
		f.Add(append(addr, "tail"...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		spec, err := readAddrSpec(r)
		consumed := len(data) - r.Len()

		hdrLen, udpAddr, udpErr := ParseUDPHeader(append([]byte{0, 0, 0}, data...))
		if (err == nil) != (udpErr == nil) {
			t.Fatalf("readAddrSpec err=%v, ParseUDPHeader err=%v on %x", err, udpErr, data)
		}

		if err != nil {
			unknown := len(data) > 0 && data[0] != ipv4Address && data[0] != ipv6Address && data[0] != fqdnAddress
			if errors.Is(err, errUnrecognizedAddrType) != unknown {
				t.Fatalf("ATYP %x: err=%v", data[:min(1, len(data))], err)
			}
			if !unknown && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("a short address failed with %v, want an EOF", err)
			}
			return
		}

		if consumed != hdrLen-3 {
			t.Fatalf("readAddrSpec took %d bytes, ParseUDPHeader %d", consumed, hdrLen-3)
		}
		if !sameAddr(spec, udpAddr) || spec.FQDN != udpAddr.FQDN {
			t.Fatalf("the parsers disagree: %+v and %+v", spec, udpAddr)
		}
		if canonicalAddr(data[0], spec) {
			if enc := AppendAddr(nil, spec); !bytes.Equal(enc, data[:consumed]) {
				t.Fatalf("a canonical address did not re-encode to itself:\n in %x\nout %x", data[:consumed], enc)
			}
		}
	})
}
