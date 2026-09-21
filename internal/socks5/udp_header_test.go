package socks5

import (
	"bytes"
	"net"
	"testing"
)

// Plan task Ф6-5: the encoder used to normalise the address by writing back
// into the caller's AddrSpec. A datagram encoder that edits its argument is a
// surprise waiting for the first caller that reuses one.
func TestBuildingAHeaderDoesNotTouchTheAddress(t *testing.T) {
	cases := []struct {
		name string
		spec AddrSpec
	}{
		{"an IPv4 address in 16-byte form", AddrSpec{IP: net.ParseIP("192.0.2.9"), Port: 1080}},
		{"an IPv6 address", AddrSpec{IP: net.ParseIP("2001:db8::1"), Port: 1080}},
		{"a name", AddrSpec{FQDN: "example.com", Port: 443}},
		{"nothing at all", AddrSpec{Port: 53}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := append([]byte(nil), c.spec.IP...)
			spec := c.spec
			_ = BuildUDPHeader(&spec, []byte("payload"))
			// Byte for byte, not net.IP.Equal: what is under test is that
			// nothing was rewritten, and net.IP.Equal calls the 4-byte and
			// 16-byte forms of one address the same.
			if !bytes.Equal([]byte(spec.IP), before) {
				t.Fatalf("the encoder rewrote the address: %v became %v", before, spec.IP)
			}
			if spec.FQDN != c.spec.FQDN || spec.Port != c.spec.Port {
				t.Fatalf("the encoder changed %+v into %+v", c.spec, spec)
			}
		})
	}
}

// What is appended has to be what the parser reads back, for every address
// form - the client on the other side is our own parser.
func TestAHeaderRoundTrips(t *testing.T) {
	cases := []struct {
		name string
		spec AddrSpec
		want AddrSpec
	}{
		{
			name: "IPv4",
			spec: AddrSpec{IP: net.ParseIP("192.0.2.9"), Port: 1080},
			want: AddrSpec{IP: net.ParseIP("192.0.2.9").To4(), Port: 1080},
		},
		{
			name: "IPv6",
			spec: AddrSpec{IP: net.ParseIP("2001:db8::1"), Port: 4443},
			want: AddrSpec{IP: net.ParseIP("2001:db8::1").To16(), Port: 4443},
		},
		{
			name: "a name",
			spec: AddrSpec{FQDN: "example.com", Port: 443},
			want: AddrSpec{FQDN: "example.com", Port: 443},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := c.spec
			packet := BuildUDPHeader(&spec, []byte("payload"))
			n, got, err := ParseUDPHeader(packet)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !got.IP.Equal(c.want.IP) || got.FQDN != c.want.FQDN || got.Port != c.want.Port {
				t.Fatalf("read back %+v, want %+v", got, c.want)
			}
			if string(packet[n:]) != "payload" {
				t.Fatalf("the payload came back as %q", packet[n:])
			}
			if n != udpHeaderLen(&spec) {
				t.Fatalf("the header is %d bytes, but udpHeaderLen says %d", n, udpHeaderLen(&spec))
			}
		})
	}
}

// The relay appends into a buffer it already holds, so the encoder must not
// allocate. This is the property the UDP path depends on: one pooled buffer
// per datagram instead of a fresh one sized with the payload.
func TestAppendingAHeaderAllocatesNothing(t *testing.T) {
	buf := make([]byte, 0, 64*1024)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 1080}
	payload := bytes.Repeat([]byte("x"), 1200)

	allocs := testing.AllocsPerRun(100, func() {
		out := AppendUDPHeaderFromAddr(buf[:0], addr)
		out = append(out, payload...)
		if len(out) != 10+len(payload) {
			t.Fatalf("the datagram is %d bytes", len(out))
		}
	})
	if allocs != 0 {
		t.Fatalf("appending a header allocated %.1f times per datagram, want 0", allocs)
	}
}

func BenchmarkUDPHeader(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1200)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 1080}

	b.Run("build", func(b *testing.B) {
		spec := AddrSpec{IP: addr.IP, Port: addr.Port}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = BuildUDPHeader(&spec, payload)
		}
	})

	b.Run("append", func(b *testing.B) {
		buf := make([]byte, 0, 64*1024)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			out := AppendUDPHeaderFromAddr(buf[:0], addr)
			_ = append(out, payload...)
		}
	})
}
