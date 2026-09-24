package stealth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// cmd/fpcollect runs this parser on whatever a stranger sends it, so it is a
// parser of untrusted input like any other.

func appendVector8(b, v []byte) []byte { return append(append(b, byte(len(v))), v...) }
func appendVector16(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint16(b, uint16(len(v))), v...)
}

func appendU16s(b []byte, v []uint16) []byte {
	for _, x := range v {
		b = binary.BigEndian.AppendUint16(b, x)
	}
	return b
}

// u16s reads pairs of bytes as values, at most limit of them.
func u16s(b []byte, limit int) []uint16 {
	var out []uint16
	for i := 0; i+1 < len(b) && len(out) < limit; i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}

func dropGREASE(v []uint16) ([]uint16, bool) {
	var out []uint16
	had := false
	for _, x := range v {
		if isGREASE(x) {
			had = true
			continue
		}
		out = append(out, x)
	}
	return out, had
}

// asRecords wraps a handshake message in TLS records of at most size bytes.
func asRecords(msg []byte, size int) []byte {
	size = max(1, min(size, 16384))
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, recordTypeHandshake, 0x03, 0x01)
		out = appendVector16(out, msg[:n])
		msg = msg[n:]
	}
	return out
}

// recordPayloads is the handshake stream of records ParseClientHello
// accepted.
func recordPayloads(raw []byte) []byte {
	var msg []byte
	for len(raw) >= 5 {
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		msg = append(msg, raw[5:5+n]...)
		raw = raw[5+n:]
	}
	return msg
}

func helloMessage(body []byte) []byte {
	msg := []byte{handshakeTypeClientHl, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

func sameHello(a, b *ClientHello) bool {
	return a.LegacyVersion == b.LegacyVersion && slices.Equal(a.SupportedVersions, b.SupportedVersions) &&
		slices.Equal(a.CipherSuites, b.CipherSuites) && slices.Equal(a.Extensions, b.Extensions) &&
		slices.Equal(a.SupportedGroups, b.SupportedGroups) && bytes.Equal(a.PointFormats, b.PointFormats) &&
		slices.Equal(a.SignatureAlgs, b.SignatureAlgs) && slices.Equal(a.ALPN, b.ALPN) &&
		a.ServerName == b.ServerName && a.HadGREASE == b.HadGREASE
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// checkFingerprints holds JA3 and JA4 to their format: JA3 is an MD5 in hex
// over five comma-separated fields; JA4 is 36 characters, a_b_c, with a the
// readable part that agrees with the hello and b and c twelve hex digits of
// a hash. Neither keeps a GREASE value, and JA4 does not change when the
// client reorders its ciphers and extensions.
func checkFingerprints(t *testing.T, h *ClientHello) {
	t.Helper()
	for _, list := range [][]uint16{h.CipherSuites, h.Extensions, h.SupportedGroups, h.SignatureAlgs, h.SupportedVersions} {
		for _, v := range list {
			if isGREASE(v) {
				t.Fatalf("a GREASE value %#04x was kept", v)
			}
		}
	}
	if ja3 := h.JA3(); len(ja3) != 32 || !isLowerHex(ja3) {
		t.Fatalf("JA3 %q is not an MD5 in hex", ja3)
	}
	if n := bytes.Count([]byte(h.JA3String()), []byte(",")); n != 4 {
		t.Fatalf("JA3 string %q has %d fields", h.JA3String(), n+1)
	}

	ja4 := h.JA4()
	if len(ja4) != 36 || ja4[10] != '_' || ja4[23] != '_' || !isLowerHex(ja4[11:23]) || !isLowerHex(ja4[24:]) {
		t.Fatalf("JA4 %q is not a_b_c", ja4)
	}
	a := ja4[:10]
	sni := byte('i')
	if h.ServerName != "" {
		sni = 'd'
	}
	if a[0] != 't' || !slices.Contains([]string{"13", "12", "11", "10", "s3", "00"}, a[1:3]) || a[3] != sni ||
		a[4:6] != twoDigits(len(h.CipherSuites)) || a[6:8] != twoDigits(len(h.Extensions)) {
		t.Fatalf("JA4_a %q does not describe the hello", a)
	}
	for i := 8; i < 10; i++ {
		if a[i] < 0x20 || a[i] > 0x7e {
			t.Fatalf("JA4_a %q carries a byte that is not printable", a)
		}
	}

	shuffled := *h
	shuffled.CipherSuites = slices.Clone(h.CipherSuites)
	shuffled.Extensions = slices.Clone(h.Extensions)
	slices.Reverse(shuffled.CipherSuites)
	slices.Reverse(shuffled.Extensions)
	if shuffled.JA4() != ja4 {
		t.Fatalf("JA4 depends on the order of the ciphers or the extensions")
	}
}

// FuzzParseClientHello reads arbitrary bytes as TLS records:
//   - a refusal is ErrNotClientHello and returns no hello;
//   - an accepted hello has well-formed fingerprints (checkFingerprints) and
//     the same bytes always give the same hello;
//   - the handshake message cut into records of another size parses to the
//     same hello - the record boundary is the client's choice, not part of
//     what it is.
func FuzzParseClientHello(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "hello-*.bin"))
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, uint16(512))
		f.Add(raw[:len(raw)/2], uint16(1))
	}
	f.Add(asRecords(helloMessage(make([]byte, 2+32+1+2+1)), 3), uint16(7))
	f.Add([]byte{recordTypeHandshake, 3, 1, 0, 0}, uint16(1))
	f.Add([]byte{0x17, 3, 3, 0, 0}, uint16(1))
	f.Add([]byte{}, uint16(0))

	f.Fuzz(func(t *testing.T, raw []byte, size uint16) {
		h, err := ParseClientHello(raw)
		if err != nil {
			if !errors.Is(err, ErrNotClientHello) || h != nil {
				t.Fatalf("a refusal returned %v and %+v", err, h)
			}
			return
		}
		checkFingerprints(t, h)
		again, err := ParseClientHello(raw)
		if err != nil || !sameHello(h, again) || again.JA3() != h.JA3() || again.JA4() != h.JA4() {
			t.Fatalf("the same bytes parsed twice differently")
		}
		resplit, err := ParseClientHello(asRecords(recordPayloads(raw), int(size)))
		if err != nil || !sameHello(h, resplit) {
			t.Fatalf("records of %d bytes gave %+v (err=%v), want %+v", size, resplit, err, h)
		}
	})
}

// FuzzClientHelloRoundTrip builds a ClientHello from fuzzed lists, with GREASE
// values wherever the fuzzer puts them, and checks that the parser reads back
// exactly what was encoded: every list in order and without GREASE, the
// extensions in the order sent, and HadGREASE set exactly when one was sent.
func FuzzClientHelloRoundTrip(f *testing.F) {
	all := []byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x2b, 0x00, 0x17}
	f.Add(uint16(0x0303), []byte{0x13, 0x01, 0x0a, 0x0a, 0xc0, 0x2b}, all, []byte{0x00, 0x1d, 0x00, 0x17}, []byte{0x04, 0x03},
		[]byte{0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03}, []byte{0}, "h2,http/1.1", "example.com", uint16(100))
	f.Add(uint16(0x0301), []byte{}, []byte{0x0a, 0x0a}, []byte{}, []byte{}, []byte{}, []byte{}, "", "", uint16(1))
	f.Add(uint16(0), []byte{0xff}, []byte{0x00, 0x10}, []byte{}, []byte{}, []byte{}, []byte{}, "\x01\xff", "", uint16(16384))

	f.Fuzz(func(t *testing.T, version uint16, suitesRaw, extsRaw, groupsRaw, sigRaw, versionsRaw, points []byte, alpnRaw, sni string, size uint16) {
		want := &ClientHello{LegacyVersion: version}
		var had bool
		suites := u16s(suitesRaw, 64)
		want.CipherSuites, had = dropGREASE(suites)
		want.HadGREASE = had

		body := binary.BigEndian.AppendUint16(nil, version)
		body = append(body, make([]byte, 32)...)
		body = appendVector8(body, []byte("session"))
		body = appendVector16(body, appendU16s(nil, suites))
		body = appendVector8(body, []byte{0})

		var exts []byte
		seen := map[uint16]bool{}
		for _, typ := range u16s(extsRaw, 32) {
			if seen[typ] {
				continue
			}
			seen[typ] = true
			exts = binary.BigEndian.AppendUint16(exts, typ)
			if isGREASE(typ) {
				exts = appendVector16(exts, nil)
				want.HadGREASE = true
				continue
			}
			want.Extensions = append(want.Extensions, typ)
			var data []byte
			switch typ {
			case extServerName:
				name := []byte(sni)[:min(len(sni), 255)]
				want.ServerName = string(name)
				data = appendVector16(nil, appendVector16([]byte{0}, name))
			case extSupportedGroups:
				v := u16s(groupsRaw, 64)
				data = appendVector16(nil, appendU16s(nil, v))
				want.SupportedGroups, had = dropGREASE(v)
				want.HadGREASE = want.HadGREASE || had
			case extECPointFormats:
				want.PointFormats = points[:min(len(points), 255)]
				data = appendVector8(nil, want.PointFormats)
			case extSignatureAlgs:
				v := u16s(sigRaw, 64)
				data = appendVector16(nil, appendU16s(nil, v))
				want.SignatureAlgs, had = dropGREASE(v)
				want.HadGREASE = want.HadGREASE || had
			case extALPN:
				var list []byte
				for _, p := range bytes.Split([]byte(alpnRaw[:min(len(alpnRaw), 1024)]), []byte(",")) {
					p = p[:min(len(p), 255)]
					list = appendVector8(list, p)
					want.ALPN = append(want.ALPN, string(p))
				}
				data = appendVector16(nil, list)
			case extSupportedVersions:
				v := u16s(versionsRaw, 64)
				data = appendVector8(nil, appendU16s(nil, v))
				want.SupportedVersions, had = dropGREASE(v)
				want.HadGREASE = want.HadGREASE || had
			default:
				data = []byte("opaque")
			}
			exts = appendVector16(exts, data)
		}
		body = appendVector16(body, exts)

		got, err := ParseClientHello(asRecords(helloMessage(body), int(size)))
		if err != nil {
			t.Fatalf("the parser refused an encoded hello: %v", err)
		}
		if !sameHello(got, want) {
			t.Fatalf("encoded %+v, parsed %+v", want, got)
		}
		checkFingerprints(t, got)
	})
}
