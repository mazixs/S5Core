package stealth

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Level 4 of the checklist: not what the stream looks like, but what the
// receiving end can write down about the client that produced it.
//
// Levels 1-3 ask whether a censor blocks the first packet. They say nothing
// about the case where the packet is allowed through and recorded instead.
// Every TLS client announces a cipher list, an extension list and their order
// in the clear, and that tuple is stable per implementation: JA3 and JA4 are
// just hashes of it. A server, a CDN or a middlebox that keeps the hash can
// tell "Chrome" from "a Go program pretending to be Chrome" without breaking
// any encryption, and can do it on the first packet of the connection.
//
// This matters here because TLS_FINGERPRINT exists precisely to make the WSS
// transport indistinguishable from a browser. Nothing checked that it did:
// uTLS could stop matching the browser it names, or the code could quietly
// stop using uTLS at all, and every test in the repository would stay green.
// The functions below compute the same two hashes an observer computes, so
// the claim can be tested instead of assumed.

// ErrNotClientHello is returned when the bytes handed in are not a TLS
// handshake record carrying a ClientHello.
var ErrNotClientHello = errors.New("stealth: not a ClientHello")

// TLS extension numbers this file needs to know by name.
const (
	extServerName         uint16 = 0x0000
	extSupportedGroups    uint16 = 0x000a
	extECPointFormats     uint16 = 0x000b
	extSignatureAlgs      uint16 = 0x000d
	extALPN               uint16 = 0x0010
	extSupportedVersions  uint16 = 0x002b
	recordTypeHandshake   byte   = 0x16
	handshakeTypeClientHl byte   = 0x01
)

// ClientHello is the part of a TLS ClientHello an observer fingerprints. It
// deliberately keeps GREASE values out of every list: both JA3 and JA4 drop
// them, because they are random by design and would make the hash differ on
// every connection from the same client.
type ClientHello struct {
	// LegacyVersion is the version field of the handshake message itself,
	// which TLS 1.3 pins to 0x0303 and JA3 hashes anyway.
	LegacyVersion uint16
	// SupportedVersions is the extension list, highest first. Empty for a
	// client that predates TLS 1.3.
	SupportedVersions []uint16
	CipherSuites      []uint16
	// Extensions is in the order the client sent them, which is what JA3
	// hashes. JA4 sorts them instead, on the argument that the order is the
	// easy thing for a client to randomise.
	Extensions      []uint16
	SupportedGroups []uint16
	PointFormats    []uint8
	SignatureAlgs   []uint16
	ALPN            []string
	ServerName      string
	// HadGREASE records whether the client sent GREASE values at all. A
	// browser does; a plain Go client does not, so its absence is itself a
	// signature even after the hashes are matched.
	HadGREASE bool
}

// ParseClientHello reads one or more TLS records and returns the ClientHello
// they carry. Several records are accepted because a client is free to split
// the handshake message across them, and one that does is exactly the client
// worth measuring.
func ParseClientHello(raw []byte) (*ClientHello, error) {
	body, err := handshakeBody(raw)
	if err != nil {
		return nil, err
	}
	return parseHelloBody(body)
}

// handshakeBody strips the record layer and the handshake header, returning
// the ClientHello body.
func handshakeBody(raw []byte) ([]byte, error) {
	var handshake []byte
	for len(raw) > 0 {
		if len(raw) < 5 {
			return nil, fmt.Errorf("%w: %d bytes left, need a 5 byte record header", ErrNotClientHello, len(raw))
		}
		if raw[0] != recordTypeHandshake {
			return nil, fmt.Errorf("%w: record type 0x%02x", ErrNotClientHello, raw[0])
		}
		length := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+length {
			return nil, fmt.Errorf("%w: record claims %d bytes, %d present", ErrNotClientHello, length, len(raw)-5)
		}
		handshake = append(handshake, raw[5:5+length]...)
		raw = raw[5+length:]
	}
	if len(handshake) < 4 {
		return nil, fmt.Errorf("%w: handshake is %d bytes", ErrNotClientHello, len(handshake))
	}
	if handshake[0] != handshakeTypeClientHl {
		return nil, fmt.Errorf("%w: handshake type 0x%02x", ErrNotClientHello, handshake[0])
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+length {
		return nil, fmt.Errorf("%w: ClientHello claims %d bytes, %d present", ErrNotClientHello, length, len(handshake)-4)
	}
	return handshake[4 : 4+length], nil
}

func parseHelloBody(b []byte) (*ClientHello, error) {
	r := reader{b: b}
	h := &ClientHello{}

	var ok bool
	if h.LegacyVersion, ok = r.u16(); !ok {
		return nil, fmt.Errorf("%w: truncated at version", ErrNotClientHello)
	}
	if !r.skip(32) { // random
		return nil, fmt.Errorf("%w: truncated at random", ErrNotClientHello)
	}
	sessionID, ok := r.vector8()
	if !ok {
		return nil, fmt.Errorf("%w: truncated at session id", ErrNotClientHello)
	}
	_ = sessionID

	suites, ok := r.vector16()
	if !ok {
		return nil, fmt.Errorf("%w: truncated at cipher suites", ErrNotClientHello)
	}
	for i := 0; i+1 < len(suites); i += 2 {
		v := binary.BigEndian.Uint16(suites[i:])
		if isGREASE(v) {
			h.HadGREASE = true
			continue
		}
		h.CipherSuites = append(h.CipherSuites, v)
	}

	if _, ok = r.vector8(); !ok { // compression methods
		return nil, fmt.Errorf("%w: truncated at compression", ErrNotClientHello)
	}

	// Extensions are optional in the format, though not in practice.
	extBlock, ok := r.vector16()
	if !ok {
		return h, nil
	}
	er := reader{b: extBlock}
	for {
		extType, ok := er.u16()
		if !ok {
			break
		}
		data, ok := er.vector16()
		if !ok {
			break
		}
		if isGREASE(extType) {
			h.HadGREASE = true
			continue
		}
		h.Extensions = append(h.Extensions, extType)
		h.readExtension(extType, data)
	}
	return h, nil
}

func (h *ClientHello) readExtension(extType uint16, data []byte) {
	switch extType {
	case extServerName:
		h.ServerName = parseSNI(data)
	case extSupportedGroups:
		dr := reader{b: data}
		list, ok := dr.vector16()
		if !ok {
			return
		}
		for i := 0; i+1 < len(list); i += 2 {
			v := binary.BigEndian.Uint16(list[i:])
			if isGREASE(v) {
				h.HadGREASE = true
				continue
			}
			h.SupportedGroups = append(h.SupportedGroups, v)
		}
	case extECPointFormats:
		dr := reader{b: data}
		list, ok := dr.vector8()
		if !ok {
			return
		}
		h.PointFormats = append(h.PointFormats, list...)
	case extSignatureAlgs:
		dr := reader{b: data}
		list, ok := dr.vector16()
		if !ok {
			return
		}
		for i := 0; i+1 < len(list); i += 2 {
			v := binary.BigEndian.Uint16(list[i:])
			if isGREASE(v) {
				h.HadGREASE = true
				continue
			}
			h.SignatureAlgs = append(h.SignatureAlgs, v)
		}
	case extALPN:
		dr := reader{b: data}
		list, ok := dr.vector16()
		if !ok {
			return
		}
		lr := reader{b: list}
		for {
			proto, ok := lr.vector8()
			if !ok {
				break
			}
			h.ALPN = append(h.ALPN, string(proto))
		}
	case extSupportedVersions:
		dr := reader{b: data}
		list, ok := dr.vector8()
		if !ok {
			return
		}
		for i := 0; i+1 < len(list); i += 2 {
			v := binary.BigEndian.Uint16(list[i:])
			if isGREASE(v) {
				h.HadGREASE = true
				continue
			}
			h.SupportedVersions = append(h.SupportedVersions, v)
		}
	}
}

func parseSNI(data []byte) string {
	dr := reader{b: data}
	list, ok := dr.vector16()
	if !ok {
		return ""
	}
	lr := reader{b: list}
	for {
		nameType, ok := lr.u8()
		if !ok {
			return ""
		}
		name, ok := lr.vector16()
		if !ok {
			return ""
		}
		if nameType == 0 {
			return string(name)
		}
	}
}

// JA3String builds the pre-hash JA3 string:
//
//	version,ciphers,extensions,groups,point formats
//
// Note that the version is the legacy one from the handshake header, not the
// version actually negotiated. JA3 predates TLS 1.3, and every TLS 1.3 client
// therefore contributes the same 771 here - which is why JA3 alone stopped
// separating modern clients well, and why JA4 exists.
func (h *ClientHello) JA3String() string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(h.LegacyVersion)))
	sb.WriteByte(',')
	sb.WriteString(joinU16(h.CipherSuites, "-"))
	sb.WriteByte(',')
	sb.WriteString(joinU16(h.Extensions, "-"))
	sb.WriteByte(',')
	sb.WriteString(joinU16(h.SupportedGroups, "-"))
	sb.WriteByte(',')
	parts := make([]string, 0, len(h.PointFormats))
	for _, p := range h.PointFormats {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	sb.WriteString(strings.Join(parts, "-"))
	return sb.String()
}

// JA3 returns the MD5 of the JA3 string. MD5 is not a security choice here -
// it is what every JA3 implementation uses, and a different hash would not be
// comparable with anyone else's records.
func (h *ClientHello) JA3() string {
	sum := md5.Sum([]byte(h.JA3String())) //nolint:gosec // JA3 is defined as MD5; this is an identifier, not a MAC.
	return hex.EncodeToString(sum[:])
}

// JA4 returns the JA4 fingerprint of the hello: a_b_c, where a is readable
// metadata, b hashes the sorted cipher list and c hashes the sorted extension
// list together with the signature algorithms.
//
// Sorting is the point of the format. JA3 hashes the order the client chose,
// so a client that shuffles its extension list - as Chrome does - produces a
// different JA3 on every connection while remaining perfectly recognisable.
func (h *ClientHello) JA4() string {
	return strings.Join([]string{h.ja4a(), h.ja4b(), h.ja4c()}, "_")
}

func (h *ClientHello) ja4a() string {
	var sb strings.Builder
	sb.WriteByte('t') // TCP; 'q' would mean QUIC, which this code never sees.
	sb.WriteString(ja4Version(h.effectiveVersion()))
	if h.ServerName != "" {
		sb.WriteByte('d')
	} else {
		sb.WriteByte('i')
	}
	sb.WriteString(twoDigits(len(h.CipherSuites)))
	sb.WriteString(twoDigits(len(h.Extensions)))
	sb.WriteString(ja4ALPN(h.ALPN))
	return sb.String()
}

func (h *ClientHello) ja4b() string {
	if len(h.CipherSuites) == 0 {
		return strings.Repeat("0", 12)
	}
	sorted := append([]uint16(nil), h.CipherSuites...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return truncatedSHA256(joinHex16(sorted, ","))
}

func (h *ClientHello) ja4c() string {
	// SNI and ALPN are excluded from the hashed list: both are already
	// described by JA4_a, and both change with the destination rather than
	// with the client.
	filtered := make([]uint16, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		filtered = append(filtered, e)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })
	if len(filtered) == 0 && len(h.SignatureAlgs) == 0 {
		return strings.Repeat("0", 12)
	}
	s := joinHex16(filtered, ",")
	if len(h.SignatureAlgs) > 0 {
		// Signature algorithms keep the client's order on purpose: unlike the
		// extension list, browsers do not shuffle it.
		s += "_" + joinHex16(h.SignatureAlgs, ",")
	}
	return truncatedSHA256(s)
}

// effectiveVersion is the highest version the client is willing to speak,
// which after TLS 1.3 lives in an extension rather than in the header.
func (h *ClientHello) effectiveVersion() uint16 {
	best := h.LegacyVersion
	for _, v := range h.SupportedVersions {
		if v > best {
			best = v
		}
	}
	return best
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

// ja4ALPN takes the first and last character of the first offered protocol:
// "h2" stays "h2", "http/1.1" becomes "h1". No ALPN at all is "00".
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	first := alpn[0]
	a, b := first[0], first[len(first)-1]
	if a < 0x20 || a > 0x7e || b < 0x20 || b > 0x7e {
		return hex.EncodeToString([]byte{a})[:1] + hex.EncodeToString([]byte{b})[:1]
	}
	return string([]byte{a, b})
}

func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func joinU16(v []uint16, sep string) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, sep)
}

func joinHex16(v []uint16, sep string) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, fmt.Sprintf("%04x", x))
	}
	return strings.Join(parts, sep)
}

// isGREASE reports whether a value is one of the sixteen reserved GREASE
// values (0x0a0a, 0x1a1a ... 0xfafa). Browsers send them to keep middleboxes
// honest about unknown values; both fingerprint formats drop them.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

// reader walks a byte slice without panicking on a truncated one, which is
// the normal case when the bytes come off a network from something hostile.
type reader struct{ b []byte }

func (r *reader) u8() (uint8, bool) {
	if len(r.b) < 1 {
		return 0, false
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(r.b) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(r.b) < n {
		return false
	}
	r.b = r.b[n:]
	return true
}

func (r *reader) vector8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}

func (r *reader) vector16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}
