package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// headerChecks read each form's header back as the protocol it claims to be.
// i is the datagram's place in its flow, counting from zero.
var headerChecks = map[string]func(t *testing.T, p []byte, i int, f *flow){
	"random": func(*testing.T, []byte, int, *flow) {},
	"quic-initial": func(t *testing.T, p []byte, _ int, f *flow) {
		if p[0]&0xf0 != 0xc0 {
			t.Errorf("first byte %#x is not a long header Initial", p[0])
		}
		if v := binary.BigEndian.Uint32(p[1:]); v != 1 {
			t.Errorf("version %#x", v)
		}
		if p[5] != 8 || !bytes.Equal(p[6:14], f.cid[:]) || p[14] != 8 || !bytes.Equal(p[15:23], f.scid[:]) {
			t.Errorf("connection ids % x / % x", p[5:14], p[14:23])
		}
		if p[23] != 0 {
			t.Errorf("token length %d", p[23])
		}
		length, n := quicVarint(p[24:])
		if 24+n+length != len(p) {
			t.Errorf("length %d does not cover the %d bytes after it", length, len(p)-24-n)
		}
	},
	"quic-short": func(t *testing.T, p []byte, _ int, f *flow) {
		if p[0]&0xc0 != 0x40 {
			t.Errorf("first byte %#x is not a short header with the fixed bit", p[0])
		}
		if !bytes.Equal(p[1:9], f.cid[:]) {
			t.Errorf("dcid % x is not the flow's", p[1:9])
		}
	},
	"dtls": func(t *testing.T, p []byte, i int, _ *flow) {
		if !bytes.Equal(p[:5], []byte{23, 0xfe, 0xfd, 0, 1}) {
			t.Errorf("record header % x", p[:5])
		}
		if seq := uint48(p[5:]); seq != uint64(i+1) {
			t.Errorf("sequence %d, want %d", seq, i+1)
		}
		if l := binary.BigEndian.Uint16(p[11:]); int(l) != len(p)-13 {
			t.Errorf("record length %d, want %d", l, len(p)-13)
		}
	},
	"dtls-hello": func(t *testing.T, p []byte, _ int, _ *flow) {
		if !bytes.Equal(p[:11], []byte{22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}) {
			t.Errorf("record header % x", p[:11])
		}
		if l := binary.BigEndian.Uint16(p[11:]); int(l) != len(p)-13 {
			t.Errorf("record length %d, want %d", l, len(p)-13)
		}
		if p[13] != 1 {
			t.Errorf("handshake type %d, want client_hello", p[13])
		}
		if l, fl := uint24(p[14:]), uint24(p[22:]); l != len(p)-25 || fl != l {
			t.Errorf("handshake length %d, fragment length %d, want %d", l, fl, len(p)-25)
		}
		if !bytes.Equal(p[17:22], make([]byte, 5)) {
			t.Errorf("message seq and fragment offset % x", p[17:22])
		}
	},
	"stun": func(t *testing.T, p []byte, _ int, _ *flow) {
		if typ := binary.BigEndian.Uint16(p); typ != 0x0001 {
			t.Errorf("type %#04x", typ)
		}
		if l := binary.BigEndian.Uint16(p[2:]); int(l) != len(p)-20 || l%4 != 0 {
			t.Errorf("length %d for %d bytes", l, len(p))
		}
		if c := binary.BigEndian.Uint32(p[4:]); c != 0x2112a442 {
			t.Errorf("cookie %#x", c)
		}
	},
	"wg": func(t *testing.T, p []byte, i int, f *flow) {
		if !bytes.Equal(p[:4], []byte{4, 0, 0, 0}) {
			t.Errorf("type and reserved % x", p[:4])
		}
		if !bytes.Equal(p[4:8], f.cid[:4]) {
			t.Errorf("receiver % x is not the flow's", p[4:8])
		}
		if c := binary.LittleEndian.Uint64(p[8:]); c != uint64(i) {
			t.Errorf("counter %d, want %d", c, i)
		}
	},
}

func TestEveryFormBuildsItsHeaderAndATrailer(t *testing.T) {
	if len(headerChecks) != len(forms) {
		t.Fatalf("%d header checks for %d forms", len(headerChecks), len(forms))
	}
	for _, fm := range forms {
		check := headerChecks[fm.name]
		for _, want := range []int{fm.min, fm.min + 3, 1200, 1472, 20000, maxDatagram} {
			if want < fm.min {
				continue
			}
			size, err := fm.wire(want)
			if err != nil {
				t.Fatalf("%s@%d: %v", fm.name, want, err)
			}
			fl := newFlow()
			token := [8]byte{1, 2, 3, 4, 5, 6, 7, fm.id}
			for i := range 3 {
				p := make([]byte, size)
				st := fl.next()
				fm.build(p, &st, nil, trailer{token: token, form: fm.id, seq: uint32(i)})
				check(t, p, i, fl)
				got, ok := readTrailer(p)
				if !ok || got.token != token || got.form != fm.id || got.reply || got.seq != uint32(i) || got.count != 0 {
					t.Errorf("%s@%d: trailer read back as %+v, %v", fm.name, size, got, ok)
				}
			}
		}
	}
}

// A reply takes the answering side of the protocol, with the same size.
func TestRepliesAnswerTheirRequest(t *testing.T) {
	build := func(name string, req []byte) []byte {
		fm := formByName(name)
		p := make([]byte, 1200)
		fm.build(p, newFlow(), req, trailer{form: fm.id, reply: req != nil})
		return p
	}
	req := build("stun", nil)
	rep := build("stun", req)
	if typ := binary.BigEndian.Uint16(rep); typ != 0x0101 || !bytes.Equal(rep[8:20], req[8:20]) {
		t.Errorf("stun reply type %#04x, transaction % x for % x", typ, rep[8:20], req[8:20])
	}
	if rep := build("dtls-hello", build("dtls-hello", nil)); rep[13] != 3 {
		t.Errorf("dtls-hello reply is handshake type %d, want hello_verify_request", rep[13])
	}
	req = build("quic-initial", nil)
	if rep := build("quic-initial", req); !bytes.Equal(rep[6:14], req[15:23]) {
		t.Errorf("quic-initial reply dcid % x, want the request's scid % x", rep[6:14], req[15:23])
	}
}

func TestSizesAreCheckedPerForm(t *testing.T) {
	tests := []struct {
		form      string
		size, got int
	}{
		{"quic-initial", 1199, 0},
		{"quic-initial", 1200, 1200},
		{"random", 23, 0},
		{"random", 24, 24},
		{"stun", 43, 0},
		{"stun", 1201, 1200},
		{"stun", 1203, 1200},
		{"stun", 1204, 1204},
		{"wg", 39, 0},
		{"dtls", maxDatagram + 1, 0},
	}
	for _, tt := range tests {
		got, err := formByName(tt.form).wire(tt.size)
		if tt.got == 0 && err == nil {
			t.Errorf("%s@%d accepted as %d", tt.form, tt.size, got)
		}
		if tt.got != 0 && (err != nil || got != tt.got) {
			t.Errorf("%s@%d = %d, %v, want %d", tt.form, tt.size, got, err, tt.got)
		}
	}
}

// Masked, the trailer is as random as the tail around it: no byte of it is
// the same across datagrams that carry the same fields.
func TestTheTrailerHasNoConstantBytes(t *testing.T) {
	fm := formByName("random")
	var first [trailerLen]byte
	var varies [trailerLen]bool
	for i := range 64 {
		p := make([]byte, 64)
		fm.build(p, newFlow(), nil, trailer{token: [8]byte{9}, form: fm.id, seq: 7})
		tail := p[len(p)-trailerLen:]
		if i == 0 {
			copy(first[:], tail)
			continue
		}
		for j := range tail {
			varies[j] = varies[j] || tail[j] != first[j]
		}
	}
	for j, v := range varies {
		if !v {
			t.Errorf("trailer byte %d is constant", j-trailerLen)
		}
	}
}

func TestStrayDatagramsAreNotProbes(t *testing.T) {
	if _, ok := readTrailer(make([]byte, 1200)); ok {
		t.Error("zeros read as a probe")
	}
	if _, ok := readTrailer(make([]byte, trailerLen-1)); ok {
		t.Error("a short datagram read as a probe")
	}
	for range 2000 {
		p := make([]byte, 64)
		fill(p)
		if _, ok := readTrailer(p); ok {
			t.Fatalf("random bytes read as a probe: % x", p)
		}
	}
}

func TestFormIDsMatchTheTable(t *testing.T) {
	for i, fm := range forms {
		if formByID(fm.id) != fm || int(fm.id) != i+1 || formByName(fm.name) != fm {
			t.Errorf("%s: id %d at place %d", fm.name, fm.id, i)
		}
	}
	if formByID(0) != nil || formByID(byte(len(forms)+1)) != nil {
		t.Error("an unknown id names a form")
	}
}

func quicVarint(p []byte) (int, int) {
	n := 1 << (p[0] >> 6)
	v := int(p[0] & 0x3f)
	for _, b := range p[1:n] {
		v = v<<8 | int(b)
	}
	return v, n
}

func uint48(p []byte) uint64 {
	var b [8]byte
	copy(b[2:], p[:6])
	return binary.BigEndian.Uint64(b[:])
}

func uint24(p []byte) int {
	return int(p[0])<<16 | int(p[1])<<8 | int(p[2])
}
