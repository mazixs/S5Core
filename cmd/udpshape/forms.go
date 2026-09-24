package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// maxDatagram is the largest UDP payload IPv4 carries.
const maxDatagram = 65507

// A datagram is a form header, random bytes, and a trailer. Only the header
// imitates a protocol; the trailer sits at a fixed offset from the end, so the
// server finds it without knowing the form.
//
//	form          id  header, from the first byte                          header  minimum
//	random        1   none                                                  0       24
//	quic-initial  2   first byte 0xC0-0xCF, version 1 (4), dcid len 8,     26      1200
//	                  dcid 8, scid len 8, scid 8, token len 0, length 2
//	                  (4 bytes and header 28 from 16410 bytes up)
//	quic-short    3   first byte 0x40-0x7F, dcid 8                          9       33
//	dtls          4   type 23, version FE FD, epoch 1 (2), seq 6, length 2  13      37
//	dtls-hello    5   record: type 22, version FE FF, epoch 0 (2), seq 0    25      49
//	                  (6), length 2; handshake: type 1, length 3, message
//	                  seq 0 (2), fragment offset 0 (3), fragment length 3
//	stun          6   type 0x0001 (2), length 2, cookie 0x2112A442 (4),     20      44
//	                  transaction id 12; size is 20 plus a multiple of 4
//	wg            7   type 4, reserved 0 (3), receiver 4, counter 8 (LE)    16      40
//
// Replies take the answering side of the same protocol where one exists: STUN
// Binding Success Response (0x0101) with the request's transaction id, DTLS
// HelloVerifyRequest (handshake type 3), and a QUIC Initial addressed to the
// request's scid.
//
// The trailer, by offset from the end of the datagram:
//
//	-24  nonce  4  random, in the clear
//	-20  token  8  one per test, chosen by the client
//	-12  form   1  form id from the table above
//	-11  flags  1  bit 0 set on replies
//	-10  seq    4  datagram number within the test, echoed by the reply
//	 -6  count  4  on replies: datagrams the server has counted for the token
//	 -2  check  2  trailerCheck, so stray datagrams are dropped
//
// The last 20 bytes are XORed with SHA-256 of the nonce: in the clear, a
// counter and a constant at a fixed distance from the end would be a shape
// of their own, and "random" would stop being random.
const (
	trailerLen   = 24
	trailerCheck = 0x5553
	flagReply    = 1
)

type trailer struct {
	token [8]byte
	form  byte
	reply bool
	seq   uint32
	count uint32
}

func putTrailer(p []byte, t trailer) {
	b := p[len(p)-trailerLen:]
	fill(b[:4])
	copy(b[4:12], t.token[:])
	b[12] = t.form
	b[13] = 0
	if t.reply {
		b[13] = flagReply
	}
	binary.BigEndian.PutUint32(b[14:], t.seq)
	binary.BigEndian.PutUint32(b[18:], t.count)
	binary.BigEndian.PutUint16(b[22:], trailerCheck)
	maskTrailer(b)
}

func readTrailer(p []byte) (trailer, bool) {
	if len(p) < trailerLen {
		return trailer{}, false
	}
	var b [trailerLen]byte
	copy(b[:], p[len(p)-trailerLen:])
	maskTrailer(b[:])
	if binary.BigEndian.Uint16(b[22:]) != trailerCheck || b[13]&^flagReply != 0 || formByID(b[12]) == nil {
		return trailer{}, false
	}
	t := trailer{
		form:  b[12],
		reply: b[13] == flagReply,
		seq:   binary.BigEndian.Uint32(b[14:]),
		count: binary.BigEndian.Uint32(b[18:]),
	}
	copy(t.token[:], b[4:12])
	return t, true
}

func maskTrailer(b []byte) {
	m := sha256.Sum256(b[:4])
	for i := 4; i < trailerLen; i++ {
		b[i] ^= m[i-4]
	}
}

// flow is what a sender keeps constant, or counts, across one flow.
type flow struct {
	cid  [8]byte // quic dcid; the wg receiver index is its first four bytes
	scid [8]byte
	n    uint64 // datagrams so far: the dtls sequence number, wg counter + 1
}

func newFlow() *flow {
	var f flow
	fill(f.cid[:])
	fill(f.scid[:])
	return &f
}

// next advances the flow and returns the state its next datagram is built with.
func (f *flow) next() flow {
	f.n++
	return *f
}

type form struct {
	id   byte
	name string
	min  int
	// head writes the header over random bytes; req is the request being
	// answered, nil on the client.
	head func(p []byte, f *flow, req []byte)
}

var forms = []*form{
	{id: 1, name: "random", min: trailerLen, head: func([]byte, *flow, []byte) {}},
	{id: 2, name: "quic-initial", min: 1200, head: quicInitial},
	{id: 3, name: "quic-short", min: 9 + trailerLen, head: quicShort},
	{id: 4, name: "dtls", min: 13 + trailerLen, head: dtlsData},
	{id: 5, name: "dtls-hello", min: 25 + trailerLen, head: dtlsHello},
	{id: 6, name: "stun", min: 20 + trailerLen, head: stun},
	{id: 7, name: "wg", min: 16 + trailerLen, head: wireguard},
}

func formByID(id byte) *form {
	if id == 0 || int(id) > len(forms) {
		return nil
	}
	return forms[id-1]
}

func formByName(name string) *form {
	for _, f := range forms {
		if f.name == name {
			return f
		}
	}
	return nil
}

func formNames() string {
	names := make([]string, len(forms))
	for i, f := range forms {
		names[i] = f.name
	}
	return strings.Join(names, ", ")
}

// wire is the datagram size the form uses for a requested size.
func (fm *form) wire(size int) (int, error) {
	if fm.name == "stun" && size >= 20 {
		size -= (size - 20) % 4
	}
	if size < fm.min {
		return 0, fmt.Errorf("%s needs at least %d bytes, %d asked", fm.name, fm.min, size)
	}
	if size > maxDatagram {
		return 0, fmt.Errorf("%d bytes is more than a UDP datagram carries (%d)", size, maxDatagram)
	}
	return size, nil
}

// build fills p, whose length is the wire size, with one datagram of the form.
func (fm *form) build(p []byte, f *flow, req []byte, t trailer) {
	fill(p)
	fm.head(p, f, req)
	putTrailer(p, t)
}

func quicInitial(p []byte, f *flow, req []byte) {
	// Header protection leaves the reserved and packet number length bits random.
	p[0] = 0xc0 | p[0]&0x0f
	binary.BigEndian.PutUint32(p[1:], 1)
	dcid, scid := f.cid[:], f.scid[:]
	if req != nil {
		dcid, scid = req[15:23], f.cid[:]
	}
	p[5] = 8
	copy(p[6:14], dcid)
	p[14] = 8
	copy(p[15:23], scid)
	p[23] = 0
	if rest := len(p) - 26; rest < 1<<14 {
		binary.BigEndian.PutUint16(p[24:], 0x4000|uint16(rest))
	} else {
		binary.BigEndian.PutUint32(p[24:], 0x8000_0000|uint32(len(p)-28))
	}
}

func quicShort(p []byte, f *flow, _ []byte) {
	p[0] = 0x40 | p[0]&0x3f
	copy(p[1:9], f.cid[:])
}

func dtlsData(p []byte, f *flow, _ []byte) {
	p[0], p[1], p[2] = 23, 0xfe, 0xfd
	binary.BigEndian.PutUint16(p[3:], 1)
	putUint48(p[5:], f.n)
	binary.BigEndian.PutUint16(p[11:], uint16(len(p)-13))
}

func dtlsHello(p []byte, _ *flow, req []byte) {
	p[0], p[1], p[2] = 22, 0xfe, 0xff
	clear(p[3:11])
	binary.BigEndian.PutUint16(p[11:], uint16(len(p)-13))
	p[13] = 1
	if req != nil {
		p[13] = 3
	}
	body := len(p) - 25
	putUint24(p[14:], body)
	clear(p[17:22])
	putUint24(p[22:], body)
}

func stun(p []byte, _ *flow, req []byte) {
	binary.BigEndian.PutUint16(p[0:], 0x0001)
	if req != nil {
		binary.BigEndian.PutUint16(p[0:], 0x0101)
		copy(p[8:20], req[8:20])
	}
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)-20))
	binary.BigEndian.PutUint32(p[4:], 0x2112a442)
}

func wireguard(p []byte, f *flow, _ []byte) {
	p[0] = 4
	clear(p[1:4])
	copy(p[4:8], f.cid[:4])
	binary.LittleEndian.PutUint64(p[8:], f.n-1)
}

func putUint48(p []byte, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	copy(p[:6], b[2:])
}

func putUint24(p []byte, v int) {
	p[0], p[1], p[2] = byte(v>>16), byte(v>>8), byte(v)
}

// fill reads random bytes; crypto/rand.Read does not fail since Go 1.24.
func fill(b []byte) {
	_, _ = rand.Read(b)
}

func parseForms(list string) ([]*form, error) {
	if strings.TrimSpace(list) == "all" {
		return forms, nil
	}
	var out []*form
	seen := map[byte]bool{}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		f := formByName(name)
		if f == nil {
			return nil, usagef("unknown form %q (known: %s, or all)", name, formNames())
		}
		if !seen[f.id] {
			seen[f.id] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, usagef("-forms is empty")
	}
	return out, nil
}

func parseSizes(list string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		n, err := strconv.Atoi(item)
		if err != nil || n < 1 || n > maxDatagram {
			return nil, usagef("size %q: want 1-%d bytes", item, maxDatagram)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, usagef("-sizes is empty")
	}
	return out, nil
}
