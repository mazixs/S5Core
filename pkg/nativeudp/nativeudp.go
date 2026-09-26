// Package nativeudp carries independent, authenticated datagrams for one
// SOCKS5 UDP association. A lost datagram never blocks a later one.
package nativeudp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Sizes on the wire (docs/veil-spec.md, 10.7). MaxWire is the longest
// datagram either side sends. BaseWire is the size every path is taken to
// carry, BASE_PLPMTU of RFC 8899. Below FloorWire the smallest QUIC packet
// with the SOCKS5 header of an IPv6 address does not fit, which the client
// reports.
const (
	MaxWire   = 1400
	BaseWire  = 1200
	FloorWire = 1200 + 22 + 8 + 2 + 16
)

const (
	KindData     byte = 1
	KindProbe    byte = 2
	KindProbeAck byte = 3
)

// ProbeHeard is the flag of a probe from a client that hears the server
// natively; a probe without it asks only whether the path works. A client of
// 2.3.0-rc1 sends it as the whole payload.
const ProbeHeard byte = 1

const (
	lookAhead  = 512
	lookBehind = 64
	// window is every counter a session can still accept.
	window = lookAhead + lookBehind
)

var ErrPacket = errors.New("nativeudp: invalid or replayed datagram")

// Packet is a verified application datagram. A packet from a hub holds a
// pooled buffer, and Data is valid until Release. Counter is the sender's
// counter of it, which orders what the client says by UDP against what it
// says by the control connection (docs/veil-spec.md, 10.6).
type Packet struct {
	Kind    byte
	Data    []byte
	Counter uint64
	buf     *[MaxWire]byte
}

// Release returns the packet's buffer. A packet from Open has none.
func (p Packet) Release() {
	if p.buf != nil {
		wirePool.Put(p.buf)
	}
}

var wirePool = sync.Pool{New: func() any { return new([MaxWire]byte) }}

// Session uses one counter space per direction and a keyed, changing tag to
// hide both the session identifier and the packet number on the wire.
type Session struct {
	keys      veil.DatagramKeys
	sendTag   tagger
	recvTag   tagger
	sendMu    sync.Mutex
	send      uint64
	sendNonce [12]byte
	sendAAD   [8]byte
	recvMu    sync.Mutex
	recvNonce [12]byte
	recvAAD   [8]byte
	recvHigh  uint64
	recvAny   bool
	recvTop   uint64
	recvTags  map[[8]byte]uint64
	// recvRing holds the tag of every counter in the window, received or
	// not, at counter % window: the window moves without computing a tag
	// twice or walking the map.
	recvRing [window][8]byte
	answers  atomic.Pointer[route]
	// candidate is a new route that the newest datagram came by once; only
	// the hub's reader touches it.
	candidate route
	packets   chan Packet
	heard     chan struct{}
	// heardTop is the highest counter of a heard probe plus one: probes that
	// come while one is pending share one wake, and the newest must survive.
	heardTop atomic.Uint64
	closed   atomic.Bool
	// resynced is the last resync the hub made, under its lock.
	resynced time.Time
	// limit is the longest datagram this side puts on the wire, 0 for
	// MaxWire until SetLimit.
	limit atomic.Int32
}

func NewSession(keys veil.DatagramKeys) *Session {
	s := &Session{keys: keys, recvTop: lookAhead, recvTags: make(map[[8]byte]uint64, window), packets: make(chan Packet, 64), heard: make(chan struct{}, 1)}
	s.sendTag = newTagger(keys.SendTag)
	s.recvTag = newTagger(keys.RecvTag)
	for i := uint64(0); i < lookAhead; i++ {
		t := s.recvTag.tag(i)
		s.recvTags[t] = i
		s.recvRing[i%window] = t
	}
	return s
}

// low is the lowest counter still accepted once high has been received.
func low(high uint64) uint64 {
	if high < lookBehind {
		return 0
	}
	return high - lookBehind
}

// tagger is HMAC-SHA256 for exactly eight bytes. Fixed-size blocks avoid
// constructing a hash.Hash and allocating on every game datagram.
type tagger struct{ inner, outer [64]byte }

func newTagger(key [32]byte) tagger {
	var t tagger
	for i := range t.inner {
		var b byte
		if i < len(key) {
			b = key[i]
		}
		t.inner[i] = b ^ 0x36
		t.outer[i] = b ^ 0x5c
	}
	return t
}

func (t *tagger) tag(counter uint64) [8]byte {
	var inner [72]byte
	copy(inner[:64], t.inner[:])
	binary.BigEndian.PutUint64(inner[64:], counter)
	sum := sha256.Sum256(inner[:])
	var outer [96]byte
	copy(outer[:64], t.outer[:])
	copy(outer[64:], sum[:])
	sum = sha256.Sum256(outer[:])
	var result [8]byte
	copy(result[:], sum[:8])
	return result
}

// Limit is the longest datagram this side puts on the wire.
func (s *Session) Limit() int {
	if l := s.limit.Load(); l != 0 {
		return int(l)
	}
	return MaxWire
}

// SetLimit bounds what this side puts on the wire to the limit the probes
// found, brought within BaseWire and MaxWire. The limit is set once: it
// reports whether this call set it.
func (s *Session) SetLimit(wire int) bool {
	return s.limit.CompareAndSwap(0, int32(min(max(wire, BaseWire), MaxWire)))
}

// overhead is what the wire adds to a payload: the tag, the kind, the pad
// length and the AEAD tag.
func (s *Session) overhead() int { return 8 + 2 + s.keys.Send.Overhead() }

// MaxPayload is the longest payload Seal takes.
func (s *Session) MaxPayload() int { return s.Limit() - s.overhead() }

// Seal appends a whole wire datagram to dst. The caller must not reuse dst
// while sending it. Oversized payloads must use the TCP fallback.
func (s *Session) Seal(dst []byte, kind byte, payload []byte) ([]byte, error) {
	if kind != KindData && kind != KindProbe && kind != KindProbeAck {
		return nil, ErrPacket
	}
	limit := s.MaxPayload()
	if len(payload) > limit {
		return nil, ErrPacket
	}
	return s.seal(dst, kind, payload, 0, min(32, limit-len(payload)))
}

// seal appends the datagram of kind that carries data, then fill zero bytes,
// then 1 to space bytes of random padding, or none when space is 0.
func (s *Session) seal(dst []byte, kind byte, data []byte, fill, space int) ([]byte, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.send == ^uint64(0) {
		return nil, ErrPacket
	}
	counter := s.send
	s.send++
	t := s.sendTag.tag(counter)
	s.sendAAD = t
	binary.BigEndian.PutUint64(s.sendNonce[4:], counter)
	pad := 0
	if space > 0 {
		var draw [1]byte
		if _, err := rand.Read(draw[:]); err != nil {
			return nil, err
		}
		pad = 1 + int(draw[0])%space
	}
	var padding [32]byte
	if _, err := rand.Read(padding[:pad]); err != nil {
		return nil, err
	}
	dst = append(dst, t[:]...)
	dst = append(dst, kind)
	dst = append(dst, data...)
	dst = append(dst, make([]byte, fill)...)
	dst = append(dst, padding[:pad]...)
	dst = append(dst, byte(pad))
	// Seal in place: plaintext begins immediately after the tag.
	plain := dst[len(dst)-len(data)-fill-pad-2:]
	return s.keys.Send.Seal(dst[:len(dst)-len(plain)], s.sendNonce[:], plain, s.sendAAD[:]), nil
}

// SealWrite seals one datagram into a pooled buffer and hands it to write,
// which must be done with it when it returns.
func (s *Session) SealWrite(kind byte, payload []byte, write func([]byte) error) error {
	b := wirePool.Get().(*[MaxWire]byte)
	defer wirePool.Put(b)
	wire, err := s.Seal(b[:0], kind, payload)
	if err != nil {
		return err
	}
	return write(wire)
}

// Open authenticates before moving the replay window. Failed packets cannot
// claim a counter or move a client to a different source address. It decrypts
// in place, so wire is overwritten whenever its tag is known, even when the
// packet then fails authentication.
func (s *Session) Open(wire []byte) (Packet, error) {
	p, counter, err := s.claim(wire)
	if err == nil {
		s.settle(counter, nil)
		p.Counter = counter
	}
	return p, err
}

// claim authenticates a datagram and takes its counter, so that a replay is
// refused, without moving the window: the hub opens outside its own lock and
// moves the window under it.
func (s *Session) claim(wire []byte) (Packet, uint64, error) {
	var p Packet
	if len(wire) < 8+2+s.keys.Recv.Overhead() || len(wire) > MaxWire {
		return p, 0, ErrPacket
	}
	var t [8]byte
	copy(t[:], wire[:8])
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	counter, ok := s.recvTags[t]
	if !ok {
		return p, 0, ErrPacket
	}
	s.recvAAD = t
	binary.BigEndian.PutUint64(s.recvNonce[4:], counter)
	plain, err := s.keys.Recv.Open(wire[8:8], s.recvNonce[:], wire[8:], s.recvAAD[:])
	if err != nil || len(plain) < 2 {
		return p, 0, ErrPacket
	}
	pad := int(plain[len(plain)-1])
	if pad > 32 || pad > len(plain)-2 {
		return p, 0, ErrPacket
	}
	if plain[0] != KindData && plain[0] != KindProbe && plain[0] != KindProbeAck {
		return p, 0, ErrPacket
	}
	delete(s.recvTags, t)
	return Packet{Kind: plain[0], Data: plain[1 : len(plain)-1-pad]}, counter, nil
}

// settle moves the window past a claimed counter and reports whether it is
// the newest received, and whether it is still in the window: a resync
// between claim and settle may have moved the window past it. moved hears of
// every tag retired below the window or added above it.
func (s *Session) settle(counter uint64, moved func(tag [8]byte, added bool)) (newest, kept bool) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	newest = !s.recvAny || counter > s.recvHigh
	s.recvAny = true
	s.advance(counter, moved)
	return newest, counter >= low(s.recvHigh)
}

// advance makes high the highest counter received, when it is higher:
// the tags below the new low are retired and the look-ahead is filled up to
// high+lookAhead. A resync can move high past the whole window, and then
// every old tag goes and no tag is computed twice.
func (s *Session) advance(high uint64, moved func(tag [8]byte, added bool)) {
	if high > s.recvHigh {
		from := low(s.recvHigh)
		s.recvHigh = high
		for c := from; c < min(low(high), s.recvTop); c++ {
			retired := s.recvRing[c%window]
			delete(s.recvTags, retired)
			if moved != nil {
				moved(retired, false)
			}
		}
	}
	for c := max(s.recvTop, low(s.recvHigh)); c < s.recvHigh+lookAhead; c++ {
		added := s.recvTag.tag(c)
		s.recvTags[added] = c
		s.recvRing[c%window] = added
		if moved != nil {
			moved(added, true)
		}
	}
	s.recvTop = s.recvHigh + lookAhead
}

// Next is the counter the next sealed datagram gets.
func (s *Session) Next() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.send
}

// Resync takes the peer's word for the counter it sends next, which it gives
// by the control connection when the path failed: past lookAhead datagrams
// lost in a row no tag would match again. The window moves only forward, so
// a stale or repeated resync changes nothing, and the counters below next
// that are still in the window stay acceptable once.
func (s *Session) Resync(next uint64) { s.resync(next, nil) }

func (s *Session) resync(next uint64, moved func(tag [8]byte, added bool)) {
	if next == 0 || next > ^uint64(0)-lookAhead {
		return
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.recvAny && next-1 <= s.recvHigh {
		return
	}
	s.recvAny = true
	s.advance(next-1, moved)
}

func (s *Session) Packets() <-chan Packet { return s.packets }

// Heard receives when a probe says the client hears the server natively.
// Probes that come while one is pending add nothing to it but their counter:
// HeardCounter is the highest of them.
func (s *Session) Heard() <-chan struct{} { return s.heard }

// HeardCounter is the highest counter of a probe that said the client hears
// the server, once Heard has received.
func (s *Session) HeardCounter() uint64 { return s.heardTop.Load() - 1 }

func (s *Session) hear(counter uint64) {
	for top := s.heardTop.Load(); counter+1 > top; top = s.heardTop.Load() {
		if s.heardTop.CompareAndSwap(top, counter+1) {
			break
		}
	}
	select {
	case s.heard <- struct{}{}:
	default:
	}
}

func (s *Session) Peer() (netip.AddrPort, bool) {
	r := s.answers.Load()
	if r == nil {
		return netip.AddrPort{}, false
	}
	return r.peer, true
}

// route is where the answers go: the client's address, and the hub's address
// it wrote to with the control message that answers from it. The two move
// together: a client that moved wrote from a new address and, on a host with
// several, possibly to another one of the hub's.
type route struct {
	peer netip.AddrPort
	from netip.Addr // zero where the kernel picks the source
	oob  []byte
}

// Hub is the single UDP socket shared by all native associations on a node.
// Unknown tags, failed AEAD and replays are silently discarded.
type Hub struct {
	conn        *net.UDPConn
	source      sourceFamily
	mu          sync.Mutex
	sessions    map[*Session]struct{}
	index       map[[8]byte]*Session
	spent       map[[8]byte]*Session
	accepted    atomic.Uint64
	tagDrops    atomic.Uint64
	replayDrops atomic.Uint64
	authDrops   atomic.Uint64
	readErrors  atomic.Uint64
	logger      *slog.Logger
	// write is writeTo on the hub's socket; a test stalls it.
	write func(wire, oob []byte, to netip.AddrPort) error
	// acks are the probes that wait for their answers. The reader does not
	// write them itself: a write that waits for the socket would stop the
	// reception of every session.
	acks chan ackRequest
}

// ackRequest is a probe to answer, and how long it was on the wire.
type ackRequest struct {
	s        *Session
	probe    Probe
	extended bool
	wire     int
}

// Stats is a cumulative, bounded-label view of the native UDP endpoint.
type Stats struct {
	Accepted, TagDrops, ReplayDrops, AuthDrops, ReadErrors uint64
	Active                                                 int
}

func (h *Hub) Stats() Stats {
	h.mu.Lock()
	active := len(h.sessions)
	h.mu.Unlock()
	return Stats{h.accepted.Load(), h.tagDrops.Load(), h.replayDrops.Load(), h.authDrops.Load(), h.readErrors.Load(), active}
}

// Listen opens the hub. logger gets the socket's read errors; nil discards
// them, and Stats counts them either way.
func Listen(addr string, logger *slog.Logger) (*Hub, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	if err := DontFragment(c); err != nil && logger != nil {
		logger.Warn("Native UDP socket may fragment datagrams longer than the path", "error", err)
	}
	return serve(c, a.IP == nil || a.IP.IsUnspecified(), logger), nil
}

// serve reads c. On a wildcard address the kernel picks the source of an
// answer by the route back to the client, which on a host with a second
// address is not always the one the client wrote to; the client's connected
// socket drops such an answer, and so does a NAT in front of it (finding 4 of
// the 2.3 review). The hub then answers from the address each datagram came
// to.
func serve(c *net.UDPConn, wildcard bool, logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	h := &Hub{conn: c, sessions: make(map[*Session]struct{}), index: make(map[[8]byte]*Session), spent: make(map[[8]byte]*Session), logger: logger}
	h.write = func(wire, oob []byte, to netip.AddrPort) error { return writeTo(c, wire, oob, to) }
	h.acks = make(chan ackRequest, ackQueue)
	if wildcard {
		h.source = askForDestination(c)
	}
	go h.read()
	go h.answer()
	return h
}

// ackQueue is how many probes may wait for their answers. A probe past it
// goes unanswered, as a lost one would: the client counts three in a row
// before it gives up on the path.
const ackQueue = 256

func (h *Hub) answer() {
	for a := range h.acks {
		r := a.s.answers.Load()
		if r == nil || a.s.closed.Load() {
			continue
		}
		_ = a.s.SealWriteAnswer(a.probe, a.extended, a.wire, func(wire []byte) error { return h.write(wire, r.oob, r.peer) })
	}
}

func (h *Hub) Port() int    { return h.conn.LocalAddr().(*net.UDPAddr).Port }
func (h *Hub) Close() error { return h.conn.Close() }

func (h *Hub) Register(keys veil.DatagramKeys) *Session {
	s := NewSession(keys)
	h.mu.Lock()
	h.sessions[s] = struct{}{}
	for t := range s.recvTags {
		h.index[t] = s
	}
	h.mu.Unlock()
	return s
}

// Remove drops every tag of the session, all of which are in its window.
func (h *Hub) Remove(s *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s.closed.Store(true)
	delete(h.sessions, s)
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	for c := low(s.recvHigh); c < s.recvTop; c++ {
		h.forget(s, s.recvRing[c%window])
	}
}

// resyncEvery bounds the work a client can ask of the hub: a resync computes
// up to a window of tags under the hub's lock.
const resyncEvery = 100 * time.Millisecond

// Resync is Session.Resync for a session of the hub, with the hub's index
// kept in step. A resync within resyncEvery of the last is ignored; the
// client's next one carries a later counter.
func (h *Hub) Resync(s *Session, next uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if s.closed.Load() || (!s.resynced.IsZero() && now.Sub(s.resynced) < resyncEvery) {
		return
	}
	s.resynced = now
	s.resync(next, func(t [8]byte, added bool) {
		if added {
			h.index[t] = s
			return
		}
		h.forget(s, t)
	})
}

// forget drops a tag of s from both indexes. Tags of two sessions can
// collide, so each is removed only where it still points at s.
func (h *Hub) forget(s *Session, t [8]byte) {
	if h.index[t] == s {
		delete(h.index, t)
	}
	if h.spent[t] == s {
		delete(h.spent, t)
	}
}

func (h *Hub) Send(s *Session, kind byte, payload []byte) error {
	r := s.answers.Load()
	if r == nil || s.closed.Load() {
		return ErrPacket
	}
	return s.SealWrite(kind, payload, func(wire []byte) error { return h.write(wire, r.oob, r.peer) })
}

// follow moves the answers to a new route only once the newest datagram has
// come by it twice in a row. A copy of one datagram that outran the original
// from another address does not move them, and neither does an older
// datagram held back and sent later; a client whose NAT mapping changed
// moves with its second datagram. The hub's address the client wrote to
// follows the same rule: it used to move with any datagram, and one copy
// sent to another address of the host moved the source of every answer.
func (s *Session) follow(h *Hub, peer netip.AddrPort, from netip.Addr) {
	cur := s.answers.Load()
	switch {
	case cur == nil:
	case cur.peer == peer && cur.from == from:
		s.candidate = route{}
		return
	case s.candidate.peer != peer || s.candidate.from != from:
		s.candidate = route{peer: peer, from: from}
		return
	}
	s.candidate = route{}
	moved := &route{peer: peer, from: from}
	if from.IsValid() {
		moved.oob = sourceControl(h.source, from)
	}
	s.answers.Store(moved)
}

// read ends only when the socket is closed. Any other error is about one
// datagram or a passing shortage, and stopping would leave every client of
// the node without native while the port is still announced.
func (h *Hub) read() {
	defer close(h.acks)
	var b [MaxWire + 1]byte
	var oob [sourceSpace]byte
	var s *Session
	moved := func(t [8]byte, added bool) {
		if added {
			h.index[t] = s
			return
		}
		h.forget(s, t)
	}
	var failed int
	var logged time.Time
	for {
		n, oobn, peer, err := readFrom(h.conn, b[:], oob[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			h.readErrors.Add(1)
			if time.Since(logged) >= time.Minute {
				h.logger.Warn("Native UDP read failed; still reading", "error", err)
				logged = time.Now()
			}
			// A repeating error must not spin the loop.
			if failed++; failed > 1 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		failed = 0
		if n < 8 || n > MaxWire {
			h.tagDrops.Add(1)
			continue
		}
		var t [8]byte
		copy(t[:], b[:8])
		h.mu.Lock()
		s = h.index[t]
		if s == nil || s.closed.Load() {
			if h.spent[t] != nil {
				h.replayDrops.Add(1)
			} else {
				h.tagDrops.Add(1)
			}
			h.mu.Unlock()
			continue
		}
		h.mu.Unlock()
		// Register, Remove and Resync wait for the window to move, not for
		// the datagram to be decrypted.
		p, counter, err := s.claim(b[:n])
		if err != nil {
			h.authDrops.Add(1)
			continue
		}
		h.mu.Lock()
		if s.closed.Load() {
			h.tagDrops.Add(1)
			h.mu.Unlock()
			continue
		}
		newest, kept := s.settle(counter, moved)
		h.accepted.Add(1)
		if h.index[t] == s {
			delete(h.index, t)
		}
		if kept {
			h.spent[t] = s
		}
		h.mu.Unlock()
		if newest {
			var from netip.Addr
			if h.source != sourceOff {
				from, _ = destinationOf(oob[:oobn])
			}
			s.follow(h, peer, from)
		}
		if p.Kind == KindProbe {
			probe, extended := ParseProbe(p.Data)
			if probe.Limit != 0 {
				s.SetLimit(probe.Limit)
			}
			select {
			case h.acks <- ackRequest{s: s, probe: probe, extended: extended, wire: n}:
			default:
			}
			if probe.Heard {
				s.hear(counter)
			}
			continue
		}
		if p.Kind != KindData {
			continue
		}
		buf := wirePool.Get().(*[MaxWire]byte)
		packet := Packet{Kind: KindData, Data: buf[:copy(buf[:], p.Data)], Counter: counter, buf: buf}
		select {
		case s.packets <- packet:
		default:
			packet.Release()
		}
	}
}
