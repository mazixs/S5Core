// Package nativeudp carries independent, authenticated datagrams for one
// SOCKS5 UDP association. A lost datagram never blocks a later one.
package nativeudp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/mazixs/S5Core/pkg/veil"
)

const (
	MaxWire           = 1400
	KindData     byte = 1
	KindProbe    byte = 2
	KindProbeAck byte = 3
	lookAhead         = 512
	lookBehind        = 64
)

var ErrPacket = errors.New("nativeudp: invalid or replayed datagram")

// Packet is a verified application datagram. Data is owned by the receiver.
type Packet struct {
	Kind byte
	Data []byte
}

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
	recvTop   uint64
	recvTags  map[[8]byte]uint64
	spentTags map[[8]byte]uint64 // hub-owned, bounded by lookBehind
	peer      atomic.Pointer[netip.AddrPort]
	packets   chan Packet
	closed    atomic.Bool
}

func NewSession(keys veil.DatagramKeys) *Session {
	s := &Session{keys: keys, recvTop: lookAhead, recvTags: make(map[[8]byte]uint64, lookAhead), spentTags: make(map[[8]byte]uint64, lookBehind), packets: make(chan Packet, 64)}
	s.sendTag = newTagger(keys.SendTag)
	s.recvTag = newTagger(keys.RecvTag)
	for i := uint64(0); i < lookAhead; i++ {
		s.recvTags[s.recvTag.tag(i)] = i
	}
	return s
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

// Seal appends a whole wire datagram to dst. The caller must not reuse dst
// while sending it. Oversized payloads must use the TCP fallback.
func (s *Session) Seal(dst []byte, kind byte, payload []byte) ([]byte, error) {
	if kind != KindData && kind != KindProbe && kind != KindProbeAck {
		return nil, ErrPacket
	}
	if len(payload)+2+8+s.keys.Send.Overhead() > MaxWire {
		return nil, ErrPacket
	}
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
	var draw [1]byte
	if _, err := rand.Read(draw[:]); err != nil {
		return nil, err
	}
	space := MaxWire - (len(payload) + 2 + 8 + s.keys.Send.Overhead())
	pad := 0
	if space > 0 {
		if space > 32 {
			space = 32
		}
		pad = 1 + int(draw[0])%space
	}
	var padding [32]byte
	if _, err := rand.Read(padding[:pad]); err != nil {
		return nil, err
	}
	dst = append(dst, t[:]...)
	dst = append(dst, kind)
	dst = append(dst, payload...)
	dst = append(dst, padding[:pad]...)
	dst = append(dst, byte(pad))
	// Seal in place: plaintext begins immediately after the tag.
	plain := dst[len(dst)-len(payload)-pad-2:]
	return s.keys.Send.Seal(dst[:len(dst)-len(plain)], s.sendNonce[:], plain, s.sendAAD[:]), nil
}

// Open authenticates before moving the replay window. Failed packets cannot
// claim a counter or move a client to a different source address.
func (s *Session) Open(wire []byte) (Packet, error) {
	var p Packet
	if len(wire) < 8+2+s.keys.Recv.Overhead() || len(wire) > MaxWire {
		return p, ErrPacket
	}
	var t [8]byte
	copy(t[:], wire[:8])
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	counter, ok := s.recvTags[t]
	if !ok {
		return p, ErrPacket
	}
	s.recvAAD = t
	binary.BigEndian.PutUint64(s.recvNonce[4:], counter)
	plain, err := s.keys.Recv.Open(wire[8:8], s.recvNonce[:], wire[8:], s.recvAAD[:])
	if err != nil || len(plain) < 2 {
		return p, ErrPacket
	}
	pad := int(plain[len(plain)-1])
	if pad > 32 || pad > len(plain)-2 {
		return p, ErrPacket
	}
	if plain[0] != KindData && plain[0] != KindProbe && plain[0] != KindProbeAck {
		return p, ErrPacket
	}
	delete(s.recvTags, t)
	if counter > s.recvHigh {
		s.recvHigh = counter
	}
	if s.recvHigh >= lookBehind {
		low := s.recvHigh - lookBehind
		for k, c := range s.recvTags {
			if c < low {
				delete(s.recvTags, k)
			}
		}
	}
	newTop := s.recvHigh + lookAhead
	for c := s.recvTop; c < newTop; c++ {
		s.recvTags[s.recvTag.tag(c)] = c
	}
	s.recvTop = newTop
	return Packet{Kind: plain[0], Data: plain[1 : len(plain)-1-pad]}, nil
}

func (s *Session) Packets() <-chan Packet { return s.packets }
func (s *Session) Peer() (netip.AddrPort, bool) {
	p := s.peer.Load()
	if p == nil {
		return netip.AddrPort{}, false
	}
	return *p, true
}

// Hub is the single UDP socket shared by all native associations on a node.
// Unknown tags, failed AEAD and replays are silently discarded.
type Hub struct {
	conn        *net.UDPConn
	mu          sync.Mutex
	sessions    map[*Session]struct{}
	index       map[[8]byte]*Session
	spent       map[[8]byte]*Session
	accepted    atomic.Uint64
	tagDrops    atomic.Uint64
	replayDrops atomic.Uint64
	authDrops   atomic.Uint64
	closed      atomic.Bool
}

// Stats is a cumulative, bounded-label view of the native UDP endpoint.
type Stats struct {
	Accepted, TagDrops, ReplayDrops, AuthDrops uint64
	Active                                     int
}

func (h *Hub) Stats() Stats {
	h.mu.Lock()
	active := len(h.sessions)
	h.mu.Unlock()
	return Stats{h.accepted.Load(), h.tagDrops.Load(), h.replayDrops.Load(), h.authDrops.Load(), active}
}

func Listen(addr string) (*Hub, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	h := &Hub{conn: c, sessions: make(map[*Session]struct{}), index: make(map[[8]byte]*Session), spent: make(map[[8]byte]*Session)}
	go h.read()
	return h, nil
}

func (h *Hub) Port() int    { return h.conn.LocalAddr().(*net.UDPAddr).Port }
func (h *Hub) Close() error { h.closed.Store(true); return h.conn.Close() }

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

func (h *Hub) Remove(s *Session) {
	h.mu.Lock()
	s.closed.Store(true)
	delete(h.sessions, s)
	for t := range s.recvTags {
		if h.index[t] == s {
			delete(h.index, t)
		}
	}
	for t := range s.spentTags {
		delete(h.spent, t)
	}
	h.mu.Unlock()
}

func (h *Hub) Send(s *Session, kind byte, payload []byte) error {
	peer, ok := s.Peer()
	if !ok || s.closed.Load() {
		return ErrPacket
	}
	var b [MaxWire]byte
	wire, err := s.Seal(b[:0], kind, payload)
	if err != nil {
		return err
	}
	_, err = h.conn.WriteToUDPAddrPort(wire, peer)
	return err
}

func (h *Hub) read() {
	var b [MaxWire + 1]byte
	for {
		n, peer, err := h.conn.ReadFromUDPAddrPort(b[:])
		if err != nil {
			return
		}
		if n < 8 || n > MaxWire {
			h.tagDrops.Add(1)
			continue
		}
		var t [8]byte
		copy(t[:], b[:8])
		h.mu.Lock()
		s := h.index[t]
		if s == nil || s.closed.Load() {
			if h.spent[t] != nil {
				h.replayDrops.Add(1)
			} else {
				h.tagDrops.Add(1)
			}
			h.mu.Unlock()
			continue
		}
		oldTop, oldHigh := s.recvTop, s.recvHigh
		counter := s.recvTags[t]
		p, err := s.Open(b[:n])
		if err == nil {
			h.accepted.Add(1)
			delete(h.index, t)
			h.spent[t] = s
			s.spentTags[t] = counter
			if s.recvHigh >= lookBehind && s.recvHigh > oldHigh {
				oldLow := uint64(0)
				if oldHigh >= lookBehind {
					oldLow = oldHigh - lookBehind
				}
				for c := oldLow; c < s.recvHigh-lookBehind; c++ {
					delete(h.index, s.recvTag.tag(c))
				}
			}
			for tag, c := range s.spentTags {
				if s.recvHigh >= lookBehind && c < s.recvHigh-lookBehind {
					delete(s.spentTags, tag)
					delete(h.spent, tag)
				}
			}
			for c := oldTop; c < s.recvTop; c++ {
				h.index[s.recvTag.tag(c)] = s
			}
		} else {
			h.authDrops.Add(1)
		}
		h.mu.Unlock()
		if err != nil {
			continue
		}
		copyPeer := peer
		s.peer.Store(&copyPeer)
		if p.Kind == KindProbe {
			_ = h.Send(s, KindProbeAck, nil)
			continue
		}
		if p.Kind != KindData {
			continue
		}
		select {
		case s.packets <- Packet{Kind: KindData, Data: append([]byte(nil), p.Data...)}:
		default:
		}
	}
}
