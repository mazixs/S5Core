package session

import (
	"net"
	"sync"
	"time"
)

// Registry holds the sessions that are open right now. It exists for one
// question - how many sessions are in each state - answered at scrape time
// by Snapshot, so the hot path pays one atomic store per transition and
// nothing per metric.
//
// A nil *Registry is usable: Open returns a session that belongs to no
// registry and reports to no observer.
type Registry struct {
	observe Observer

	mu   sync.Mutex
	live map[*Session]struct{}
}

// NewRegistry returns an empty registry. observe may be nil.
func NewRegistry(observe Observer) *Registry {
	return &Registry{observe: observe, live: make(map[*Session]struct{})}
}

// Open creates a session for a connection just accepted on transport. framed
// says whether the transport carries obfuscation frames, i.e. whether the
// frames region exists for it. The session starts in Accepted, AwaitHeader
// (or Unframed) and WithinQuota, and it is in the registry until Close.
func (r *Registry) Open(transport string, framed bool, sla SLA) *Session {
	s := &Session{
		reg:        r,
		transport:  transport,
		sla:        sla,
		acceptedAt: time.Now(),
	}
	if framed {
		s.frames.Store(uint32(AwaitHeader))
	}
	if r != nil {
		r.mu.Lock()
		r.live[s] = struct{}{}
		r.mu.Unlock()
	}
	return s
}

func (r *Registry) remove(s *Session) {
	r.mu.Lock()
	delete(r.live, s)
	r.mu.Unlock()
}

// Len is how many sessions are open.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

// Count is one cell of a snapshot: how many sessions on a transport are in a
// state of a region.
type Count struct {
	Transport string
	Region    Region
	State     uint8
	N         int64
}

// StateName spells the state the way the metric does.
func (c Count) StateName() string { return c.Region.StateName(c.State) }

// Snapshot counts the open sessions by transport, region and state. Cells
// with nothing in them are left out; the frames region of an unframed
// session is left out too, because there is no such region.
func (r *Registry) Snapshot() []Count {
	if r == nil {
		return nil
	}
	type key struct {
		transport string
		region    Region
		state     uint8
	}
	counts := make(map[key]int64)

	r.mu.Lock()
	for s := range r.live {
		counts[key{s.transport, RegionProtocol, uint8(s.Protocol())}]++
		if f := s.Frames(); f != Unframed {
			counts[key{s.transport, RegionFrames, uint8(f)}]++
		}
		counts[key{s.transport, RegionAccount, uint8(s.Account())}]++
	}
	r.mu.Unlock()

	out := make([]Count, 0, len(counts))
	for k, n := range counts {
		out = append(out, Count{Transport: k.transport, Region: k.region, State: k.state, N: n})
	}
	return out
}

// Carrier is a connection wrapper that knows its session. The outermost
// wrapper in the listener pipeline implements it.
type Carrier interface {
	Session() *Session
}

// maxWrappers bounds the walk in Of: a wrapper that returns itself, or a
// cycle of them, must not hang the handshake.
const maxWrappers = 16

// Of finds the session of a connection, or nil when it has none.
//
// By the time a connection reaches the SOCKS5 core it is wrapped several
// times - metrics, limits, deadlines, obfuscation. Rather than make every
// wrapper forward a method it knows nothing about, this walks down the usual
// unwrapping methods until it finds a Carrier or runs out of layers.
func Of(c net.Conn) *Session {
	for range maxWrappers {
		if c == nil {
			return nil
		}
		if carrier, ok := c.(Carrier); ok {
			return carrier.Session()
		}
		switch w := c.(type) {
		case interface{ NetConn() net.Conn }:
			c = w.NetConn()
		case interface{ Unwrap() net.Conn }:
			c = w.Unwrap()
		default:
			return nil
		}
	}
	return nil
}
