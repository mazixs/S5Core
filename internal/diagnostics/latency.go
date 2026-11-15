package diagnostics

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

const (
	// selectedSockets is the most sockets recorded at once: the first to
	// come take the slots, a closed one gives its slot back.
	selectedSockets = 32
	// newSocketBurst and newSocketsPerSecond bound how fast sockets are
	// selected, so a burst of short connections cannot churn the ring.
	newSocketBurst      = 32
	newSocketsPerSecond = 8
	newSocketInterval   = time.Second / newSocketsPerSecond
	// transportSampleEvery: one read and one write in so many of a selected
	// socket are recorded.
	transportSampleEvery = 512
	// slowWrite is how long a write takes to be recorded whatever its turn.
	// A read waits for the peer, so a long one says nothing on its own: the
	// longest read between two samples goes into the socket sample instead.
	slowWrite = 25 * time.Millisecond
)

// current is the running recorder, nil while diagnostics are off.
var current atomic.Pointer[recorder]

type recorder struct {
	start time.Time // the origin of every record's elapsed time
	// stopped is set when the recorder stops; the wrappers it left on
	// sockets pass every call through from then on.
	stopped atomic.Bool

	// mu guards what follows. No I/O happens under it.
	mu        sync.Mutex
	ring      ring
	sockets   map[*socket]struct{}
	flows     uint32 // the last flow ID given
	selection selection
}

func newRecorder() *recorder {
	return &recorder{start: time.Now(), ring: newRing(ringRecords), sockets: make(map[*socket]struct{})}
}

// socket is a selected socket.
type socket struct {
	flow          *flowInfo
	conn          net.Conn // what ObserveConn was given
	reads, writes atomic.Uint64
	// readWait is the longest read, in nanoseconds, since the last periodic
	// sample took it.
	readWait atomic.Int64
}

// selection decides which sockets are recorded: a slot must be free and a
// token left. A token is newSocketInterval of credit, so the refill does not
// drift.
type selection struct {
	last                                 time.Time
	credit                               time.Duration
	admitted, omittedRate, omittedActive uint64
}

func (s *selection) allow(now time.Time) bool {
	const capacity = newSocketBurst * newSocketInterval
	if s.last.IsZero() {
		s.last, s.credit = now, capacity
	} else if now.After(s.last) {
		s.credit = min(capacity, s.credit+min(now.Sub(s.last), capacity))
		s.last = now
	}
	// A caller whose clock reading is older than another's neither refills
	// nor moves the anchor back.
	if s.credit < newSocketInterval {
		return false
	}
	s.credit -= newSocketInterval
	return true
}

// ObserveConn returns c wrapped for the latency recorder when diagnostics are
// on and c is selected, and c itself otherwise. leg says which side of the
// tunnel c is, transport how it is carried. Off, it costs one atomic load.
func ObserveConn(c net.Conn, leg, transport string) net.Conn {
	if current.Load() == nil {
		return c
	}
	return observe(c, leg, transport)
}

// observe is ObserveConn past its check, kept apart so that the check
// inlines into the callers.
func observe(c net.Conn, leg, transport string) net.Conn {
	r := current.Load()
	if r == nil || r.stopped.Load() {
		return c
	}
	if _, err := tcptune.Socket(c); err != nil {
		return c
	}
	r.mu.Lock()
	if len(r.sockets) >= selectedSockets {
		r.selection.omittedActive++
		r.mu.Unlock()
		return c
	}
	if !r.selection.allow(time.Now()) {
		r.selection.omittedRate++
		r.mu.Unlock()
		return c
	}
	r.selection.admitted++
	r.flows++
	s := &socket{conn: c, flow: &flowInfo{
		id: r.flows, leg: leg, transport: transport,
		local: c.LocalAddr().String(), remote: c.RemoteAddr().String(),
	}}
	r.sockets[s] = struct{}{}
	r.pushLocked(record{flow: s.flow, kind: kindFlowOpen})
	r.mu.Unlock()
	r.sampleSocket(s, sampleOpen)
	o := &observedConn{Conn: c, r: r, s: s}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return &observedHalfConn{observedConn: o, closeWrite: cw.CloseWrite}
	}
	return o
}

func (r *recorder) push(rec record) {
	r.mu.Lock()
	r.pushLocked(rec)
	r.mu.Unlock()
}

// pushLocked stamps rec with the time under the lock, so the order of the
// records is the order of their times.
func (r *recorder) pushLocked(rec record) {
	now := time.Now()
	rec.mono, rec.wall = int64(now.Sub(r.start)), now.UnixNano()
	r.ring.push(rec)
}

// sampleSocket records the kernel's counters of s.
func (r *recorder) sampleSocket(s *socket, why uint8) {
	c, err := tcptune.CountersOf(s.conn)
	r.push(record{flow: s.flow, kind: kindSocket, what: why, payload: &tcpSample{counters: c, available: err == nil}})
}

// release gives the slot of s back. Its last counters go first, while the
// socket is still open.
func (r *recorder) release(s *socket) {
	r.mu.Lock()
	_, selected := r.sockets[s]
	delete(r.sockets, s)
	r.mu.Unlock()
	if !selected || r.stopped.Load() {
		return
	}
	r.sampleSocket(s, sampleClose)
	r.push(record{flow: s.flow, kind: kindFlowClose, payload: &flowTotals{reads: s.reads.Load(), writes: s.writes.Load()}})
}
