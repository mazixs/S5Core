package diagnostics

import (
	"context"
	"net"
	"runtime/trace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

const (
	// selectedSockets is the most sockets selected at once: the first to
	// come take the slots, a closed one gives its slot back. The socket
	// related to a selected one takes none, and there are at most as many
	// related sockets (ObserveRelated).
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
	// maxWrappers bounds the walk down the wrappers of a connection, as in
	// tcptune.Socket.
	maxWrappers = 10
)

// current is the running recorder, nil while diagnostics are off.
var current atomic.Pointer[recorder]

type recorder struct {
	start time.Time // the origin of every record's elapsed time
	dir   string
	// runID names the run, bootID this start of the process.
	runID, bootID string
	budget        int64                 // diskBudget, less in a test
	flight        *trace.FlightRecorder // nil without S5_DIAGNOSTICS_TRACE=1
	cancel        context.CancelFunc
	done          chan struct{} // closed when the worker is gone
	// stopped is set when the recorder stops; the wrappers it left on
	// sockets pass every call through from then on.
	stopped atomic.Bool
	tracing atomic.Bool // a trace is being written
	traces  sync.WaitGroup

	// mu guards what follows. No I/O happens under it.
	mu   sync.Mutex
	ring ring
	// sockets are the sampled ones: the selected sockets and those related
	// to them. taken counts the selected, which take the slots.
	sockets   map[*socket]struct{}
	taken     int
	flows     uint32 // the last flow ID given
	selection selection

	// The worker's.
	sampler    sampler
	pending    *incident
	traceID    string // the incident of the trace written last or now
	lastMarker string
	ticks      int
	chunk      []record
	line       []byte
	health     workerHealth
}

func newRecorder() *recorder {
	return &recorder{
		start: time.Now(), budget: diskBudget, cancel: func() {}, done: make(chan struct{}),
		ring: newRing(ringRecords), sockets: make(map[*socket]struct{}), sampler: newSampler(),
		chunk: make([]record, 0, copyChunk),
	}
}

// socket is a sampled socket: a selected one, or one related to it.
type socket struct {
	flow          *flowInfo
	conn          net.Conn // what ObserveConn or ObserveRelated was given
	reads, writes atomic.Uint64
	// readWait is the longest read, in nanoseconds, since the last periodic
	// sample took it.
	readWait atomic.Int64
	detector spikeDetector // the worker's
	// outer is the selected socket a related one belongs to, nil for a
	// selected one. related is the related socket of a selected one while it
	// is sampled, queue the queue in front of a selected one while it is
	// watched (ObserveQueue); mu guards both.
	outer, related *socket
	queue          *watchedQueue
}

// selection decides which sockets are recorded: a slot must be free and a
// token left. A token is newSocketInterval of credit, so the refill does not
// drift.
type selection struct {
	last                                                time.Time
	credit                                              time.Duration
	admitted, omittedRate, omittedActive, evictedClosed uint64
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
	if r.taken >= selectedSockets {
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
	r.taken++
	r.flows++
	s := &socket{conn: c, flow: &flowInfo{
		id: r.flows, leg: leg, transport: transport,
		local: c.LocalAddr().String(), remote: c.RemoteAddr().String(),
	}}
	r.sockets[s] = struct{}{}
	r.pushLocked(record{flow: s.flow, kind: kindFlowOpen})
	r.mu.Unlock()
	r.sampleSocket(s, sampleOpen)
	return r.wrap(c, s)
}

// ObserveRelated returns related wrapped for the latency recorder when outer
// is a socket it selected, and related itself otherwise. related is the
// other side of outer's relay, leg says which; it is recorded as a flow of
// its own that names outer's flow. It takes no slot and no token and starts
// no incident; a selected socket has one at a time, and there are at most
// selectedSockets of them. Off, it costs one atomic load.
func ObserveRelated(outer, related net.Conn, leg string) net.Conn {
	if current.Load() == nil {
		return related
	}
	return observeRelated(outer, related, leg)
}

// observeRelated is ObserveRelated past its check.
func observeRelated(outer, related net.Conn, leg string) net.Conn {
	r := current.Load()
	if r == nil || r.stopped.Load() {
		return related
	}
	o := socketUnder(outer)
	if o == nil {
		return related
	}
	if _, err := tcptune.Socket(related); err != nil {
		return related
	}
	r.mu.Lock()
	// A selected socket of this recorder, still sampled, without a related
	// one yet. A related socket can outlive its outer one, whose slot goes
	// to another, so their number is bounded on its own.
	if _, sampled := r.sockets[o]; !sampled || o.outer != nil || o.related != nil ||
		len(r.sockets)-r.taken >= selectedSockets {
		r.mu.Unlock()
		return related
	}
	r.flows++
	// The destination of a CONNECT and the application are plain TCP.
	s := &socket{conn: related, outer: o, flow: &flowInfo{
		id: r.flows, outer: o.flow.id, leg: leg, transport: "tcp",
		local: related.LocalAddr().String(), remote: related.RemoteAddr().String(),
	}}
	o.related = s
	r.sockets[s] = struct{}{}
	r.pushLocked(record{flow: s.flow, kind: kindFlowOpen})
	r.mu.Unlock()
	r.sampleSocket(s, sampleOpen)
	return r.wrap(related, s)
}

// wrap returns c wrapped for the sampled socket s.
func (r *recorder) wrap(c net.Conn, s *socket) net.Conn {
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
	c, err := countersOf(s.conn)
	r.push(record{flow: s.flow, kind: kindSocket, what: why, payload: &tcpSample{counters: c, available: err == nil}})
}

// release ends the sampling of s. Its last counters go first, while the
// socket is still open.
func (r *recorder) release(s *socket) {
	r.mu.Lock()
	sampled := r.unsampleLocked(s)
	r.mu.Unlock()
	if !sampled || r.stopped.Load() {
		return
	}
	r.sampleSocket(s, sampleClose)
	r.push(record{flow: s.flow, kind: kindFlowClose, payload: &flowTotals{reads: s.reads.Load(), writes: s.writes.Load()}})
}

// unsampleLocked stops sampling s and says whether it was sampled: a
// selected socket gives its slot back and its queue's watch ends, a related
// one gives its place beside its outer socket back. mu is held.
func (r *recorder) unsampleLocked(s *socket) bool {
	if _, sampled := r.sockets[s]; !sampled {
		return false
	}
	delete(r.sockets, s)
	s.queue = nil
	if s.outer != nil {
		s.outer.related = nil
	} else {
		r.taken--
	}
	return true
}
