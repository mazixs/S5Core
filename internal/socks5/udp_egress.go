package socks5

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/udpbuf"
)

// rotatingUDP is the egress socket a UDP-over-TCP association (0x83/0x84) sends
// its target datagrams from and hears their replies on. On a path that spreads
// flows over parallel links by their 5-tuple, the source port this socket
// happens to draw can put every one of the association's flows on a link that
// drops everything, so the client sends and hears nothing back (node D in
// docs/field/nodes.md). When that happens the socket is closed and reopened,
// which draws a new source port and a new link.
//
// It rotates only while no target has ever answered on it. Once one has, the
// socket holds at least one live link, and rotating it would only move the
// flows that work onto a fresh draw where some of them would land in the hole
// instead. So the gate is not "some flow is dead" - with per-5-tuple hashing a
// third of them are - but "nothing answers at all", which is the single-flow
// case a match join hits, and there rotation can lose nothing that was working.
type rotatingUDP struct {
	bindIP net.IP

	conn atomic.Pointer[net.UDPConn]

	// tx counts datagrams sent to targets since the current socket opened; rx
	// counts replies from targets over the association's whole life; n counts
	// rotations. openedAt is when the current socket opened, in unix
	// nanoseconds.
	tx       atomic.Int64
	rx       atomic.Int64
	n        atomic.Int64
	openedAt atomic.Int64

	mu     sync.Mutex
	closed bool
}

func newRotatingUDP(bindIP net.IP) (*rotatingUDP, error) {
	e := &rotatingUDP{bindIP: bindIP}
	c, err := e.open()
	if err != nil {
		return nil, err
	}
	e.conn.Store(c)
	e.openedAt.Store(time.Now().UnixNano())
	return e, nil
}

func (e *rotatingUDP) open() (*net.UDPConn, error) {
	return udpbuf.ListenUDP("udp", &net.UDPAddr{IP: e.bindIP, Port: 0})
}

// current returns the socket to use now. A reader keeps it to ask replaced
// whether a failed read was a rotation.
func (e *rotatingUDP) current() *net.UDPConn {
	return e.conn.Load()
}

// replaced reports that c is no longer the socket and the association is
// still open: the read that just failed on c failed because a rotation closed
// it, and the caller should read again from current. A closed association is
// not a rotation. It compares the socket itself rather than a generation
// counter read beside it, so there is no pair of reads a rotation can split.
func (e *rotatingUDP) replaced(c *net.UDPConn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.conn.Load() != c
}

func (e *rotatingUDP) sentToTarget() { e.tx.Add(1) }

// gotReply counts a reply and reports whether it is the association's first.
// The first reply after at least one rotation is the hole found and left,
// the one event worth a line in the log, whenever it comes: the watcher may
// have run out of draws by then.
func (e *rotatingUDP) gotReply() bool { return e.rx.Add(1) == 1 }

// replied counts a reply and logs the first one that follows a rotation.
func (e *rotatingUDP) replied(log *slog.Logger) {
	if !e.gotReply() {
		return
	}
	if n := e.rotations(); n > 0 {
		log.Info("socks: udp egress socket answered after rotation", "rotations", n)
	}
}
func (e *rotatingUDP) recvCount() int64 {
	return e.rx.Load()
}

// rotations is how many times the socket has been replaced.
func (e *rotatingUDP) rotations() int64 { return e.n.Load() }

// deadLongEnough reports the rotation condition: nothing has ever answered,
// at least minTx datagrams have gone out on the current socket, and it has
// been open at least window. minTx keeps a single stray datagram from arming
// the rotation.
func (e *rotatingUDP) deadLongEnough(now time.Time, minTx int64, window time.Duration) bool {
	if e.rx.Load() > 0 {
		return false
	}
	if e.tx.Load() < minTx {
		return false
	}
	opened := time.Unix(0, e.openedAt.Load())
	return now.Sub(opened) >= window
}

// rotate replaces the socket with a fresh one and reports whether it did. The
// new socket is opened before the old is closed, so a reader blocked on the old
// one wakes to find the new one already in place. A closed association does not
// rotate.
func (e *rotatingUDP) rotate() (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false, nil
	}
	c, err := e.open()
	if err != nil {
		return false, err
	}
	old := e.conn.Swap(c)
	e.n.Add(1)
	e.tx.Store(0)
	e.openedAt.Store(time.Now().UnixNano())
	if old != nil {
		_ = old.Close()
	}
	return true, nil
}

// Close closes the current socket once. It is safe to call alongside rotate:
// the two share the mutex, so a rotation in flight finishes first and its new
// socket is the one closed.
func (e *rotatingUDP) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if c := e.conn.Load(); c != nil {
		return c.Close()
	}
	return nil
}

const (
	// udpRotateWindow is how long the egress socket may send without a single
	// reply before it is rotated.
	udpRotateWindow = time.Second
	// udpRotateMinTx is how many datagrams must have gone out first.
	udpRotateMinTx = 2
	// udpRotateMax bounds the draws: after this many the destination is taken
	// to be silent rather than behind a hole, and the socket is left alone.
	udpRotateMax = 4
	// udpRotateTick is how often the condition is checked.
	udpRotateTick = 250 * time.Millisecond
)

// watchDeadEgress rotates the egress socket while it hears nothing back, up to
// udpRotateMax times, and returns when the association ends, the socket comes
// alive, or the draws run out. rotated, when set, is called after each
// successful rotation with the running count.
func watchDeadEgress(ctx context.Context, e *rotatingUDP, rotated func(int)) {
	ticker := time.NewTicker(udpRotateTick)
	defer ticker.Stop()
	rotations := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if e.recvCount() > 0 || rotations >= udpRotateMax {
				return
			}
			if !e.deadLongEnough(now, udpRotateMinTx, udpRotateWindow) {
				continue
			}
			ok, err := e.rotate()
			if err != nil || !ok {
				return
			}
			rotations++
			if rotated != nil {
				rotated(rotations)
			}
		}
	}
}
