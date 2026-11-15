package diagnostics

import (
	"math"
	"net"
	"sync"
	"time"
)

// observedConn times the reads and writes of a selected socket. It hides no
// behaviour of the connection: deadlines pass through, NetConn leads the
// walks of tcptune and obfs to what it wraps, and observedHalfConn keeps
// CloseWrite where the connection has it.
type observedConn struct {
	net.Conn
	r    *recorder
	s    *socket
	once sync.Once
}

func (c *observedConn) NetConn() net.Conn { return c.Conn }

func (c *observedConn) Read(p []byte) (int, error) {
	if c.r.stopped.Load() {
		return c.Conn.Read(p)
	}
	periodic := c.s.reads.Add(1)%transportSampleEvery == 1
	var op operation
	if periodic {
		op = c.r.beginOperation(c.s.flow, "s5core.transport_read")
	}
	start := time.Now()
	n, err := c.Conn.Read(p)
	d := time.Since(start)
	op.end()
	c.s.noteReadWait(d)
	if periodic {
		c.r.stage(c.s, stageRead, d, n, err, true)
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	if c.r.stopped.Load() {
		return c.Conn.Write(p)
	}
	periodic := c.s.writes.Add(1)%transportSampleEvery == 1
	var op operation
	if periodic {
		op = c.r.beginOperation(c.s.flow, "s5core.transport_write")
	}
	start := time.Now()
	n, err := c.Conn.Write(p)
	d := time.Since(start)
	op.end()
	if periodic || d >= slowWrite {
		c.r.stage(c.s, stageWrite, d, n, err, periodic)
	}
	return n, err
}

func (c *observedConn) Close() error {
	c.once.Do(func() { c.r.release(c.s) })
	return c.Conn.Close()
}

type observedHalfConn struct {
	*observedConn
	closeWrite func() error
}

func (c *observedHalfConn) CloseWrite() error { return c.closeWrite() }

func (s *socket) noteReadWait(d time.Duration) {
	for {
		was := s.readWait.Load()
		if int64(d) <= was || s.readWait.CompareAndSwap(was, int64(d)) {
			return
		}
	}
}

func (r *recorder) stage(s *socket, what uint8, d time.Duration, n int, err error, periodic bool) {
	var flags uint8
	if periodic {
		flags |= flagPeriodic
	}
	if what == stageWrite && d >= slowWrite {
		flags |= flagSlow
	}
	if err != nil {
		flags |= flagError
	}
	r.push(record{flow: s.flow, kind: kindStage, what: what, flags: flags, dur: int64(d), n: uint32(min(uint64(n), math.MaxUint32))})
}
