package s5server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/session"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// bufferPool backs the metered copies in metricsConn: one 32 KiB buffer per
// direction, reused, so that a busy server does not allocate one per
// connection.
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type closeWriter interface {
	CloseWrite() error
}

// timeoutConn arms session budgets at the transport boundary. Successful
// outbound stream traffic extends an already pending client read; write
// deadlines still bound a blocked writer independently.
type timeoutConn struct {
	net.Conn
	sess       *session.Session
	deadlineMu sync.Mutex
	readArmed  bool
	writeArmed bool
}

func (c *timeoutConn) NetConn() net.Conn { return c.Conn }

// armReadLocked serializes read-side arming with outbound activity, so an
// older deadline cannot overwrite the extension made by the other goroutine.
func (c *timeoutConn) armReadLocked() error {
	deadline, ok := c.sess.ReadDeadline(time.Now())
	if ok || c.readArmed {
		if err := c.SetReadDeadline(deadline); err != nil {
			return err
		}
		c.readArmed = ok
	}
	return nil
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	c.deadlineMu.Lock()
	err := c.armReadLocked()
	c.deadlineMu.Unlock()
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if deadline, ok := c.sess.WriteDeadline(time.Now()); ok {
		if err := c.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		c.writeArmed = true
	} else if c.writeArmed {
		_ = c.SetWriteDeadline(time.Time{})
		c.writeArmed = false
	}
	n, err := c.Conn.Write(b)
	p := c.sess.Protocol()
	if n > 0 && c.sess.Kind() == session.Stream && (p == session.Relay || p == session.HalfClosed) {
		c.deadlineMu.Lock()
		deadlineErr := c.armReadLocked()
		c.deadlineMu.Unlock()
		if err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

func (c *timeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("timeoutConn: underlying connection does not support CloseWrite")
}

// metricsConn is designed to count traffic and reduce GC using buffer pools.
type metricsConn struct {
	net.Conn
	telemetry *Telemetry
	// sess is the connection's state machine. metricsConn is the outermost
	// wrapper, so it is the one that owns the session's lifetime: session.Of
	// finds it here through Session, and Close ends it. A nil session (an SDK
	// caller that wraps its own connection) is handled by every Session
	// method being nil-safe.
	sess *session.Session
	// transport names the listener the connection arrived on: plain, obfs or
	// ws. It is a constant of this package, safe as a metric label, and it is
	// the only way to see from the metrics which transports clients actually
	// use.
	transport metric.MeasurementOption
	// transportName is the same value in plain form, for metrics that need it
	// alongside another label.
	transportName string
	closeOnce     sync.Once
}

// NetConn hands back the connection underneath. The obfuscation layer is
// below this one and carries the member the tunnel resolved, so hiding it
// would cost every member their name (plan task Ф5-5).
func (c *metricsConn) NetConn() net.Conn { return c.Conn }

// Session is how session.Of finds the connection's state machine: this is the
// outermost wrapper, so the search stops here (plan task Ф6-1).
func (c *metricsConn) Session() *session.Session { return c.sess }

func (c *metricsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.telemetry != nil && n > 0 {
		c.telemetry.BytesIn.Add(context.Background(), int64(n))
	}
	return n, err
}

func (c *metricsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.telemetry != nil && n > 0 {
		c.telemetry.BytesOut.Add(context.Background(), int64(n))
	}
	return n, err
}

func (c *metricsConn) ReadFrom(r io.Reader) (int64, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	var total int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := c.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (c *metricsConn) WriteTo(w io.Writer) (int64, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	var total int64
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return total, nil
			}
			return total, er
		}
	}
}

func (c *metricsConn) Close() error {
	c.closeOnce.Do(func() {
		if c.telemetry != nil {
			c.telemetry.ActiveConnections.Add(context.Background(), -1, c.transport)
		}
		// The session reaches its terminal state and leaves the registry
		// here, where the connection actually closes - ServeConn's own defer
		// drives this on every path, including the forced close the relay
		// uses to unblock a stuck half.
		c.sess.Close()
	})
	return c.Conn.Close()
}

// CloseWrite passes the half-close down the transport stack and counts it when
// it fails. This is the one place that knows both that the attempt failed and
// which transport the client came in on.
func (c *metricsConn) CloseWrite() error {
	cw, ok := c.Conn.(closeWriter)
	if !ok {
		c.failHalfClose()
		return fmt.Errorf("metricsConn: underlying connection does not support CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		c.failHalfClose()
		return err
	}
	return nil
}

func (c *metricsConn) failHalfClose() {
	if c.telemetry == nil || c.telemetry.HalfCloseFailures == nil {
		return
	}
	c.telemetry.HalfCloseFailures.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("side", SideClient),
		attribute.String("transport", c.transportName),
	))
}

// connLimiter caps how many connections the server holds open at once, across
// every listener.
//
// MAX_CONNECTIONS used to be netutil.LimitListener wrapped around the plain
// listener alone. That is wrong twice: the obfuscated port - the one a real
// deployment actually serves - had no limit at all, and had the wrapper been
// copied to each listener the effective ceiling would have been three times
// the number configured, because each listener would own its own counter.
// One counter, shared, is what "global limit" means.
type connLimiter struct {
	slots chan struct{}
}

// newConnLimiter returns nil when no limit is configured. A nil *connLimiter
// is usable: its methods do nothing, so the accept path needs no branches.
func newConnLimiter(n int) *connLimiter {
	if n <= 0 {
		return nil
	}
	return &connLimiter{slots: make(chan struct{}, n)}
}

// acquire takes a slot if one is free and reports whether it got it. It never
// waits.
//
// netutil.LimitListener instead takes the slot before calling Accept and
// blocks there until one frees up. With several listeners sharing one counter
// that is unusable: each idle listener sits holding a slot it is not using,
// so three transports and MAX_CONNECTIONS=2 would deadlock before a single
// client arrived. Refusing on arrival also tells the client something - a
// closed connection now, rather than a connect that succeeds and then hangs
// silently in the kernel backlog.
func (l *connLimiter) acquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *connLimiter) release() {
	if l == nil {
		return
	}
	select {
	case <-l.slots:
	default:
	}
}

// limitedConn returns its slot to the limiter when it is closed, once.
type limitedConn struct {
	net.Conn
	limiter   *connLimiter
	closeOnce sync.Once
}

func (c *limitedConn) Close() error {
	c.closeOnce.Do(c.limiter.release)
	return c.Conn.Close()
}

// NetConn lets tcptune reach the socket. Without it a server with a
// connection limit, which cmd/s5core always has, left every 0x83 tunnel on
// the kernel's timer.
func (c *limitedConn) NetConn() net.Conn { return c.Conn }

// CloseWrite keeps the half-close path intact: every wrapper between socks5
// and the socket has to pass it down, or the shutdown turns into a full close.
func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("limitedConn: underlying connection does not support CloseWrite")
}

// listenerPipeline is the single path from an accepted socket to a connection
// the SOCKS5 core can serve: connection limit, IP whitelist, deadlines,
// transport wrapping and metrics, in that order, for every transport.
//
// There used to be three separate paths, and they disagreed. The limit
// applied to one port; the whitelist could be updated on one port; the
// WebSocket listener bypassed the wrapper entirely and so had neither
// deadlines nor connection metrics. Each of those was a hole you could only
// find by reading all three code paths and noticing what one of them left
// out. With one pipeline, adding a stage adds it everywhere.
