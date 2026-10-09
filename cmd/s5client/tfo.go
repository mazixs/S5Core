package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// fastOpen says whether this attempt dials with TCP Fast Open: OBFS_TFO on,
// the obfs transport, and a connection that writes at once. A spare dialled
// ahead of its tunnel sets noFastOpen: with the option connect() sends no
// SYN until the first write, so the spare would warm nothing.
func (cfg clientParams) fastOpen() bool {
	return cfg.FastOpen && !cfg.noFastOpen && !cfg.usesWS()
}

// noFastOpenFor is how long a node where Fast Open failed is dialled without
// it. The kernel does not do this by itself: it records a lost SYN per
// destination and does not read the record, and its global switch-off for a
// path that drops SYNs with data is disabled since Linux 5.14
// (tcp_fastopen_blackhole_timeout_sec = 0).
const noFastOpenFor = 10 * time.Minute

// noFastOpenAt remembers, by nativeKey, nodes where a SYN with data did not
// get through, and nodes not reached with one.
var noFastOpenAt sync.Map // string -> time.Time

func rememberNoFastOpen(key string, reached bool) {
	if prev, ok := noFastOpenAt.Swap(key, time.Now()); ok && time.Since(prev.(time.Time)) < noFastOpenFor {
		return
	}
	if reached {
		slog.Info("TCP Fast Open to the server failed; dialling it without for now",
			"server", key, "for", noFastOpenFor.String())
		return
	}
	slog.Info("The server was not reached; dialling it without TCP Fast Open for now",
		"server", key, "for", noFastOpenFor.String())
}

// fastOpenFailed says whether a connection that answered says the path or the
// node does not take SYNs with data: its SYN was sent again without it. A
// server whose key changed (a new container, a new network namespace)
// answers the SYN alone with a new cookie, and the next SYN carries data
// again. A kernel older than 5.5 does not tell one from the other, and its
// connection that did not carry data counts as failed.
func fastOpenFailed(carried bool, cause int) bool {
	return !carried && cause != tcptune.FastOpenDataNotAcked && cause != tcptune.FastOpenNoCookie
}

var fastOpenCause = tcptune.FastOpenClientFail

func fastOpenRested(key string) bool {
	at, ok := noFastOpenAt.Load(key)
	return ok && time.Since(at.(time.Time)) < noFastOpenFor
}

// dialTCP opens the TCP connection of the obfs transport. With Fast Open the
// deadline of ctx also bounds the wait for the server's SYN-ACK, which
// connect() no longer waits for once the kernel holds a cookie.
func dialTCP(ctx context.Context, cfg clientParams) (net.Conn, error) {
	key := nativeKey(cfg)
	if !cfg.fastOpen() || fastOpenRested(key) {
		return dialOutbound(ctx, "tcp", cfg.ServerAddr)
	}
	c, err := dialFastOpen(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	return newFastOpenConn(c, key, deadline, bounded), nil
}

// dialFastOpen is dialOutbound with TCP_FASTOPEN_CONNECT: from the second
// connection to a server, once the kernel holds its cookie, the opening, the
// greeting and the request go in the SYN.
var dialFastOpen = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Control: tcptune.DialFastOpen(fastOpenRefused)}
	return d.DialContext(ctx, network, addr)
}

var fastOpenRefusedSaid sync.Once

func fastOpenRefused(err error) {
	fastOpenRefusedSaid.Do(func() {
		slog.Debug("tunnel: TCP Fast Open is not available, dialling without it", "error", err)
	})
}

// fastOpenConn is the connection of a tunnel dialled with Fast Open. When
// connect() returned before the handshake (early), a server that is down or a
// path that drops the SYN shows only at the first read or write, where it
// would read as a server that took the connection and went quiet. A failure
// before the SYN-ACK is therefore marked unreached, and a dial phase failure
// (tunnelFail) without the hint about the PSK and the clock.
type fastOpenConn struct {
	net.Conn
	key       string
	early     bool
	answered  atomic.Bool // the server has sent a byte
	unreached atomic.Bool // no SYN-ACK within the dial's budget
	settled   sync.Once
	timer     *time.Timer
}

func newFastOpenConn(c net.Conn, key string, deadline time.Time, bounded bool) *fastOpenConn {
	f := &fastOpenConn{Conn: c, key: key}
	f.early, _ = tcptune.SYNSent(c)
	if f.early && bounded {
		f.timer = time.AfterFunc(time.Until(deadline), f.giveUp)
	}
	return f
}

func (c *fastOpenConn) NetConn() net.Conn { return c.Conn }

func (c *fastOpenConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.answered.Load() {
		c.answered.Store(true)
		c.settle(true)
	}
	if err != nil {
		err = c.failed(err)
	}
	return n, err
}

func (c *fastOpenConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		err = c.failed(err)
	}
	return n, err
}

func (c *fastOpenConn) Close() error {
	if c.timer != nil {
		c.timer.Stop()
	}
	return c.Conn.Close()
}

// giveUp ends a handshake that outlived the dial's budget.
func (c *fastOpenConn) giveUp() {
	if waiting, ok := tcptune.SYNSent(c.Conn); ok && waiting {
		c.unreached.Store(true)
		_ = c.SetDeadline(time.Now())
	}
}

func (c *fastOpenConn) failed(err error) error {
	if c.answered.Load() || errors.Is(err, net.ErrClosed) {
		return err
	}
	waiting, _ := tcptune.SYNSent(c.Conn)
	unreached := c.unreached.Load() || waiting || neverConnected(err)
	c.settle(!unreached)
	if unreached {
		return &unreachedError{err: err}
	}
	return err
}

// settle runs at the server's first byte or at a failure before it. The node
// is dialled without Fast Open for a while when a SYN sent with a cookie was
// not answered (reached false: the node is down, or the path drops SYNs with
// data), or was answered after a retransmit without the data (fastOpenFailed).
func (c *fastOpenConn) settle(reached bool) {
	c.settled.Do(func() {
		if c.timer != nil {
			c.timer.Stop()
		}
		if !c.early {
			return
		}
		if !reached {
			rememberNoFastOpen(c.key, false)
			return
		}
		carried, ok := tcptune.SYNData(c.Conn)
		if !ok {
			return
		}
		cause, _ := fastOpenCause(c.Conn)
		if fastOpenFailed(carried, cause) {
			rememberNoFastOpen(c.key, true)
		}
	})
}

func neverConnected(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}

// unreachedError is a failure of a Fast Open connection before the server's
// SYN-ACK: the failure of a dial, wherever it surfaced.
type unreachedError struct{ err error }

func (e *unreachedError) Error() string { return "the server was not reached: " + e.err.Error() }
func (e *unreachedError) Unwrap() error { return e.err }

// noteFastOpen says at debug level whether the first write of the tunnel went
// in its SYN. It is read once the server has answered, when the kernel knows,
// and only for a socket dialled with the option: a spare is not.
func noteFastOpen(c net.Conn) {
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	if on, ok := tcptune.DialsFastOpen(c); !ok || !on {
		return
	}
	if carried, ok := tcptune.SYNData(c); ok {
		slog.Debug("tunnel: TCP Fast Open", "conn", obfs.LogIDOf(c), "syn_data", carried)
	}
}

var probeFastOpen = tcptune.ProbeFastOpenConnect

// checkFastOpen says at startup what OBFS_TFO will do on this machine.
func checkFastOpen(cfg clientParams) {
	if !cfg.FastOpen {
		return
	}
	if err := probeFastOpen(); err != nil {
		fastOpenRefused(err)
		return
	}
	mode, ok := tcptune.FastOpenMode()
	if ok && mode&tcptune.FastOpenClient == 0 {
		slog.Warn("OBFS_TFO is on, but net.ipv4.tcp_fastopen does not let the client send data in a SYN",
			"tcp_fastopen", mode)
		return
	}
	slog.Info("TCP Fast Open on the obfs transport", "tcp_fastopen", mode)
}
