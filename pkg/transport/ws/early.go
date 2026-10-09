package ws

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Shape is the frame band a dialled connection is cut to, the arguments of
// NewShapedConn. MaxFrame zero means no shaper: one frame per write.
type Shape struct {
	MinFrame  int
	MaxFrame  int
	MaxJitter time.Duration
}

// UpgradeError is a failed upgrade after the request has left: the server
// answered with something other than a WebSocket, or did not answer in time.
// With early data the caller learns it on its first Read, not from the dial.
type UpgradeError struct {
	Status int // 0 without an HTTP response
	Err    error
}

func (e *UpgradeError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("ws dial: %v (status %d)", e.Err, e.Status)
	}
	return fmt.Sprintf("ws dial: %v", e.Err)
}

func (e *UpgradeError) Unwrap() error { return e.Err }

// DialEarly is DialFrames with early data: see the package function.
func (d *Dialer) DialEarly(ctx context.Context, shape Shape) (*EarlyConn, error) {
	opts := d.opts
	opts.WriteBufferSize = shape.MaxFrame
	return DialEarly(ctx, opts, shape)
}

// DialEarly returns as soon as the upgrade request has been written, without
// waiting for the 101. Writes made before the answer go out as masked client
// frames right behind the request, cut by the same plan as ShapedConn.Write;
// reads wait for the answer. Errors up to and including the request write are
// returned here; a refused upgrade is an *UpgradeError from Read and Write.
//
// Only for a server that announced early data (docs/veil-spec.md, 8.5): an
// ordinary gorilla server closes a connection that has bytes behind the
// upgrade request.
func DialEarly(ctx context.Context, opts DialOpts, shape Shape) (*EarlyConn, error) {
	dialer, target, headers, err := newGorillaDialer(opts, true)
	if err != nil {
		return nil, err
	}

	e := &EarlyConn{
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
		wake:   make(chan struct{}),
	}
	if shape.MaxFrame > 0 {
		e.shaper = NewShapedConn(nil, shape.MinFrame, shape.MaxFrame, shape.MaxJitter)
	}

	// The upgrade outlives ctx, which the caller may cancel as soon as this
	// returns; its deadline still bounds the answer.
	gctx := context.WithoutCancel(ctx)
	var gcancel context.CancelFunc
	if dl, ok := ctx.Deadline(); ok {
		gctx, gcancel = context.WithDeadline(gctx, dl)
	} else {
		gctx, gcancel = context.WithCancel(gctx)
	}

	sent := make(chan struct{})
	var rawMu sync.Mutex
	abandoned := false
	// As in DialContext: gorilla does not interrupt the upgrade read on
	// cancellation, so the socket is closed until the upgrade settles.
	var stopCancel func() bool
	var canceled chan struct{}
	hook := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(dialCtx, network, addr)
			if err != nil {
				return nil, err
			}
			rawMu.Lock()
			defer rawMu.Unlock()
			if abandoned {
				_ = c.Close()
				return nil, context.Canceled
			}
			canceled = make(chan struct{})
			stopCancel = context.AfterFunc(gctx, func() { _ = c.Close(); close(canceled) })
			e.raw = &upgradeConn{Conn: c, sent: sent}
			return e.raw, nil
		}
	}
	if dialer.NetDialTLSContext != nil {
		dialer.NetDialTLSContext = hook(dialer.NetDialTLSContext)
	} else {
		dialer.NetDialContext = hook(dialer.NetDialContext)
	}

	go func() {
		defer gcancel()
		wsConn, resp, err := dialer.DialContext(gctx, target, headers)
		if stopCancel != nil && !stopCancel() {
			<-canceled
		}
		if gctx.Err() != nil {
			if wsConn != nil {
				_ = wsConn.Close()
			}
			err = gctx.Err()
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		e.finish(wsConn, resp, err, opts.ReadLimit, sent)
	}()

	select {
	case <-sent:
		return e, nil
	case <-e.ready:
		if e.err == nil {
			return e, nil
		}
		return nil, e.err
	case <-ctx.Done():
		rawMu.Lock()
		abandoned = true
		raw := e.raw
		rawMu.Unlock()
		gcancel()
		if raw != nil {
			_ = raw.Close()
		}
		<-e.ready
		_ = e.Close()
		return nil, ctx.Err()
	}
}

// EarlyConn is a client WebSocket connection that accepts writes before the
// server has answered the upgrade.
type EarlyConn struct {
	raw    *upgradeConn
	shaper *ShapedConn

	writeMu sync.Mutex

	mu       sync.Mutex
	ready    chan struct{}
	closed   chan struct{}
	isClosed bool
	conn     net.Conn // *ShapedConn or *Conn, set before ready closes
	err      error
	readDL   time.Time
	writeDL  time.Time
	wake     chan struct{} // closed and replaced when the read deadline moves
}

func (e *EarlyConn) finish(wsConn *websocket.Conn, resp *http.Response, err error, readLimit int64, sent chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer close(e.ready)
	// A connection closed by its owner before the answer ends as closed,
	// whatever the upgrade made of its socket going away.
	if e.isClosed {
		if wsConn != nil {
			_ = wsConn.Close()
		}
		e.err = net.ErrClosed
		return
	}
	if err != nil {
		select {
		case <-sent:
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			e.err = &UpgradeError{Status: status, Err: err}
		default:
			e.err = dialError(err, resp)
		}
		return
	}
	c := WrapWithLimit(wsConn, readLimit)
	_ = c.SetReadDeadline(e.readDL)
	_ = c.SetWriteDeadline(e.writeDL)
	if e.shaper != nil {
		e.shaper.Conn = c
		e.conn = e.shaper
	} else {
		e.conn = c
	}
}

// settled reports the upgrade's outcome once it is known.
func (e *EarlyConn) settled() (net.Conn, error, bool) {
	select {
	case <-e.ready:
		return e.conn, e.err, true
	default:
		return nil, nil, false
	}
}

// Upgraded reports whether the server has answered the upgrade with 101.
func (e *EarlyConn) Upgraded() bool {
	c, err, ok := e.settled()
	return ok && err == nil && c != nil
}

func (e *EarlyConn) Write(b []byte) (int, error) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if c, err, ok := e.settled(); ok {
		if err != nil {
			return 0, err
		}
		return c.Write(b)
	}
	select {
	case <-e.closed:
		return 0, net.ErrClosed
	default:
	}

	var one [1]int
	sizes := one[:0]
	switch {
	case len(b) == 0:
	case e.shaper != nil:
		sizes = e.shaper.plan(len(b))
	default:
		sizes = append(sizes, len(b))
	}
	total := 0
	for _, size := range sizes {
		// One frame, one write: under TLS one write is one record, as with
		// ShapedConn.Write. No jitter here: the frames ride with the request.
		if _, err := e.raw.Conn.Write(maskedFrame(b[total : total+size])); err != nil {
			// A server that refused the upgrade may have closed the socket
			// first; the refusal is the cause worth reporting. The upgrade
			// read ends quickly on a broken socket, not on a timed-out write.
			if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
				return total, err
			}
			<-e.ready
			if e.err != nil {
				return total, e.err
			}
			return total, err
		}
		total += size
	}
	return total, nil
}

// maskedFrame is one final binary client frame (RFC 6455, 5.2), the form
// gorilla gives a message that fits its write buffer.
func maskedFrame(p []byte) []byte {
	n := len(p)
	frame := make([]byte, 0, 14+n)
	frame = append(frame, 0x82)
	switch {
	case n <= 125:
		frame = append(frame, 0x80|byte(n))
	case n <= 0xffff:
		frame = append(frame, 0x80|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
	default:
		frame = append(frame, 0x80|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n))
	}
	var key [4]byte
	_, _ = cryptorand.Read(key[:])
	frame = append(frame, key[:]...)
	start := len(frame)
	frame = append(frame, p...)
	for i := range p {
		frame[start+i] ^= key[i&3]
	}
	return frame
}

func (e *EarlyConn) Read(b []byte) (int, error) {
	for {
		if c, err, ok := e.settled(); ok {
			if err != nil {
				return 0, err
			}
			return c.Read(b)
		}
		e.mu.Lock()
		dl, wake := e.readDL, e.wake
		e.mu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			expired = timer.C
		}
		select {
		case <-e.ready:
		case <-e.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case <-wake:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (e *EarlyConn) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isClosed {
		return nil
	}
	e.isClosed = true
	close(e.closed)
	if e.conn != nil {
		return e.conn.Close()
	}
	if e.raw == nil {
		return nil
	}
	return e.raw.Close()
}

// NetConn keeps the socket reachable for tcptune and obfs.layerOf.
func (e *EarlyConn) NetConn() net.Conn { return e.raw }

func (e *EarlyConn) LocalAddr() net.Addr  { return e.raw.LocalAddr() }
func (e *EarlyConn) RemoteAddr() net.Addr { return e.raw.RemoteAddr() }

func (e *EarlyConn) SetDeadline(t time.Time) error {
	if err := e.SetReadDeadline(t); err != nil {
		return err
	}
	return e.SetWriteDeadline(t)
}

func (e *EarlyConn) SetReadDeadline(t time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	e.readDL = t
	if e.conn != nil {
		return e.conn.SetReadDeadline(t)
	}
	close(e.wake)
	e.wake = make(chan struct{})
	return nil
}

func (e *EarlyConn) SetWriteDeadline(t time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	e.writeDL = t
	if e.conn != nil {
		return e.conn.SetWriteDeadline(t)
	}
	// Early frames go straight to the socket; finish moves the deadline to
	// the WebSocket once the upgrade is through.
	return e.raw.SetWriteDeadline(t)
}

// upgradeConn reports when the upgrade request has been written in full.
// The request is a GET without a body, so its end is the blank line.
type upgradeConn struct {
	net.Conn
	sent chan struct{}
	done bool
	tail []byte
}

func (u *upgradeConn) Write(b []byte) (int, error) {
	n, err := u.Conn.Write(b)
	if !u.done && err == nil {
		u.tail = append(u.tail, b...)
		if len(u.tail) > 4 {
			u.tail = u.tail[len(u.tail)-4:]
		}
		if string(u.tail) == "\r\n\r\n" {
			u.done = true
			u.tail = nil
			close(u.sent)
		}
	}
	return n, err
}

func (u *upgradeConn) NetConn() net.Conn { return u.Conn }
