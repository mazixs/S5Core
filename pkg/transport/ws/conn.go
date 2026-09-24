// Package ws provides a net.Conn adapter over WebSocket binary frames.
// It is used to tunnel obfuscated SOCKS5 traffic so that DPI sees a
// standard WSS connection (e.g. a real-time web app) instead of a raw
// encrypted tunnel.
package ws

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultReadLimit bounds one WebSocket message. It is not a memory bound -
// Read below never holds a whole message - but a statement about the
// protocol: this transport carries batches of obfuscated frames, and the
// largest a sender of ours produces is two frames of a jumbo MTU, some 128
// KiB. A message an order of magnitude past that is not this protocol, and
// reading it to the end would be doing an unauthenticated peer's bidding.
const DefaultReadLimit = 1024 * 1024

// Conn wraps a gorilla websocket.Conn to implement net.Conn.
//
// Read is streaming: it hands out the current message as the caller asks for
// it and never holds more than the caller's own buffer. It used to call
// ReadMessage, which assembles the whole message in memory first and left
// whatever did not fit in a buffer of this Conn. Nothing above this layer had
// authenticated the peer at that point - the obfuscation check happens on the
// bytes this Read returns - so any client that completed a WebSocket
// handshake could name a message size and have the server allocate it. A
// 2 MiB message left 2 MiB parked per connection, and the handshake timeout
// bounds how long that takes, not how much of it there is (F05 in
// docs/reports/code-quality-audit-2026-09-20.md).
type Conn struct {
	ws *websocket.Conn
	// msg is the message being read, or nil between messages. Holding the
	// reader, rather than the bytes, is what makes Read streaming.
	msg     io.Reader
	readMu  sync.Mutex
	writeMu sync.Mutex
	closed  atomic.Bool

	// Gorilla stores its deadline in an unsynchronized field. Keep our own
	// deadline and interrupt an expired active write by closing the socket:
	// after a write timeout Gorilla cannot be used for further writes anyway.
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	writeTimer    *time.Timer
	writing       bool
	writeTimedOut bool
	// Allocated only by a shaping pause. Closing this channel broadcasts
	// Close/deadline changes without adding work to ordinary frame writes.
	writeWake chan struct{}
}

// Wrap wraps an existing websocket.Conn, with the default message limit.
func Wrap(ws *websocket.Conn) *Conn {
	return WrapWithLimit(ws, DefaultReadLimit)
}

// WrapWithLimit is Wrap with a message limit of the caller's choosing, in the
// form the transport options use it: zero asks for DefaultReadLimit, and a
// negative value asks for no limit at all, which only a caller that trusts its
// peer should do. An unset option therefore means the default and not the
// absence of one - the way round that leaves a zero value protected.
func WrapWithLimit(ws *websocket.Conn, limit int64) *Conn {
	switch {
	case limit == 0:
		ws.SetReadLimit(DefaultReadLimit)
	case limit > 0:
		ws.SetReadLimit(limit)
	}
	_ = ws.SetWriteDeadline(time.Time{})
	return &Conn{ws: ws}
}

// Read implements net.Conn.Read. It returns what is left of the current
// message, taking the next one only when the current is exhausted, so the
// memory it uses is the caller's buffer and nothing besides.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(b) == 0 {
		return 0, nil
	}

	for {
		if c.msg != nil {
			n, err := c.msg.Read(b)
			if n > 0 {
				return n, nil
			}
			// The end of a message is not the end of the stream: the next
			// Read takes the next message.
			c.msg = nil
			if err != nil && err != io.EOF {
				return 0, c.readError(err)
			}
			continue
		}

		mt, r, err := c.ws.NextReader()
		if err != nil {
			return 0, c.readError(err)
		}
		if mt != websocket.BinaryMessage {
			// Skip non-binary messages (e.g. pings are handled internally)
			continue
		}
		c.msg = r
	}
}

// readError keeps the one piece of error translation this adapter has always
// done: an orderly close from the peer is reported as such.
func (c *Conn) readError(err error) error {
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return fmt.Errorf("ws: %w", err)
	}
	return err
}

// Write implements net.Conn.Write.
// It sends the entire buffer as a single binary WebSocket message.
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, fmt.Errorf("ws: write on closed connection")
	}

	c.deadlineMu.Lock()
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		c.deadlineMu.Unlock()
		return 0, c.writeTimeout()
	}
	c.writing = true
	c.deadlineMu.Unlock()
	err := c.ws.WriteMessage(websocket.BinaryMessage, b)
	c.deadlineMu.Lock()
	c.writing = false
	timedOut := c.writeTimedOut
	c.deadlineMu.Unlock()
	if timedOut {
		return 0, c.writeTimeout()
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements net.Conn.Close. It is safe to call while another goroutine
// is writing, which is what a server shutdown does.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	c.deadlineMu.Lock()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.wakeWriteWaitersLocked()
	c.deadlineMu.Unlock()
	// net.Conn.Close must interrupt I/O even when the peer stops reading.
	return c.ws.Close()
}

// NetConn returns the TLS connection under the WebSocket, so that a UDP
// tunnel can reach its socket (internal/tcptune). Bytes read or written on
// it bypass the framing.
func (c *Conn) NetConn() net.Conn { return c.ws.NetConn() }

// LocalAddr implements net.Conn.LocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	if uc := c.ws.UnderlyingConn(); uc != nil {
		return uc.LocalAddr()
	}
	return nil
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	if uc := c.ws.UnderlyingConn(); uc != nil {
		return uc.RemoteAddr()
	}
	return nil
}

// SetDeadline implements net.Conn.SetDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline. It needs no lock: a
// gorilla Conn passes the read deadline straight to the socket, which is safe
// to set while another goroutine reads.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

// SetWriteDeadline also applies to a write already in progress, without
// waiting for the writer lock. Clearing or extending it cancels the watchdog.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if !c.writeDeadline.Equal(t) {
		c.writeDeadline = t
		c.wakeWriteWaitersLocked()
	}
	c.armWriteTimerLocked()
	return nil
}

func (c *Conn) wakeWriteWaitersLocked() {
	if c.writeWake != nil {
		close(c.writeWake)
		c.writeWake = nil
	}
}

// waitWriteDelay keeps an intentional shaping pause inside net.Conn's
// lifecycle: Close and updated deadlines must also interrupt a sleeping
// writer. Deadline changes do not restart or shorten the selected pause.
func (c *Conn) waitWriteDelay(delay time.Duration) error {
	end := time.Now().Add(delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		c.deadlineMu.Lock()
		now := time.Now()
		deadline := c.writeDeadline
		switch {
		case c.closed.Load():
			c.deadlineMu.Unlock()
			return net.ErrClosed
		case c.writeTimedOut || (!deadline.IsZero() && !now.Before(deadline)):
			c.deadlineMu.Unlock()
			return c.writeTimeout()
		case !now.Before(end):
			c.deadlineMu.Unlock()
			return nil
		}
		if c.writeWake == nil {
			c.writeWake = make(chan struct{})
		}
		wake := c.writeWake
		c.deadlineMu.Unlock()
		until := end
		if !deadline.IsZero() && deadline.Before(until) {
			until = deadline
		}
		timer.Reset(time.Until(until))
		select {
		case <-wake:
		case <-timer.C:
		}
	}
}

// Leave the timer armed between writes. Repeated writes under the same
// deadline need no timer reset; the callback checks whether a write is active.
func (c *Conn) armWriteTimerLocked() {
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	if c.writeDeadline.IsZero() {
		return
	}
	delay := time.Until(c.writeDeadline)
	if c.writeTimer == nil {
		c.writeTimer = time.AfterFunc(delay, c.expireWrite)
	} else {
		c.writeTimer.Reset(delay)
	}
}

func (c *Conn) expireWrite() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	// A callback already scheduled before Stop may run after a deadline was
	// moved or cleared. Check the current deadline under the same lock.
	if !c.writing || c.writeDeadline.IsZero() || time.Now().Before(c.writeDeadline) {
		return
	}
	c.writeTimedOut = true
	_ = c.ws.Close()
}

func (c *Conn) writeTimeout() error {
	return &net.OpError{Op: "write", Net: "websocket", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: os.ErrDeadlineExceeded}
}
