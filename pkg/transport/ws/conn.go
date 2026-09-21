// Package ws provides a net.Conn adapter over WebSocket binary frames.
// It is used to tunnel obfuscated SOCKS5 traffic so that DPI sees a
// standard WSS connection (e.g. a real-time web app) instead of a raw
// encrypted tunnel.
package ws

import (
	"fmt"
	"io"
	"net"
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

	err := c.ws.WriteMessage(websocket.BinaryMessage, b)
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

	// The close frame is a courtesy: it tells the peer the connection ended
	// in an orderly way. It is sent only if no write is in flight. A gorilla
	// Conn takes one writer at a time and keeps its write deadline in a plain
	// field, so writing the frame from here while another goroutine is in
	// Write is a data race - one that stayed hidden while Close was only ever
	// called by the goroutine that owned the connection.
	if c.writeMu.TryLock() {
		_ = c.ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.writeMu.Unlock()
	}

	// Closing the socket is what actually ends the connection, and it is what
	// releases a writer that is blocked in the middle of a frame.
	return c.ws.Close()
}

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

// SetWriteDeadline implements net.Conn.SetWriteDeadline, under the same lock
// as a write.
//
// A gorilla Conn keeps its write deadline in a plain field and reads it while
// flushing a frame, so setting it from another goroutine is a data race - the
// same race Close already avoids by taking this lock. The deadline is set once
// per write by the layer above, so the extra lock costs one uncontended
// acquire per write and removes the last unsynchronised access to a gorilla
// write.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.SetWriteDeadline(t)
}
