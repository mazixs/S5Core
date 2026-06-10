// Package ws provides a net.Conn adapter over WebSocket binary frames.
// It is used to tunnel obfuscated SOCKS5 traffic so that DPI sees a
// standard WSS connection (e.g. a real-time web app) instead of a raw
// encrypted tunnel.
package ws

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Conn wraps a gorilla websocket.Conn to implement net.Conn.
// It buffers partial message reads so that Read()/Write() behave like
// a stream-oriented connection.
type Conn struct {
	ws      *websocket.Conn
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
	closed  atomic.Bool
}

// Wrap wraps an existing websocket.Conn.
func Wrap(ws *websocket.Conn) *Conn {
	return &Conn{ws: ws}
}

// Read implements net.Conn.Read.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		mt, data, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return 0, fmt.Errorf("ws: %w", err)
			}
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			// Skip non-binary messages (e.g. pings are handled internally)
			continue
		}
		if len(data) == 0 {
			continue
		}
		n := copy(b, data)
		if n < len(data) {
			c.readBuf = append(c.readBuf[:0], data[n:]...)
		}
		return n, nil
	}
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

// Close implements net.Conn.Close.
func (c *Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		// Send close frame and close underlying connection
		_ = c.ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return c.ws.Close()
	}
	return nil
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
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}
