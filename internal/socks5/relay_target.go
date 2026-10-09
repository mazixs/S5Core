package socks5

import (
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/relay"
	"github.com/mazixs/S5Core/internal/session"
)

// relayTarget arms the destination's remaining read when the client sends
// FIN. Before FIN an upload may legitimately wait for its first response;
// after FIN each received chunk refreshes the configured idle budget.
type relayTarget struct {
	net.Conn
	session    *session.Session
	mu         sync.Mutex
	halfClosed bool
}

func (c *relayTarget) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if c.halfClosed {
			c.armReadLocked()
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *relayTarget) Write(p []byte) (int, error) {
	deadline, _ := c.session.WriteDeadline(time.Now())
	if err := c.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *relayTarget) boundRemainingRead() {
	c.mu.Lock()
	c.halfClosed = true
	c.armReadLocked()
	c.mu.Unlock()
}

func (c *relayTarget) armReadLocked() {
	var deadline time.Time
	if idle := c.session.SLA().ReadIdle; idle > 0 {
		deadline = time.Now().Add(idle)
	}
	if grace, ok := c.session.GraceDeadline(); ok && (deadline.IsZero() || grace.Before(deadline)) {
		deadline = grace
	}
	_ = c.SetReadDeadline(deadline)
}

func (c *relayTarget) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return relay.ErrHalfCloseUnsupported
}
