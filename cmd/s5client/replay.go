package main

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// earlyStreamBytes bounds what the tunnel of an optimistic CONNECT keeps of
// the application's bytes until the server answers its greeting, as
// earlyQueueBytes does for the datagrams of an association.
const earlyStreamBytes = 64 << 10

// replayConn is the tunnel of an optimistic CONNECT that may be set up again:
// the application has heard success and is sending, and nothing has reached
// it from the server. A setup that fails before the server answers the
// greeting is set up once more on a fresh transport only where the server is
// proven not to have got the request (markRetry): on a spare an end of
// stream without that answer, or nothing of the spare acknowledged since it
// was taken; on an early upgrade a refusal of the upgrade. The request and
// the application's bytes are written again, and the application notices
// nothing (readGreeting). Past earlyStreamBytes, or without that proof, the
// application's connection is reset instead.
//
// dialObfsTunnel makes one for a tunnel on a spare or an early upgrade. Until
// the greeting is answered a failed write is not the application's to hear:
// the bytes are kept, and the transport is closed so that its reader learns
// of it and decides.
type replayConn struct {
	cfg     clientParams
	request []byte
	spare   *takenSpare // the spare under the first attempt; touched by the reader only

	cur     atomic.Pointer[connRef]
	closed  atomic.Bool
	settled atomic.Bool

	mu       sync.Mutex // held across writes until settled
	kept     []byte
	over     bool
	wroteEnd bool
	writeErr error
}

type connRef struct{ net.Conn }

func newReplayConn(c net.Conn, cfg clientParams, request []byte, spare *takenSpare) *replayConn {
	r := &replayConn{cfg: cfg, request: request, spare: spare}
	r.cur.Store(&connRef{c})
	return r
}

func (r *replayConn) current() net.Conn { return r.cur.Load().Conn }

// NetConn is the transport of the current attempt, for the walks of
// obfs.LogIDOf and tcptune.
func (r *replayConn) NetConn() net.Conn { return r.current() }

func (r *replayConn) Read(b []byte) (int, error) { return r.current().Read(b) }

func (r *replayConn) Write(b []byte) (int, error) {
	if r.settled.Load() {
		return r.current().Write(b)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled.Load() {
		return r.current().Write(b)
	}
	r.keep(b)
	n, err := r.current().Write(b)
	if err != nil && !r.over {
		r.failed(err)
		return len(b), nil
	}
	return n, err
}

// CloseWrite is the application's end of its stream, which a retry carries
// too.
func (r *replayConn) CloseWrite() error {
	if r.settled.Load() {
		return closeWrite(r.current())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled.Load() {
		return closeWrite(r.current())
	}
	r.wroteEnd = true
	err := closeWrite(r.current())
	if err != nil && !r.over {
		r.failed(err)
		return nil
	}
	return err
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (r *replayConn) keep(b []byte) {
	if r.over {
		return
	}
	if len(r.kept)+len(b) > earlyStreamBytes {
		r.over, r.kept = true, nil
		return
	}
	r.kept = append(r.kept, b...)
}

// failed records a write the reader is to hear of, and wakes it.
func (r *replayConn) failed(err error) {
	if r.writeErr == nil {
		r.writeErr = err
	}
	_ = r.current().Close()
}

// failure names the write that closed the transport instead of the read of
// a closed connection that followed it, and marks a spare's.
func (r *replayConn) failure(err error) error {
	if r.closed.Load() {
		return err
	}
	unanswered := endedUnanswered(err)
	r.mu.Lock()
	if r.writeErr != nil {
		err = tunnelFail(phaseGreeting, "failed to send: %w", r.writeErr)
	}
	r.mu.Unlock()
	markRetry(err, unanswered, r.spare)
	return err
}

// again sets the tunnel up on a fresh transport after a failure that may be
// repeated and writes again what went to the one that failed. It returns the
// failure that stands when that cannot be done.
func (r *replayConn) again(failure error) error {
	r.wasted()
	_ = r.current().Close()
	r.mu.Lock()
	over := r.over
	r.mu.Unlock()
	if over || r.closed.Load() {
		return failure
	}
	slog.Debug("Tunnel setup failed before the server answered; setting it up again",
		"transport", r.cfg.effectiveTransport(), "error", failure)
	c, _, err := handshakeTunnel(waitingForUpgrade(r.cfg), r.request, dialFresh)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.over {
		_ = c.Close()
		return failure
	}
	if len(r.kept) > 0 {
		if _, err := c.Write(r.kept); err != nil {
			_ = c.Close()
			return tunnelFail(phaseGreeting, "failed to send: %w", err)
		}
	}
	if r.wroteEnd {
		if err := closeWrite(c); err != nil {
			_ = c.Close()
			return tunnelFail(phaseGreeting, "failed to send: %w", err)
		}
	}
	r.writeErr = nil
	r.cur.Store(&connRef{c})
	if r.closed.Load() {
		_ = c.Close()
		return net.ErrClosed
	}
	return nil
}

// wasted counts the spare under the first attempt as one the server never
// answered on.
func (r *replayConn) wasted() {
	if r.spare != nil {
		r.spare = nil
		minutes.prewarmWasted.Add(1)
	}
}

// settle is told the server answered the greeting: nothing is set up again
// from here, so nothing is kept for it. A write that failed meanwhile closed
// the transport, and the server has spoken, so it is not repeated either.
func (r *replayConn) settle() error {
	r.mu.Lock()
	r.settled.Store(true)
	r.kept = nil
	werr := r.writeErr
	r.mu.Unlock()
	if r.spare != nil {
		minutes.prewarmUsed.Add(1)
	}
	if werr != nil {
		return tunnelFail(phaseConnectReply, "failed to send: %w", werr)
	}
	return nil
}

func (r *replayConn) Close() error {
	r.closed.Store(true)
	return r.current().Close()
}

func (r *replayConn) LocalAddr() net.Addr                { return r.current().LocalAddr() }
func (r *replayConn) RemoteAddr() net.Addr               { return r.current().RemoteAddr() }
func (r *replayConn) SetDeadline(t time.Time) error      { return r.current().SetDeadline(t) }
func (r *replayConn) SetReadDeadline(t time.Time) error  { return r.current().SetReadDeadline(t) }
func (r *replayConn) SetWriteDeadline(t time.Time) error { return r.current().SetWriteDeadline(t) }

// readGreeting reads the server's answer to a deferred greeting. This is
// where a replayConn is set up again, once.
func readGreeting(c net.Conn) (byte, error) {
	r, ok := c.(*replayConn)
	if !ok {
		return readServerGreeting(c)
	}
	method, err := readServerGreeting(r)
	if err != nil {
		if err = r.failure(err); mayRetry(err) {
			if err = r.again(err); err == nil {
				if method, err = readServerGreeting(r); err != nil {
					err = r.failure(err)
				}
			}
		}
	}
	if err != nil {
		r.wasted()
		return 0, err
	}
	if err := r.settle(); err != nil {
		return 0, err
	}
	return method, nil
}
