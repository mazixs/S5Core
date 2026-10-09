package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// Prewarm (plan task R4-8) keeps at most one spare transport to the server
// open while the client is busy: a TCP connection for obfs, TCP, TLS and the
// upgrade for wss, and nothing of the obfuscation on it. A new tunnel that
// takes it skips the transport's round trips. Every spare the client does not
// use is an empty connection on the wire, so the rules keep them rare and
// without a rhythm:
//   - a spare is ordered only by a new tunnel that comes within
//     prewarmActivity of the one before it, so a lone tunnel after a quiet
//     spell, and a client that polls once a minute, order nothing;
//   - a spare that reaches its age is closed and not replaced; the age is
//     drawn from [prewarmAgeMin, prewarmAgeMax) and stays well inside the
//     server's 15 s handshake budget, which starts at the server's accept;
//   - a spare is taken only by a tunnel to the same transport, address and
//     WebSocket frame shape it was dialed for (spareKey).
const (
	prewarmActivity = 30 * time.Second
	prewarmAgeMin   = 6 * time.Second
	prewarmAgeMax   = 10 * time.Second
)

// spares is the client's pool; run starts it when PREWARM is on. Until then
// take dials as before, which is what tests that build a configuration by
// hand get.
var spares prewarmPool

type prewarmPool struct {
	mu      sync.Mutex
	on      bool
	gen     uint64 // bumped by stop, so a fill that outlives it closes its conn
	dialing bool
	spare   *spareConn
	lastKey string // the key of the last new tunnel
	lastAt  stamp
	now     func() time.Time // the wall clock: time.Now unless a test sets it
}

// stamp is a moment by both clocks: the monotonic one stands still while a
// laptop sleeps, and a spare that crossed a sleep is as dead as its age by
// the wall clock says.
type stamp struct{ mono, wall time.Time }

func (p *prewarmPool) stamp() stamp {
	wall := time.Now()
	if p.now != nil {
		wall = p.now()
	}
	return stamp{mono: time.Now(), wall: wall.Round(0)}
}

// since is the time from s to now by the larger of the two clocks.
func (s stamp) since(now stamp) time.Duration {
	return max(now.mono.Sub(s.mono), now.wall.Sub(s.wall))
}

type spareConn struct {
	conn   net.Conn
	key    string
	born   stamp // when its dial started
	maxAge time.Duration
	expire *time.Timer
}

// spareKey is what a spare must share with the tunnel that takes it. The
// WebSocket frame shape is fixed when the transport is dialed and the server
// may advise another one.
func spareKey(cfg clientParams) string {
	if cfg.usesWS() {
		return fmt.Sprintf("%s %d-%d %dms", nativeKey(cfg), cfg.WSMinFrame, cfg.WSMaxFrame, cfg.WSMaxJitterMs)
	}
	return nativeKey(cfg)
}

// start turns the pool on until ctx ends.
func (p *prewarmPool) start(ctx context.Context, cfg clientParams) {
	if !cfg.Prewarm {
		return
	}
	p.mu.Lock()
	p.on = true
	p.mu.Unlock()
	go func() {
		<-ctx.Done()
		p.stop()
	}()
}

// stop turns the pool off and closes the spare.
func (p *prewarmPool) stop() {
	p.mu.Lock()
	p.on = false
	p.gen++
	p.lastKey, p.lastAt = "", stamp{}
	s := p.spare
	p.spare = nil
	p.mu.Unlock()
	p.discard(s)
}

// take is dialServer for a new tunnel: the spare when there is a fitting one,
// a fresh dial otherwise. spare says which of the two it is.
func (p *prewarmPool) take(cfg clientParams) (conn net.Conn, spare bool, err error) {
	p.mu.Lock()
	if !p.on {
		p.mu.Unlock()
		conn, err = dialServer(cfg)
		return conn, false, err
	}
	now := p.stamp()
	busy := !p.lastAt.mono.IsZero() && p.lastAt.since(now) < prewarmActivity
	key := spareKey(cfg)
	p.lastKey, p.lastAt = key, now
	s := p.spare
	p.spare = nil
	if s != nil {
		s.expire.Stop()
	}
	if busy && !p.dialing {
		p.dialing = true
		go p.fill(cfg, key, p.gen)
	}
	p.mu.Unlock()

	if s != nil {
		if s.key == key && s.born.since(now) < s.maxAge && !hungUp(s.conn) {
			return s.conn, true, nil
		}
		p.discard(s)
	}
	conn, err = dialServer(cfg)
	return conn, false, err
}

func (p *prewarmPool) fill(cfg clientParams, key string, gen uint64) {
	born := p.stamp()
	maxAge := prewarmAgeMin + rand.N(prewarmAgeMax-prewarmAgeMin)
	cfg.noFastOpen = true
	conn, err := dialServer(waitingForUpgrade(cfg))

	p.mu.Lock()
	p.dialing = false
	if err != nil {
		p.mu.Unlock()
		slog.Debug("Spare connection was not opened", "transport", cfg.effectiveTransport(), "error", err)
		return
	}
	s := &spareConn{conn: conn, key: key, born: born, maxAge: maxAge}
	left := maxAge - born.since(p.stamp())
	if gen != p.gen || !p.on || key != p.lastKey || p.spare != nil || left <= 0 {
		p.mu.Unlock()
		p.discard(s)
		return
	}
	s.expire = time.AfterFunc(left, func() { p.expire(s) })
	p.spare = s
	p.mu.Unlock()
}

// expire closes a spare that reached its age unused. Nothing replaces it:
// only a new tunnel orders a spare.
func (p *prewarmPool) expire(s *spareConn) {
	p.mu.Lock()
	if p.spare != s {
		p.mu.Unlock()
		return
	}
	p.spare = nil
	p.mu.Unlock()
	p.discard(s)
}

func (p *prewarmPool) discard(s *spareConn) {
	if s == nil {
		return
	}
	if s.expire != nil {
		s.expire.Stop()
	}
	_ = s.conn.Close()
	minutes.prewarmWasted.Add(1)
}

// takenSpare is a spare as a tunnel takes it, with what the kernel had
// acknowledged of it by then: for wss that is after TLS and the upgrade, for
// obfs nothing. A setup that fails with nothing acknowledged since did not
// reach the server (sentNothing).
type takenSpare struct {
	net.Conn
	acked uint64
	known bool

	mu           sync.Mutex
	closed       bool
	ackedAtClose uint64
	knownAtClose bool
}

func newTakenSpare(c net.Conn) *takenSpare {
	s := &takenSpare{Conn: c}
	s.acked, s.known = bytesAcked(c)
	return s
}

func bytesAcked(c net.Conn) (uint64, bool) {
	info, ok := tcptune.InfoOf(c)
	return info.BytesAcked, ok
}

func (s *takenSpare) NetConn() net.Conn { return s.Conn }

// Close keeps the count a closed socket no longer gives.
func (s *takenSpare) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.ackedAtClose, s.knownAtClose = bytesAcked(s.Conn)
	}
	s.mu.Unlock()
	return s.Conn.Close()
}

// sentNothing says the peer acknowledged nothing since the spare was taken.
// Where the kernel does not say (not Linux, no socket), it is false.
func (s *takenSpare) sentNothing() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, ok := s.ackedAtClose, s.knownAtClose
	if !s.closed {
		now, ok = bytesAcked(s.Conn)
	}
	return s.known && ok && now == s.acked
}

// retryFailure is the failure of a setup that may be set up again, marked by
// markRetry.
func retryFailure(cfg clientParams, err error, spare *takenSpare) error {
	if err == nil {
		return nil
	}
	unanswered := endedUnanswered(err)
	if cfg.setup != nil {
		// A refusal that came in just before the application left is not repeated.
		if cfg.setup.abandoned() {
			return err
		}
		err = cfg.setup.failure(err)
	}
	markRetry(err, unanswered, spare)
	return err
}

// endedUnanswered says the server ended the stream without answering the
// greeting. It answers the greeting before it reads the request
// (internal/socks5/auth.go), so the request was not served.
func endedUnanswered(err error) bool {
	return tunnelPhaseOf(err) == phaseGreeting && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
}

// markRetry marks the failure of a setup that may be set up again: one on a
// spare by markSpareFailure, one on an early upgrade only where the server
// refused the upgrade (earlyRefused). An early upgrade answered with 101 is
// not repeated: behind a front the 101 and the acknowledgements are the
// front's, so silence or an end after it proves nothing (earlyPhaseOf keeps
// it off the policy instead).
func markRetry(err error, unanswered bool, spare *takenSpare) {
	if spare != nil {
		markSpareFailure(err, unanswered, spare)
		return
	}
	var te *tunnelError
	if errors.As(err, &te) && earlyRefused(err) {
		te.retryable = true
	}
}

// markSpareFailure marks the failure of a setup on a spare that was dead -
// the server closed it, the laptop slept, the network changed. A setup is
// repeated only where the server is proven not to have got the request: a
// failure before it was written, an end of stream without an answer to the
// greeting (unanswered), or any other failure before that answer with nothing
// of the spare acknowledged since it was taken. Any other failure before the
// answer is not repeated and does not count against the path either. A
// timeout is neither: the spare was alive, the server is slow or silent, and
// a fresh dial would wait the same. A close of our own is not a failure.
func markSpareFailure(err error, unanswered bool, spare *takenSpare) {
	var te *tunnelError
	if !errors.As(err, &te) || isTimeout(err) || errors.Is(err, net.ErrClosed) {
		return
	}
	switch {
	case te.phase == phaseDial, unanswered, te.phase == phaseGreeting && spare.sentNothing():
		te.retryable = true
	case te.phase == phaseGreeting:
		te.deadSpare = true
	}
}

// mayRetry says whether a failed setup may be repeated on a fresh transport
// without the application or the transport policy hearing of it. This is the
// one rule of a retry; what marks a failure retryable is markRetry.
func mayRetry(err error) bool {
	var te *tunnelError
	return errors.As(err, &te) && te.retryable
}

// countsAgainstThePath reports whether a failed tunnel says something about
// its transport. A failure of a dead spare does not, retried or not: it was
// the spare that was dead, not the path.
func countsAgainstThePath(err error) bool {
	var te *tunnelError
	return !errors.As(err, &te) || !te.retryable && !te.deadSpare
}
