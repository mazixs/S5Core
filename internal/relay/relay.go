// Package relay moves bytes between two connections and meters them.
//
// It is the part of a proxied connection that has nothing to do with SOCKS5:
// it copies, counts, asks the account whether it may continue, and passes on
// the end of a stream. Plan task Ф6-2 separated it from the message codec in
// internal/socks5 for that reason - the codec parses requests and knows
// nothing about traffic, this knows about traffic and nothing about requests.
package relay

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/mazixs/S5Core/internal/session"
)

// Status is what the account behind a session may still do. It is asked on
// the relay's flush boundary, so the answer is a small enum rather than a
// sentence: the relay does not log it, it turns it into a state of the
// session's account region.
type Status uint8

const (
	// Allowed: the account may keep transferring.
	Allowed Status = iota
	// QuotaExceeded: the traffic limit is spent.
	QuotaExceeded
	// Expired: the account's validity ended - by date, by being disabled, or
	// by being removed while the session ran.
	Expired
)

// AccountState maps a status onto the session's account region.
func (st Status) AccountState() session.Account {
	if st == Expired {
		return session.Expired
	}
	return session.QuotaExceeded
}

// ErrNotAllowed ends a relay whose account may no longer transfer: out of
// quota, expired or disabled while the session was running.
var ErrNotAllowed = errors.New("relay: session is no longer allowed to transfer")

// ErrHalfCloseUnsupported marks the case the half-close counter exists for:
// the transport under this connection has no half-close at all.
var ErrHalfCloseUnsupported = errors.New("relay: transport does not support half-close")

// HalfCloseObserver receives the result of a half-close attempt: nil when the
// write side was shut down, an error when it could not be.
type HalfCloseObserver func(err error)

type closeWriter interface {
	CloseWrite() error
}

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// FlushThreshold is how far the relay lets the traffic counter fall behind
// the truth: it flushes every 64 KiB, and that is also the boundary on which
// the account is asked whether it may continue, so a quota is overrun by at
// most this much.
const FlushThreshold = 64 * 1024

// HalfClose shuts down the write side of dst and reports the outcome.
//
// The error used to be discarded here. It is not cosmetic: not every
// transport in this codebase can half-close (a WebSocket connection cannot),
// and a destination that never sees EOF keeps waiting for a request that will
// not come. Since plan task Ф4-9 the obfuscation layer carries the half-close
// as a frame of its own, so the failure is rare; it is still counted.
func HalfClose(dst io.Writer, observe HalfCloseObserver) {
	cw, ok := dst.(closeWriter)
	if !ok {
		if observe != nil {
			observe(ErrHalfCloseUnsupported)
		}
		return
	}
	err := cw.CloseWrite()
	if observe != nil {
		observe(err)
	}
}

// Half is one direction of a relay: bytes from Src to Dst, metered when the
// account is, and ended when the account says so. It knows nothing about
// SOCKS5, only about copying, counting and the hooks below.
type Half struct {
	Dst io.Writer
	Src io.Reader
	// Counter, when set, receives the bytes written, in batches. Nil is an
	// unmetered relay: it still asks Status, it just has nowhere to put the
	// byte count.
	Counter *atomic.Int64
	// Status, when set, is asked on the flush boundary whether the account
	// may continue.
	//
	// It is independent of Counter. It used to be consulted only when a
	// counter existed, on the reasoning that the flush is when the counter is
	// up to date - true of a quota, but Status answers more than a quota: it
	// also reports an account that has been disabled, has expired, or has
	// been removed while the session ran. Those answers do not need a
	// counter, and tying them to one meant that the account whose counter had
	// just disappeared - the removed one - was the account that stopped being
	// asked. See F01 in docs/reports/code-quality-audit-2026-09-20.md.
	Status func() Status
	// Exhaust, when set, is told that the account may no longer transfer and
	// answers whether this half should keep copying anyway - true for the
	// direction that drains what the destination has already sent, during a
	// grace period. It is called at most once per half. Without it a status
	// other than Allowed ends the half, which is the answer an account that
	// has nobody to speak for it should get.
	Exhaust func(Status) bool
	// CloseDst, when set, is the half-close of Dst once Src is exhausted. It
	// is a function rather than a call to HalfClose so that two parties -
	// this half and the account's exhaustion - can share one attempt.
	//
	// Every hook here is optional, and that is the point of saying so: the
	// zero Half with a Dst and a Src copies one to the other and stops,
	// which is what the documentation above describes and what the package
	// promises. Leaving CloseDst out used to panic on the first end of
	// stream, so the smallest configuration the package documents was also
	// one it could not run (review finding R12).
	CloseDst func()
}

// closeDst passes on the end of the stream, if there is anyone to pass it to.
func (h *Half) closeDst() {
	if h.CloseDst != nil {
		h.CloseDst()
	}
}

// exhausted answers whether this half keeps copying after the account said
// stop. Without an Exhaust hook it does not: draining past the account's
// refusal is a grace the caller grants deliberately, not a default.
func (h *Half) exhausted(st Status) bool {
	return h.Exhaust != nil && h.Exhaust(st)
}

// Run copies until Src ends, Dst fails, or the account says stop. It returns
// nil for a clean end of stream, ErrNotAllowed when the account ended the
// half, and the transport's error otherwise. CloseDst runs in every case.
func (h *Half) Run() error {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	// The fast path is for a half that neither counts nor checks: there is
	// nothing to do on the flush boundary, so there is no reason to have one.
	if h.Counter == nil && h.Status == nil {
		_, err := io.CopyBuffer(h.Dst, h.Src, buf)
		h.closeDst()
		return err
	}

	var accumulated int64
	flush := func() {
		if h.Counter != nil && accumulated > 0 {
			h.Counter.Add(accumulated)
		}
		accumulated = 0
	}
	finish := func(e error) error {
		flush()
		h.closeDst()
		return e
	}

	checking := h.Status != nil
	for {
		nr, er := h.Src.Read(buf)
		if nr > 0 {
			nw, ew := h.Dst.Write(buf[0:nr])
			if nw > 0 {
				accumulated += int64(nw)
				// Flushing before the next read can push the batch over the
				// threshold keeps every step at or under 64 KiB, so the
				// counter is never further behind the truth than that - which
				// is what bounds how far a session runs past its quota. With
				// the pooled 32 KiB buffer this fires at exactly the same
				// points as a plain >= threshold test; a buffer as large as
				// the threshold would turn it into a flush per write.
				if accumulated+int64(len(buf)) > FlushThreshold {
					flush()
					if checking {
						if st := h.Status(); st != Allowed {
							if !h.exhausted(st) {
								return finish(ErrNotAllowed)
							}
							// This half is the drain. The account has been
							// asked its last question; what ends the half
							// now is the stream or the grace deadline.
							checking = false
						}
					}
				}
			}
			if ew != nil {
				return finish(ew)
			}
			if nr != nw {
				return finish(io.ErrShortWrite)
			}
		}
		if er != nil {
			if er != io.EOF {
				return finish(er)
			}
			return finish(nil)
		}
	}
}

// Result is what one half reports when it ends.
type Result struct {
	// ToDestination says which half: client to destination, or the reverse.
	ToDestination bool
	Err           error
}
