package socks5

import (
	"io"
	"sync/atomic"
	"time"
)

// Phase names one stage in the life of a proxied connection. The set is closed
// and known at compile time, which is what makes it safe to use as a metric
// label (docs/design/observability-policy.md).
type Phase string

const (
	// PhaseHandshake covers the version byte and the method negotiation,
	// i.e. everything before credentials are asked for.
	PhaseHandshake Phase = "handshake"
	// PhaseAuth covers credential verification only. Password hashing lives
	// here, so this is where Argon2id shows up if it is on the hot path.
	PhaseAuth Phase = "auth"
	// PhaseDNS covers name resolution, including failed lookups.
	PhaseDNS Phase = "dns"
	// PhaseDial covers TCP attempts against the resolved destination addresses.
	PhaseDial Phase = "dial"
	// PhaseFirstByte covers the wait between the SOCKS success reply and the first
	// byte the destination sends back. For HTTPS this is usually TLS data,
	// not the HTTP response.
	PhaseFirstByte Phase = "first_byte"
	// PhaseSession covers the whole connection, from entering the handler
	// (before waiting for the version byte) to the moment it returns.
	PhaseSession Phase = "session"
)

// PhaseObserver receives the duration of one finished phase. ok is false when
// the phase ended in an error, so that a slow failure is not averaged in with
// successful traffic.
//
// It is called on the connection goroutine and must not block. The callback
// gets a duration and a phase name - never an address, a username or a
// destination.
type PhaseObserver func(phase Phase, d time.Duration, ok bool)

// PhaseCounter is called with +1 when a connection enters a phase and -1 when
// it leaves it. The sum over a phase is "how many connections are sitting here
// right now", which is what turns "a third of connections hang waiting for the
// reply to CONNECT" into a visible anomaly instead of an anecdote.
type PhaseCounter func(phase Phase, delta int64)

// phaseTimer measures one phase and reports it exactly once.
type phaseTimer struct {
	observe PhaseObserver
	count   PhaseCounter
	phase   Phase
	start   time.Time
	// done is atomic because the two callers of end run in different
	// goroutines: the handler's defer and the relay's firstByteReader,
	// and handleConnect may return before the relay goroutine does.
	done atomic.Bool
}

// startPhase begins measuring. A nil observer and counter make every method a
// no-op, so instrumentation costs one branch when it is switched off.
func (s *Server) startPhase(p Phase) *phaseTimer {
	if s.config.ObservePhase == nil && s.config.CountPhase == nil {
		return nil
	}
	t := &phaseTimer{
		observe: s.config.ObservePhase,
		count:   s.config.CountPhase,
		phase:   p,
		start:   time.Now(),
	}
	if t.count != nil {
		t.count(p, 1)
	}
	return t
}

// end closes the phase. Calling it twice is deliberate and harmless: handlers
// use defer for the error paths and an explicit call on the happy path.
func (t *phaseTimer) end(ok bool) {
	if t == nil || !t.done.CompareAndSwap(false, true) {
		return
	}
	if t.count != nil {
		t.count(t.phase, -1)
	}
	if t.observe != nil {
		t.observe(t.phase, time.Since(t.start), ok)
	}
}

// firstByteReader reports how long the destination took to produce its first
// byte. It wraps only the read side of the target connection and adds one
// predictable branch per read.
type firstByteReader struct {
	io.Reader
	timer *phaseTimer
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.timer.end(true)
	} else if err != nil {
		// The destination closed or failed without sending anything: still a
		// finished wait, just not a successful one.
		r.timer.end(false)
	}
	return n, err
}

// halfCloseObserver returns the configured observer, or nil when nobody is
// listening - so the copy loops keep their current cost.
func (s *Server) halfCloseObserver() HalfCloseObserver {
	return s.config.ObserveHalfClose
}
