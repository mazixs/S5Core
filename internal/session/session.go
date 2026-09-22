// Package session is the explicit state machine of one proxied connection
// (plan task Ф6-1).
//
// The lifecycle used to be implicit: the state of a connection was wherever
// the handler goroutine happened to be, the deadline regime was a string
// passed down the transport stack, and the quota was a boolean the relay
// asked on a flush boundary. None of that could be inspected, and a fault
// in it - a third of connections parked waiting for the reply to CONNECT
// (docs/reports/v1.4.4-field-run.md, bug 1) - showed up in a metric only
// after somebody guessed where to put a counter.
//
// A Session is a hierarchical machine with three orthogonal regions:
//
//   - protocol: where the connection is in the SOCKS5 conversation
//     (Accepted, Handshake, Dialing, Relay, HalfClosed, Closed);
//   - frames: what the obfuscation reader is waiting for on the wire
//     (AwaitHeader, AwaitBody, Deliver, FrameError), or Unframed for the plain
//     listener, which has no frames;
//   - account: whether the account behind the session may still transfer
//     (WithinQuota, Grace, QuotaExceeded, Expired).
//
// The regions are orthogonal because their product is not a machine anyone
// can read: 6 x 5 x 4 states, most of them meaningless. What couples them is
// written down in exactly one place, Exhaust: an event in the account region
// moves the protocol region to HalfClosed, so a quota that runs out during a
// transfer is felt during the transfer and not at the next login.
//
// Every state carries its own SLA (SLA), and the transport asks the session
// for the deadline of the read or write it is about to do (ReadDeadline,
// WriteDeadline) instead of keeping a regime of its own. Every transition is
// reported to an Observer, which is how the states become a metric.
//
// The package knows nothing about sockets, metrics or accounts. It is a
// model; internal/socks5 drives the protocol and account regions, pkg/obfs
// drives the frames region through a hook, and pkg/s5server turns the
// transitions into telemetry.
package session

import (
	"sync"
	"sync/atomic"
	"time"
)

// Region names one of the three orthogonal regions. It is a metric label,
// so the set is closed and spelled here.
type Region uint8

const (
	RegionProtocol Region = iota
	RegionFrames
	RegionAccount
)

func (r Region) String() string {
	switch r {
	case RegionProtocol:
		return "protocol"
	case RegionFrames:
		return "frames"
	case RegionAccount:
		return "account"
	}
	return "unknown"
}

// StateName spells state s of this region the way the metric does.
func (r Region) StateName(s uint8) string {
	switch r {
	case RegionProtocol:
		return Protocol(s).String()
	case RegionFrames:
		return Frames(s).String()
	case RegionAccount:
		return Account(s).String()
	}
	return "unknown"
}

// Protocol is the state of the SOCKS5 conversation.
type Protocol uint8

const (
	// Accepted: the socket is open and nothing has been read from it. A
	// scanner that connects and says nothing sits here.
	Accepted Protocol = iota
	// Handshake: version, methods, credentials and the request are being read.
	Handshake
	// Dialing: the destination is being resolved and connected to. The client
	// is waiting for its reply to CONNECT - this is the state bug 1 of the
	// bug report piled connections into.
	Dialing
	// Relay: bytes flow. A UDP association and the 0x83 tunnel are relays too;
	// Kind says which deadlines apply.
	Relay
	// HalfClosed: one direction has ended and the other drains. A peer's FIN
	// puts a session here, and so does the account region (Exhaust).
	HalfClosed
	// Closed: terminal.
	Closed
)

func (p Protocol) String() string {
	switch p {
	case Accepted:
		return "accepted"
	case Handshake:
		return "handshake"
	case Dialing:
		return "dialing"
	case Relay:
		return "relay"
	case HalfClosed:
		return "half_closed"
	case Closed:
		return "closed"
	}
	return "unknown"
}

// Frames is what the obfuscation reader is waiting for. It changes on every
// socket read, so it is observed as a distribution (how many sessions sit
// mid-frame right now) rather than as events.
type Frames uint8

const (
	// Unframed: the transport has no frames. The region does not exist for
	// this session and never leaves this state.
	Unframed Frames = iota
	// AwaitHeader: idle between frames, waiting for the next masked length.
	AwaitHeader
	// AwaitBody: a header arrived and the rest of the frame has not. A session
	// that stays here is a client that stopped mid-frame, or a middlebox that
	// cut a segment - and it holds the reader until the frame completes.
	AwaitBody
	// Deliver: the last frame was decoded and handed up; nothing is awaited.
	Deliver
	// FrameError: the reader refused a frame. Terminal for the region.
	FrameError
)

func (f Frames) String() string {
	switch f {
	case Unframed:
		return "unframed"
	case AwaitHeader:
		return "await_header"
	case AwaitBody:
		return "await_body"
	case Deliver:
		return "deliver"
	case FrameError:
		return "frame_error"
	}
	return "unknown"
}

// Account is whether the account behind the session may still transfer.
type Account uint8

const (
	// WithinQuota: allowed. Also the state of a session nobody meters.
	WithinQuota Account = iota
	// Grace: the account ran out while the session was transferring. What
	// is in flight may finish, for SLA.Grace at most; nothing new goes to
	// the destination.
	Grace
	// QuotaExceeded: terminal, the traffic limit is spent.
	QuotaExceeded
	// Expired: terminal, the account's validity ended - by date, by being
	// disabled or by being removed.
	Expired
)

func (a Account) String() string {
	switch a {
	case WithinQuota:
		return "within_quota"
	case Grace:
		return "grace"
	case QuotaExceeded:
		return "quota_exceeded"
	case Expired:
		return "expired"
	}
	return "unknown"
}

// Kind says what a relay carries, which decides the deadlines it lives under.
type Kind uint8

const (
	// Stream: a TCP relay. Idle for longer than the relay timeout means dead.
	Stream Kind = iota
	// Tunnel: the 0x83 UDP-over-TCP tunnel or the TCP side of a UDP
	// association. Silent whenever the application has nothing to send, so
	// no idle timeout applies to it - only the per-frame one.
	Tunnel
)

// SLA is the budget of each state. A zero field means no bound of that kind.
type SLA struct {
	// Handshake is the absolute budget from accept to the reply to the
	// request; it covers Accepted, Handshake and Dialing. It is not an idle
	// timeout: a client sending one byte a second keeps an idle timeout alive
	// forever.
	Handshake time.Duration
	// Dial bounds one connection attempt to the destination.
	Dial time.Duration
	// ReadIdle and WriteIdle are the relay's idle timeouts, refreshed by
	// traffic. They do not apply to a Tunnel.
	ReadIdle  time.Duration
	WriteIdle time.Duration
	// Grace is how long a session drains after its account ran out. Zero
	// ends the session where the quota is noticed.
	Grace time.Duration
	// FrameBody is how long a frame may stay incomplete once its header has
	// arrived. It applies to tunnels too: a half frame blocks the reader no
	// matter what the connection carries.
	FrameBody time.Duration
}

// Transition is one reported state change.
type Transition struct {
	Transport string
	Region    Region
	From, To  uint8
	// Illegal marks an attempt the table refused. The state did not change;
	// the report exists because an illegal transition is a bug in a driver,
	// and a bug that is counted gets found.
	Illegal bool
}

// FromName and ToName spell the states the way the metric does.
func (t Transition) FromName() string { return t.Region.StateName(t.From) }
func (t Transition) ToName() string   { return t.Region.StateName(t.To) }

// Observer receives every transition. It runs on the goroutine that made the
// transition and must not block. For the frames region that goroutine is the
// reader's, once per socket wait.
type Observer func(Transition)

// Session is the machine for one connection. Every method is safe to call on
// a nil *Session and does nothing: a connection that reached the SOCKS5 core
// without going through the listener pipeline - a test, an SDK user - simply
// has no session, and the drivers do not have to care.
type Session struct {
	reg        *Registry
	transport  string
	sla        SLA
	acceptedAt time.Time

	kind     atomic.Uint32
	protocol atomic.Uint32
	frames   atomic.Uint32
	account  atomic.Uint32

	// graceAt is when Grace began, unix nanoseconds; exhausted is the
	// terminal account state Grace resolves to when the session closes.
	frameBodyAt atomic.Int64
	graceAt     atomic.Int64
	exhausted   atomic.Uint32

	closeOnce sync.Once
}

// Transport names the listener the connection arrived on.
func (s *Session) Transport() string {
	if s == nil {
		return ""
	}
	return s.transport
}

// SLA returns the budgets this session lives under.
func (s *Session) SLA() SLA {
	if s == nil {
		return SLA{}
	}
	return s.sla
}

// Protocol returns the state of the protocol region.
func (s *Session) Protocol() Protocol {
	if s == nil {
		return Closed
	}
	return Protocol(s.protocol.Load())
}

// Frames returns the state of the frames region.
func (s *Session) Frames() Frames {
	if s == nil {
		return Unframed
	}
	return Frames(s.frames.Load())
}

// Account returns the state of the account region.
func (s *Session) Account() Account {
	if s == nil {
		return WithinQuota
	}
	return Account(s.account.Load())
}

// Kind returns what the relay carries.
func (s *Session) Kind() Kind {
	if s == nil {
		return Stream
	}
	return Kind(s.kind.Load())
}

// Become records what the relay is about to carry. It is not a transition:
// the kind is an attribute of the Relay state, set once on the way in.
func (s *Session) Become(k Kind) {
	if s == nil {
		return
	}
	s.kind.Store(uint32(k))
}

// Enter moves the protocol region to p and reports whether it did. Entering
// the current state again is a no-op that returns true; a move the table
// does not allow is reported to the observer and returns false.
func (s *Session) Enter(p Protocol) bool {
	if s == nil {
		return false
	}
	return s.move(RegionProtocol, &s.protocol, uint32(p), legalProtocol)
}

// Frame moves the frames region to f. An unframed session refuses every
// move: the region does not exist for it, and a driver that thinks otherwise
// is wired to the wrong transport.
func (s *Session) Frame(f Frames) bool {
	if s == nil {
		return false
	}
	// Only the frame reader drives this region. Publish the absolute start
	// before AwaitBody, so concurrent writes cannot extend an incomplete frame.
	if f == AwaitBody && s.Frames() != AwaitBody && legalFrames(s.frames.Load(), uint32(f)) {
		s.frameBodyAt.Store(time.Now().UnixNano())
	}
	return s.move(RegionFrames, &s.frames, uint32(f), legalFrames)
}

// Exhaust is the one coupling between regions: the account can no longer
// transfer, for the given reason (QuotaExceeded or Expired).
//
// With a grace budget and a relay under way the account region goes to Grace
// and the protocol region to HalfClosed: the destination's side is to be
// closed by the caller, what the destination has already sent may still
// reach the client, and SLA.Grace bounds how long. Without a grace budget,
// or before the relay started, the account region goes straight to the
// terminal state and the caller ends the session.
//
// It returns true for the call that made the transition, so that of two
// relay goroutines noticing the same exhaustion exactly one performs the
// half-close.
func (s *Session) Exhaust(reason Account) bool {
	if s == nil {
		return false
	}
	if reason != Expired {
		reason = QuotaExceeded
	}
	s.exhausted.CompareAndSwap(0, uint32(reason))

	p := s.Protocol()
	if s.sla.Grace > 0 && (p == Relay || p == HalfClosed) {
		if !s.account.CompareAndSwap(uint32(WithinQuota), uint32(Grace)) {
			return false
		}
		s.graceAt.Store(time.Now().UnixNano())
		s.observe(RegionAccount, uint32(WithinQuota), uint32(Grace), false)
		s.Enter(HalfClosed)
		return true
	}
	return s.move(RegionAccount, &s.account, uint32(reason), legalAccount)
}

// InGrace reports whether the session is draining after exhaustion.
func (s *Session) InGrace() bool { return s.Account() == Grace }

// GraceDeadline is the moment the drain ends, and false when there is none.
func (s *Session) GraceDeadline() (time.Time, bool) {
	if s == nil || s.Account() != Grace {
		return time.Time{}, false
	}
	return time.Unix(0, s.graceAt.Load()).Add(s.sla.Grace), true
}

// ReadDeadline is the deadline the transport should arm for the read it is
// about to do, given the states the session is in right now.
func (s *Session) ReadDeadline(now time.Time) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return s.deadline(now, s.sla.ReadIdle, true)
}

// WriteDeadline is the same for a write.
func (s *Session) WriteDeadline(now time.Time) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return s.deadline(now, s.sla.WriteIdle, false)
}

// deadline is the SLA table read for one operation. The stricter bound
// always wins, so adding a state never loosens a deadline that applied
// before.
func (s *Session) deadline(now time.Time, idle time.Duration, read bool) (time.Time, bool) {
	var d time.Time
	switch s.Protocol() {
	case Accepted, Handshake, Dialing:
		// The idle timeout still applies inside the setup; the budget caps
		// how long the whole thing may take.
		d = after(now, idle)
		d = stricter(d, after(s.acceptedAt, s.sla.Handshake))
	case Relay, HalfClosed:
		if s.Kind() == Stream {
			d = after(now, idle)
		}
		if read && s.Frames() == AwaitBody {
			d = stricter(d, after(time.Unix(0, s.frameBodyAt.Load()), s.sla.FrameBody))
		}
		if end, ok := s.GraceDeadline(); ok {
			d = stricter(d, end)
		}
	case Closed:
		// Nothing more is expected of the connection; whatever is armed
		// stays armed.
	}
	return d, !d.IsZero()
}

// Close ends the session: the protocol region reaches Closed, a drain that
// was under way resolves to the reason it began for, and the session leaves
// its registry. Calling it again does nothing.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.Account() == Grace {
			s.move(RegionAccount, &s.account, s.exhausted.Load(), legalAccount)
		}
		s.Enter(Closed)
		if s.reg != nil {
			s.reg.remove(s)
		}
	})
}

// move performs one guarded, lock-free transition.
func (s *Session) move(r Region, state *atomic.Uint32, to uint32, legal func(from, to uint32) bool) bool {
	for {
		from := state.Load()
		if from == to {
			return true
		}
		if !legal(from, to) {
			s.observe(r, from, to, true)
			return false
		}
		if state.CompareAndSwap(from, to) {
			s.observe(r, from, to, false)
			return true
		}
	}
}

func (s *Session) observe(r Region, from, to uint32, illegal bool) {
	if s.reg == nil || s.reg.observe == nil {
		return
	}
	s.reg.observe(Transition{
		Transport: s.transport,
		Region:    r,
		From:      uint8(from),
		To:        uint8(to),
		Illegal:   illegal,
	})
}

// The transition tables. Same-state moves never reach them.

func legalProtocol(from, to uint32) bool {
	if Protocol(to) == Closed {
		return Protocol(from) != Closed
	}
	switch Protocol(from) {
	case Accepted:
		return Protocol(to) == Handshake
	case Handshake:
		// A UDP association or a tunnel has nothing to dial: it goes
		// straight to Relay.
		return Protocol(to) == Dialing || Protocol(to) == Relay
	case Dialing:
		return Protocol(to) == Relay
	case Relay:
		return Protocol(to) == HalfClosed
	}
	return false
}

func legalFrames(from, to uint32) bool {
	switch Frames(from) {
	case Unframed, FrameError:
		return false
	}
	return Frames(to) != Unframed
}

func legalAccount(from, to uint32) bool {
	switch Account(from) {
	case WithinQuota:
		return Account(to) != WithinQuota
	case Grace:
		return Account(to) == QuotaExceeded || Account(to) == Expired
	}
	return false
}

// after is t+d, or the zero time when d sets no bound.
func after(t time.Time, d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return t.Add(d)
}

// stricter is the earlier of two deadlines, ignoring a zero one.
func stricter(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	}
	return a
}
