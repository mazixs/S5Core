package veil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

// Plan task Ф5-3. A prologue that is nothing but random bytes is valid
// forever: an observer who records one can replay it a year later, and the
// only thing standing in the way is the server's replay history, which is
// finite and local. Binding the prologue to a coarse clock puts an expiry on
// it that costs no state at all.
//
// The construction is obfs4's, not VMess's, and the difference is the whole
// point. VMess authenticated a timestamp with a window of plus or minus 90
// seconds; the result was a stream of "invalid user" failures from clients
// whose clocks were off, and VLESS removed the dependency on time entirely.
// The failure there was not the idea of a clock - it was the precision. An
// hour-wide epoch with a window on either side tolerates clock skew measured
// in hours, which is what unsynchronised devices actually exhibit: a router
// that came back from a power cut has no idea what time it is, and NTP
// arrives seconds to minutes later.

// EpochSeconds is how coarse the clock is. One hour: fine enough to expire a
// recorded prologue, coarse enough that no realistic skew lands outside the
// window.
const EpochSeconds = 3600

// DefaultEpochWindow is how many epochs on each side of its own the server
// accepts. Two, not one, because the acceptance test for this task is a
// client two hours out: a skew of exactly two hours shifts the epoch by
// exactly two, and a window of one would refuse it.
//
// The window is what the tolerance costs: a recorded prologue stays valid
// for at most 2*DefaultEpochWindow+1 hours instead of forever.
const DefaultEpochWindow = 2

// DefaultDiagnosticWindow is how far out the server looks when nothing in
// the accepting window matched, purely to tell "this client's clock is
// wrong" apart from "this is a scanner". It changes no decision - see
// Clocked.Accept.
const DefaultDiagnosticWindow = 36

// clockedTagSize is how much of the prologue the MAC takes. Eight bytes of
// MAC leave 24 bytes of randomness, which is more than enough to keep two
// prologues from colliding, and forging one without the PSK is a 2^64
// problem for an attacker who gets no feedback about which guess was closer.
const clockedTagSize = 8

// clockedRandomSize is the rest of the prologue.
const clockedRandomSize = SaltSize - clockedTagSize

// clockedMACLabel keeps this MAC from ever equalling a MAC computed
// elsewhere under the same PSK.
const clockedMACLabel = "S5Core/veil v1 epoch"

// diagnosticInterval is the shortest gap between two diagnostic searches.
// Without it, every byte of scanner traffic would cost the server a search
// over the diagnostic window instead of over the accepting one - a cheap way
// to multiply the work an unauthenticated peer can ask for.
const diagnosticInterval = time.Second

// Clocked is the symmetric scheme with an hour attached: the prologue is
// random bytes plus a MAC over those bytes and the current epoch, and the
// session secret includes the epoch the MAC was made for.
//
// Because the epoch is inside the secret rather than on the wire, an
// observer sees 32 bytes that look exactly like the 32 random bytes
// Symmetric sends. Nothing about the hour is visible, and nothing about it
// is negotiated.
//
// A Clocked is safe for concurrent use and is meant to be shared by every
// connection of one listener.
type Clocked struct {
	// Context is what this end's keys are bound to: the format version and,
	// when set, the node (plan task Ф5-4). A client stamps it into the
	// prologue MAC; a server accepts it unless Accepts says otherwise.
	//
	// Because it is inside the MAC, a server recognises which context a
	// client used before deriving anything - so accepting two of them costs
	// one extra HMAC, not a second decryption attempt.
	Context Context
	// Accepts lists the contexts a server will recognise, in the order it
	// tries them. Empty means Context alone. Two entries are what a format
	// migration looks like: the new labels and the old, for as long as
	// clients in the field have not caught up (plan task Ф5-7).
	Accepts []Context
	// Now is the clock, injectable so that tests can stand on either side of
	// an hour boundary without waiting for one. Nil means time.Now.
	Now func() time.Time
	// Window is how many epochs either side of its own a server accepts.
	// Zero means DefaultEpochWindow.
	Window int
	// DiagnosticWindow is how far out a server looks to recognise a skewed
	// clock. Zero means DefaultDiagnosticWindow; negative disables the
	// search.
	DiagnosticWindow int
	// OnClockSkew, when set, is called by a server that recognised a valid
	// prologue from outside the accepting window. The argument is how many
	// epochs the peer is out by, signed: positive means the peer's clock
	// runs ahead. The connection is refused either way - this exists so the
	// operator can tell a broken clock from a scanner, which is the whole
	// difference between a bug report and noise.
	//
	// It is called from the connection's read path and must not block.
	OnClockSkew func(epochs int64)

	lastDiagnostic atomic.Int64 // unix nanoseconds, rate-limits the search
}

// NewClocked returns the scheme with default windows and the system clock.
func NewClocked() *Clocked { return &Clocked{} }

func (*Clocked) Name() string { return "clocked" }
func (*Clocked) Size() int    { return SaltSize }

func (c *Clocked) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// epoch is the coarse hour of the scheme's clock.
func (c *Clocked) epoch() int64 { return c.now().Unix() / EpochSeconds }

func (c *Clocked) window() int {
	if c.Window <= 0 {
		return DefaultEpochWindow
	}
	return c.Window
}

// Offer draws the random half, stamps it with the current epoch and this
// end's context, and returns the secret for that pair.
func (c *Clocked) Offer(psk, dst []byte) (Result, error) {
	if len(dst) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue buffer is %d bytes, the clocked scheme needs %d", len(dst), SaltSize)
	}
	if _, err := (Symmetric{}).Offer(psk, dst); err != nil {
		return Result{}, err
	}
	epoch := c.epoch()
	tag := epochTag(psk, dst[:clockedRandomSize], epoch, c.Context)
	copy(dst[clockedRandomSize:], tag[:clockedTagSize])
	return Result{Secret: clockedSecret(dst, epoch), Context: c.Context.normalized()}, nil
}

// Accept finds the epoch whose MAC matches and returns the secret for it.
//
// When nothing matches, it returns the secret for its own epoch: a secret
// the peer cannot have derived, so the connection fails on the tag of the
// first frame like any other wrong key. That is deliberate. Refusing here
// would make a wrong prologue cheaper to reject than a wrong payload, and
// the gap between the two is what an active probe measures.
func (c *Clocked) Accept(psk, prologue []byte) (Result, error) {
	if len(prologue) != SaltSize {
		return Result{}, fmt.Errorf("veil: prologue is %d bytes, the clocked scheme needs %d", len(prologue), SaltSize)
	}

	mine := c.epoch()
	if epoch, ctx, ok := c.search(psk, prologue, mine, c.window()); ok {
		return Result{Secret: clockedSecret(prologue, epoch), Context: ctx.normalized()}, nil
	}

	c.diagnose(psk, prologue, mine)
	return Result{Secret: clockedSecret(prologue, mine), Context: c.Context.normalized()}, nil
}

// accepts is the list of contexts this end recognises.
func (c *Clocked) accepts() []Context {
	if len(c.Accepts) == 0 {
		return []Context{c.Context}
	}
	return c.Accepts
}

// search walks the epochs nearest first and, within an epoch, the contexts
// in the order they were configured. The ordinary case - a client whose
// clock is right, speaking the current format - costs one MAC.
func (c *Clocked) search(psk, prologue []byte, mine int64, window int) (int64, Context, bool) {
	random, tag := prologue[:clockedRandomSize], prologue[clockedRandomSize:]
	contexts := c.accepts()
	for d := 0; d <= window; d++ {
		for _, epoch := range [2]int64{mine - int64(d), mine + int64(d)} {
			for _, ctx := range contexts {
				want := epochTag(psk, random, epoch, ctx)
				if hmac.Equal(tag, want[:clockedTagSize]) {
					return epoch, ctx, true
				}
			}
			if d == 0 {
				break // -0 and +0 are the same epoch
			}
		}
	}
	return 0, Context{}, false
}

// diagnose looks further out than the accepting window, only to name what
// went wrong. It never changes the outcome: the caller has already decided
// to hand back a secret that will not match.
func (c *Clocked) diagnose(psk, prologue []byte, mine int64) {
	if c.OnClockSkew == nil || c.DiagnosticWindow < 0 {
		return
	}
	wide := c.DiagnosticWindow
	if wide == 0 {
		wide = DefaultDiagnosticWindow
	}
	if wide <= c.window() {
		return
	}

	// Rate-limit: a scanner must not be able to buy a wide search with every
	// connection it opens. A skewed clock is a standing condition, so one
	// report per second says everything a rare one would.
	now := c.now().UnixNano()
	last := c.lastDiagnostic.Load()
	if now-last < int64(diagnosticInterval) || !c.lastDiagnostic.CompareAndSwap(last, now) {
		return
	}

	if epoch, _, ok := c.search(psk, prologue, mine, wide); ok {
		c.OnClockSkew(epoch - mine)
	}
}

// epochTag is the MAC that binds a prologue to an hour and a context.
//
// The context goes in as its canonical string, so a prologue minted for node
// A does not authenticate on node B and a prologue minted under the old
// format version does not authenticate on a server that dropped it. Neither
// fact is on the wire: an observer sees eight bytes that look random, and a
// node that refuses refuses the way it refuses noise.
func epochTag(psk, random []byte, epoch int64, ctx Context) [sha256.Size]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(clockedMACLabel))
	mac.Write(random)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(epoch))
	mac.Write(buf[:])
	// Length-prefixed, so that a context cannot be split differently and
	// still produce the same MAC.
	label := ctx.String()
	binary.BigEndian.PutUint64(buf[:], uint64(len(label)))
	mac.Write(buf[:])
	mac.Write([]byte(label))
	var out [sha256.Size]byte
	mac.Sum(out[:0])
	return out
}

// clockedSecret is the prologue with the epoch appended, so that two
// connections sending the same prologue in different hours derive different
// keys - and so that a server which guessed the epoch wrong derives keys
// that do not match, rather than keys that happen to work.
func clockedSecret(prologue []byte, epoch int64) []byte {
	secret := make([]byte, SaltSize+8)
	copy(secret, prologue)
	binary.BigEndian.PutUint64(secret[SaltSize:], uint64(epoch))
	return secret
}
