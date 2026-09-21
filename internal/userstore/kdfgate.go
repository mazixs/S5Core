package userstore

import (
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// Argon2id is expensive on purpose, and the expense is memory: one standard
// run of this project's parameters asks for 64 MiB. The verifier cache
// (verifier.go) takes the KDF off the steady-state path and collapses
// simultaneous checks of the same credentials into one run, but neither helps
// with the case that hurts - many *different* wrong passwords against a cold
// account. Each is a different flight, so each runs its own KDF, and 32 of
// them at once ask the machine for 2 GiB it does not have. The connection
// limit does not bound this: one connection is one KDF, and the bound that
// matters is memory, not sockets. The lockout in internal/identity is
// recorded after the check, so it does not stop a batch already in flight
// (F06 in docs/reports/code-quality-audit-2026-09-20.md).
//
// kdfGate is the missing bound. It is a memory budget expressed as a count of
// concurrent runs, plus a queue for the rest, because the alternative to
// waiting is either running out of memory or refusing a correct password the
// moment two people log in at once.
const (
	// defaultKDFBudget is how much memory password checking may use at once.
	// At this project's parameters that is four concurrent runs. It is a
	// budget rather than a count so that changing the KDF parameters moves
	// the limit with them instead of silently multiplying it.
	defaultKDFBudget int64 = 256 << 20

	// kdfQueuePerPermit is how many checks may wait per running one. Four
	// deep at ~110 ms a run is under half a second of waiting at the back of
	// a full queue - long enough to absorb the burst a browser makes of one
	// page, short enough that the queue is not itself the memory leak.
	kdfQueuePerPermit = 4

	// defaultKDFWait bounds a wait that the queue depth should already have
	// bounded. It is the backstop for a machine slower than the estimate
	// above, not the normal limit.
	defaultKDFWait = 2 * time.Second
)

// kdfGate admits a bounded number of concurrent KDF runs and a bounded number
// of waiters. Past both, a check is refused without running: the caller sees
// a failed password check, which is what an overloaded server has to say
// anyway, and the memory is never allocated.
type kdfGate struct {
	// admitted holds one token per check inside the gate, running or
	// waiting. Its capacity is the queue bound.
	admitted chan struct{}
	// running holds one token per check actually running. Its capacity is
	// the memory bound.
	running chan struct{}
	wait    time.Duration
}

// newKDFGate builds a gate for the given memory budget. A budget at or below
// zero means no gate at all, which only a caller that has its own bound
// should ask for.
func newKDFGate(budget int64) *kdfGate {
	if budget <= 0 {
		return nil
	}
	permits := int(budget / passwordhash.MemoryBytes)
	if permits < 1 {
		// A budget smaller than one run still has to allow one, or no
		// password is ever checked. The operator asked for less memory than
		// the KDF needs; serialising is the closest answer to that.
		permits = 1
	}
	return &kdfGate{
		admitted: make(chan struct{}, permits*(1+kdfQueuePerPermit)),
		running:  make(chan struct{}, permits),
		wait:     defaultKDFWait,
	}
}

// run calls f under the gate. ran is false when the gate refused, in which
// case f was not called and ok is false: a refusal is not an answer about the
// password, and the caller reports it as its own path so that an overloaded
// server is visible in metrics rather than looking like a wave of wrong
// passwords.
func (g *kdfGate) run(f func() bool) (ok, ran bool) {
	if g == nil {
		return f(), true
	}

	select {
	case g.admitted <- struct{}{}:
	default:
		// The queue is full. Waiting for a place in the queue would make the
		// queue unbounded again.
		return false, false
	}
	defer func() { <-g.admitted }()

	select {
	case g.running <- struct{}{}:
	default:
		timer := time.NewTimer(g.wait)
		defer timer.Stop()
		select {
		case g.running <- struct{}{}:
		case <-timer.C:
			return false, false
		}
	}
	defer func() { <-g.running }()

	return f(), true
}
