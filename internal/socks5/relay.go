package socks5

import (
	"github.com/mazixs/S5Core/internal/relay"
)

// The relay itself moved to internal/relay in plan task Ф6-2: copying and
// metering bytes is not part of speaking SOCKS5. What stays here are the
// names this package's API exposes, kept as aliases so that an embedder of
// the SDK - which configures SessionStatus and reads ErrSessionNotAllowed -
// is not made to import a second package for two identifiers.

// SessionStatus is what the account behind a session may still do. It is
// asked of Config.SessionStatus on the relay's flush boundary.
type SessionStatus = relay.Status

const (
	// SessionAllowed: the account may keep transferring.
	SessionAllowed = relay.Allowed
	// SessionQuotaExceeded: the traffic limit is spent.
	SessionQuotaExceeded = relay.QuotaExceeded
	// SessionExpired: the account's validity ended - by date, by being
	// disabled, or by being removed while the session ran.
	SessionExpired = relay.Expired
)

// ErrSessionNotAllowed ends a relay whose account may no longer transfer:
// out of quota, expired or disabled while the session was running.
var ErrSessionNotAllowed = relay.ErrNotAllowed

// HalfCloseObserver receives the result of a half-close attempt: nil when the
// write side was shut down, an error when it could not be.
type HalfCloseObserver = relay.HalfCloseObserver
