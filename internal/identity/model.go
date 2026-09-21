package identity

import (
	"fmt"
	"time"
)

// The two things an account is were one thing until plan task Ф6-3.
//
// An Identity is who the tunnel lets in: a name, a key, a role and a policy.
// It is resolved before SOCKS5 is spoken, in constant time, from a tag in the
// prologue - no password is involved and none can be.
//
// A Credential is a password, and it exists for the control panel and the
// API. It is checked by Argon2id, which costs 64 MiB and about a tenth of a
// second, and that is affordable exactly because it is not on the connection
// path.
//
// Keeping them apart is what makes both statements true at once: the tunnel
// cannot be brute-forced because it does not take passwords, and the panel
// can take passwords because it is not the tunnel.

// Role is what an identity is allowed to do beyond passing traffic.
type Role string

const (
	// RoleUser passes traffic and nothing else. It is the default, and the
	// role every account loaded from a file without one gets.
	RoleUser Role = "user"
	// RoleOperator may look at the accounts and change the server's runtime
	// settings, but may not create or delete accounts.
	RoleOperator Role = "operator"
	// RoleAdmin may do everything, including handing out roles.
	RoleAdmin Role = "admin"
)

// Action is one thing that can be asked of the server.
type Action uint8

const (
	// ConnectAction is using the proxy. Every known role has it: a role is
	// about management, not about whether traffic flows.
	ConnectAction Action = iota
	// ViewAccountsAction is reading the account list - names, roles, quotas
	// and how much of them is spent. Never keys or hashes.
	ViewAccountsAction
	// ManageAccountsAction is creating, removing and changing accounts.
	ManageAccountsAction
	// ManageServerAction is changing the running server: the client
	// whitelist, the timeouts, the transport advice.
	ManageServerAction
)

func (a Action) String() string {
	switch a {
	case ConnectAction:
		return "connect"
	case ViewAccountsAction:
		return "view accounts"
	case ManageAccountsAction:
		return "manage accounts"
	case ManageServerAction:
		return "manage the server"
	}
	return "unknown"
}

// Can reports whether this role may perform the action. The table is small
// and closed on purpose: a permission system that needs a parser is a
// permission system nobody can audit.
func (r Role) Can(a Action) bool {
	switch r {
	case RoleUser, RoleOperator, RoleAdmin:
	default:
		// A role that is not one of the three is not a role. It cannot
		// arrive from a file - ParseRole refuses it at load time - so
		// reaching here means something built one in memory, and the safe
		// reading of a value nobody defined is that it grants nothing.
		return false
	}
	switch a {
	case ConnectAction:
		// Every role passes traffic: a role says what may be managed, not
		// whether bytes flow. That is the policy's job.
		return true
	case ViewAccountsAction, ManageServerAction:
		return r == RoleOperator || r == RoleAdmin
	case ManageAccountsAction:
		return r == RoleAdmin
	}
	return false
}

// ParseRole turns the stored form of a role into a Role. An empty string is
// RoleUser rather than an error: every account written before plan task Ф6-3
// has no role field, and those accounts are users.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case "":
		return RoleUser, nil
	case RoleUser:
		return RoleUser, nil
	case RoleOperator:
		return RoleOperator, nil
	case RoleAdmin:
		return RoleAdmin, nil
	}
	return "", fmt.Errorf("identity: unknown role %q, want one of user, operator, admin", s)
}

// ErrNotAllowed is returned when a role may not do what was asked of it.
type ErrNotAllowed struct {
	Role   Role
	Action Action
}

func (e *ErrNotAllowed) Error() string {
	return fmt.Sprintf("identity: role %q may not %s", e.Role, e.Action)
}

// Authorize returns nil when the role may perform the action, and an
// *ErrNotAllowed when it may not.
func Authorize(r Role, a Action) error {
	if r.Can(a) {
		return nil
	}
	return &ErrNotAllowed{Role: r, Action: a}
}

// Policy is what an identity is allowed to spend. It is deliberately not part
// of the Role: a role says what someone may do, a policy says how much.
type Policy struct {
	// Enabled false is an account that exists and may not connect.
	Enabled bool
	// ValidFrom and ValidUntil bound the account in time. Nil is unbounded.
	ValidFrom  *time.Time
	ValidUntil *time.Time
	// TrafficLimitBytes is the quota; 0 is unlimited.
	TrafficLimitBytes int64
	// TrafficUsedBytes is how much of it has been spent, as of the last
	// flush.
	TrafficUsedBytes int64
}

// Allows reports whether the policy lets a session run at time now.
func (p Policy) Allows(now time.Time) bool {
	if !p.Enabled {
		return false
	}
	if p.ValidUntil != nil && now.After(*p.ValidUntil) {
		return false
	}
	if p.ValidFrom != nil && now.Before(*p.ValidFrom) {
		return false
	}
	if p.TrafficLimitBytes > 0 && p.TrafficUsedBytes >= p.TrafficLimitBytes {
		return false
	}
	return true
}

// Identity is an account as the tunnel knows it. There is no password here
// and there must not be one: this is resolved from the prologue before any
// SOCKS5 byte is read.
type Identity struct {
	ID   string
	Name string
	// Key is the 32-byte tunnel key, decoded. Empty means the account has no
	// key and authenticates the old way, over the shared account.
	Key    []byte
	Role   Role
	Policy Policy
}

// HasKey reports whether this identity is resolvable by the tunnel on its own.
func (i Identity) HasKey() bool { return len(i.Key) > 0 }

// Credential is a password as the control panel knows it: an Argon2id PHC
// string and nothing else. It never reaches the connection path.
type Credential struct {
	// Hash is the PHC-encoded Argon2id hash, empty when the account has no
	// password at all - which is a normal state for a key-only account.
	Hash string
}

// HasPassword reports whether there is anything to check.
func (c Credential) HasPassword() bool { return c.Hash != "" }
