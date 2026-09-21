package userstore

import (
	"time"

	"github.com/mazixs/S5Core/internal/identity"
)

// UserAccount represents a single proxy user with authentication,
// validity period, and traffic accounting.
type UserAccount struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`      // Deprecated: use PasswordHash
	PasswordHash string `json:"password_hash,omitempty"` // Argon2id PHC hash
	// TunnelKey is this account's own 32-byte key, base64 (standard
	// encoding). It is what identifies the user to the obfuscation layer,
	// before SOCKS5 and before any password (plan task Ф5-5): the client
	// stamps a tag of it into the prologue and the server resolves it in
	// constant time. Generate one with `openssl rand -base64 32`.
	//
	// It is not derived from the password and must not be: a password is
	// something a person remembers, and this is the key the tunnel trusts.
	// An account without one still works - it authenticates with a password
	// over the shared account, the way every account did before.
	TunnelKey string `json:"tunnel_key,omitempty"`
	// Role is what this account may do beyond passing traffic: user,
	// operator or admin (plan task Ф6-3). Empty means user, which is what
	// every account written before roles existed is.
	//
	// It has nothing to do with the tunnel: a role is checked by the control
	// panel and the SDK, never on the connection path.
	Role              string     `json:"role,omitempty"`
	Comment           string     `json:"comment,omitempty"`
	ValidFrom         *time.Time `json:"valid_from,omitempty"`
	ValidUntil        *time.Time `json:"valid_until,omitempty"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes,omitempty"`
	TrafficUsedBytes  int64      `json:"traffic_used_bytes,omitempty"`
	Enabled           bool       `json:"enabled"`
}

// UsersFile is the root structure of the users JSON file.
type UsersFile struct {
	Users []UserAccount `json:"users"`
}

// IsExpired checks if the account has passed its validity period.
func (u *UserAccount) IsExpired(now time.Time) bool {
	if u.ValidUntil != nil && now.After(*u.ValidUntil) {
		return true
	}
	return false
}

// IsNotYetActive checks if the account is not yet within its validity period.
func (u *UserAccount) IsNotYetActive(now time.Time) bool {
	if u.ValidFrom != nil && now.Before(*u.ValidFrom) {
		return true
	}
	return false
}

// IsTrafficExceeded checks if the user has exceeded their traffic limit.
func (u *UserAccount) IsTrafficExceeded() bool {
	if u.TrafficLimitBytes > 0 && u.TrafficUsedBytes >= u.TrafficLimitBytes {
		return true
	}
	return false
}

// Identity is this account as the tunnel knows it: name, key, role and
// policy, with nothing about passwords in it. key is the decoded tunnel key,
// which the caller has already validated; an account without one gets an
// identity without one.
func (u *UserAccount) Identity(key []byte) identity.Identity {
	role, err := identity.ParseRole(u.Role)
	if err != nil {
		// An unparsable role is refused at load time, so reaching this means
		// the account was built in memory with a typo. The safe reading of an
		// unknown role is the least privileged one.
		role = identity.RoleUser
	}
	return identity.Identity{
		ID:     u.ID,
		Name:   u.Username,
		Key:    key,
		Role:   role,
		Policy: u.Policy(),
	}
}

// Policy is what this account may spend.
func (u *UserAccount) Policy() identity.Policy {
	return identity.Policy{
		Enabled:           u.Enabled,
		ValidFrom:         u.ValidFrom,
		ValidUntil:        u.ValidUntil,
		TrafficLimitBytes: u.TrafficLimitBytes,
		TrafficUsedBytes:  u.TrafficUsedBytes,
	}
}

// Credential is the password half: the Argon2id hash and nothing else. A
// legacy plaintext password is not a credential - it is a thing waiting to be
// migrated into one on its first successful use.
func (u *UserAccount) Credential() identity.Credential {
	return identity.Credential{Hash: u.PasswordHash}
}
