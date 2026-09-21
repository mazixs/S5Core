package userstore

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/mazixs/S5Core/internal/identity"
	"github.com/mazixs/S5Core/internal/passwordhash"
)

// Plan task Ф6-3: an account file written before tunnel keys existed is
// migrated when it is read, not by hand.
//
// Every account without a key is given one - 32 random bytes, not derived
// from the password and never derivable from it - and the file is written
// back, so the keys survive a restart and the operator has them where the
// accounts already are. Nothing about the account's behaviour changes: until
// the operator hands a key to a client, that client keeps authenticating with
// its password over the shared account, exactly as before.
//
// The key does not go to the log. A log line is the wrong place for a secret:
// logs are shipped, rotated and read by people who are not the account's
// owner, and a key in one is a key that leaked. The warning says which
// accounts were given keys and where to read them.

// migrateAccounts fills in what a pre-Ф6-3 file does not have. It returns the
// names of the accounts it changed, in file order.
func migrateAccounts(users []UserAccount) ([]string, error) {
	var changed []string
	for i := range users {
		u := &users[i]
		if u.TunnelKey != "" {
			continue
		}
		key := make([]byte, TunnelKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("userstore: generate a tunnel key for %q: %w", u.Username, err)
		}
		u.TunnelKey = base64.StdEncoding.EncodeToString(key)
		changed = append(changed, u.Username)
	}
	return changed, nil
}

// standardiseHashes brings password hashes written by an earlier build up to
// the PHC standard alphabet (audit finding P3-1). It returns the names of the
// accounts it changed, in file order.
//
// This needs no password and changes no password: the salt and the hash are
// the same bytes in either alphabet, only spelled differently, so the accounts
// keep working and their hashes become readable by other Argon2id
// implementations. A hash this package cannot parse is left alone - refusing
// to load an account file over a spelling would be the wrong trade, and
// verification reports the real problem when someone logs in.
func standardiseHashes(users []UserAccount) []string {
	var changed []string
	for i := range users {
		u := &users[i]
		if u.PasswordHash == "" {
			continue
		}
		if std, ok := passwordhash.Standardise(u.PasswordHash); ok {
			u.PasswordHash = std
			changed = append(changed, u.Username)
		}
	}
	return changed
}

// reportHashMigration says which accounts had their hash respelled. The hash
// itself does not go to the log for the same reason a tunnel key does not.
func (s *Store) reportHashMigration(changed []string) {
	s.logger.Info("Password hashes rewritten in the standard PHC alphabet",
		"accounts", changed,
		"count", len(changed),
		"note", "same passwords, same hashes - only the base64 spelling changed (audit P3-1)",
	)
}

// reportMigration tells the operator which accounts were given a key and
// where to read it. path may be empty, in which case the keys live only in
// memory and the warning says so.
func (s *Store) reportMigration(changed []string, path string) {
	where := path
	if where == "" {
		where = "memory only - this store has no file"
	}
	s.logger.Warn("Accounts were given a tunnel key",
		"accounts", changed,
		"count", len(changed),
		"read_keys_from", where,
		"note", "hand each key to its client as OBFS_MEMBER_KEY; the key is not logged",
	)
}

// Identity returns the account as the tunnel knows it, with its key decoded.
// ok is false when there is no such account.
func (s *Store) Identity(username string) (identity.Identity, bool) {
	acc, ok := s.Lookup(username)
	if !ok {
		return identity.Identity{}, false
	}
	var key []byte
	if acc.TunnelKey != "" {
		// A malformed key is already reported once per reload by
		// TunnelMembers; here it simply means the account has none.
		key, _ = DecodeTunnelKey(acc.TunnelKey)
	}
	return acc.Identity(key), true
}

// Role is the role of an account, and RoleUser for one that does not exist -
// the least privileged answer, so that a missing account can never be a way
// to gain a permission.
func (s *Store) Role(username string) identity.Role {
	id, ok := s.Identity(username)
	if !ok {
		return identity.RoleUser
	}
	return id.Role
}

// Identities returns every account as an identity, for a control panel that
// lists them. Keys are included because the panel is what hands them out;
// password hashes are not, because nothing outside verification needs them.
func (s *Store) Identities() []identity.Identity {
	s.mu.RLock()
	accounts := make([]UserAccount, 0, len(s.users))
	deltas := make([]int64, 0, len(s.users))
	for _, entry := range s.users {
		accounts = append(accounts, entry.account)
		deltas = append(deltas, entry.trafficDelta.Load())
	}
	s.mu.RUnlock()

	out := make([]identity.Identity, 0, len(accounts))
	for i, acc := range accounts {
		var key []byte
		if acc.TunnelKey != "" {
			key, _ = DecodeTunnelKey(acc.TunnelKey)
		}
		id := acc.Identity(key)
		// The counter on the hot path has not been flushed to the account
		// yet, so a panel reading this would otherwise show a quota as less
		// spent than it is.
		id.Policy.TrafficUsedBytes += deltas[i]
		out = append(out, id)
	}
	return out
}
