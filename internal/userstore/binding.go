package userstore

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/identity"
)

var entrySerial atomic.Uint64

func newUserEntry(account UserAccount) *userEntry {
	return &userEntry{account: account, token: strconv.FormatUint(entrySerial.Add(1), 16)}
}

// Binding pins an account incarnation, not the current owner of its name.
// Reload preserves it for the same ID. Removal, replacement or renaming
// revokes it, including removal followed by recreation with the same ID.
type Binding struct {
	store *Store
	entry *userEntry
	name  string
}

// Bind resolves a name once. Its status, identity and traffic counter all
// refer to the same entry even when Reload later reuses the name.
func (s *Store) Bind(username string) *Binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bindLocked(username, s.users[username])
}

func (s *Store) bindLocked(name string, entry *userEntry) *Binding {
	if entry == nil {
		return nil
	}
	return &Binding{store: s, entry: entry, name: name}
}

// BindMember resolves the server-local member reference captured by the
// roster. A stale directory must not authenticate a replacement by name.
// The reference is local metadata; no identity bytes on the wire change.
func (s *Store) BindMember(reference string) *Binding {
	token, name, ok := strings.Cut(reference, ":")
	if !ok {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.users[name]
	if entry == nil || entry.token != token {
		return nil
	}
	return s.bindLocked(name, entry)
}

func (b *Binding) Name() string { return b.name }

// Counter never redirects old traffic to a replacement's quota.
func (b *Binding) Counter() *atomic.Int64 { return &b.entry.trafficDelta }

func (b *Binding) Status() SessionStatus {
	b.store.mu.RLock()
	defer b.store.mu.RUnlock()
	if b.store.users[b.name] != b.entry {
		return SessionExpired
	}
	return entryStatus(b.entry, time.Now())
}

// Identity returns current permissions only while this incarnation is
// still present under its original name. Dates and keys are owned copies.
func (b *Binding) Identity() (identity.Identity, bool) {
	b.store.mu.RLock()
	defer b.store.mu.RUnlock()
	if b.store.users[b.name] != b.entry {
		return identity.Identity{}, false
	}
	acc := b.entry.account.clone()
	acc.TrafficUsedBytes += b.entry.trafficDelta.Load()
	var key []byte
	if acc.TunnelKey != "" {
		var err error
		key, err = DecodeTunnelKey(acc.TunnelKey)
		if err != nil {
			return identity.Identity{}, false
		}
	}
	return acc.Identity(key), true
}

// The caller holds Store.mu, so policy and counter belong to one snapshot.
func entryStatus(entry *userEntry, now time.Time) SessionStatus {
	acc := &entry.account
	if !acc.Enabled || acc.IsExpired(now) || acc.IsNotYetActive(now) {
		return SessionExpired
	}
	if acc.TrafficLimitBytes > 0 && acc.TrafficUsedBytes+entry.trafficDelta.Load() >= acc.TrafficLimitBytes {
		return SessionQuotaExceeded
	}
	return SessionAllowed
}
