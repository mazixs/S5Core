package userstore

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/identity"
	"github.com/mazixs/S5Core/internal/passwordhash"
)

const maxUsersFileSize = 10 << 20 // 10 MiB

// Store is a thread-safe in-memory user store backed by a JSON file.
// It supports periodic flushing of traffic counters and hot-reload.
type Store struct {
	mu    sync.RWMutex
	users map[string]*userEntry // keyed by username

	filePath  string
	logger    *slog.Logger
	stopFlush chan struct{}

	// verifier keeps Argon2id off the connection path: the KDF runs once per
	// password, not once per TCP connection. See verifier.go.
	verifier *verifierCache
	// kdf bounds how many Argon2id runs happen at once. See kdfgate.go.
	kdf *kdfGate
	// onVerify, when set, reports which path answered each password check.
	// It is the only way to tell from the outside whether the cache is doing
	// its job.
	onVerify func(path VerifyPath)
}

// userEntry holds a user account and an atomic traffic counter
// for lock-free increments on the hot path.
type userEntry struct {
	account      UserAccount
	trafficDelta atomic.Int64 // unflushed traffic delta since last save
}

// NewStore creates a new empty Store.
func NewStore(logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		users:    make(map[string]*userEntry),
		logger:   logger,
		verifier: newVerifierCache(),
		kdf:      newKDFGate(defaultKDFBudget),
	}
}

// SetKDFBudget sets how much memory concurrent password checks may use, in
// bytes. Zero restores the default; a negative budget removes the bound,
// which is for tests and for embedders that bound it themselves. It must be
// called before the store serves connections.
func (s *Store) SetKDFBudget(bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes == 0 {
		bytes = defaultKDFBudget
	}
	s.kdf = newKDFGate(bytes)
}

// readFileLimited reads a file with a size limit to prevent unbounded memory consumption.
func readFileLimited(path string, maxSize int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxSize {
		return nil, fmt.Errorf("file size %d exceeds limit %d", fi.Size(), maxSize)
	}
	return os.ReadFile(path)
}

// LoadFromFile reads and parses a users JSON file into the store.
// Existing users are replaced entirely. Traffic counters are reset.
func (s *Store) LoadFromFile(path string) error {
	data, err := readFileLimited(path, maxUsersFileSize)
	if err != nil {
		return fmt.Errorf("userstore: read file %s: %w", path, err)
	}

	var uf UsersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		return fmt.Errorf("userstore: parse JSON %s: %w", path, err)
	}

	if err := validateUsers(uf.Users); err != nil {
		return fmt.Errorf("userstore: validation: %w", err)
	}

	migrated, err := migrateAccounts(uf.Users)
	if err != nil {
		return err
	}
	respelled := standardiseHashes(uf.Users)

	users := make(map[string]*userEntry, len(uf.Users))
	for _, u := range uf.Users {
		users[u.Username] = &userEntry{account: u}
	}

	s.mu.Lock()
	s.users = users
	s.filePath = path
	s.mu.Unlock()
	s.verifier.retain(users)

	s.logger.Info("User store loaded", "path", path, "user_count", len(users))

	if len(migrated) > 0 {
		s.reportMigration(migrated, path)
	}
	if len(respelled) > 0 {
		s.reportHashMigration(respelled)
	}
	if len(migrated) > 0 || len(respelled) > 0 {
		// Written back so the keys survive a restart. A failure here is
		// logged rather than returned: the server runs fine with keys that
		// live only in memory, it just has to generate them again next time,
		// and refusing to start over a read-only account file would be a
		// worse outcome than that.
		if err := s.SaveToFile(path); err != nil {
			s.logger.Error("Could not write the migrated account file back",
				"path", path, "error", err)
		}
	}
	return nil
}

// Reload re-reads the JSON file, merging current traffic counters
// into the freshly loaded data so in-flight traffic is not lost.
func (s *Store) Reload(path string) error {
	data, err := readFileLimited(path, maxUsersFileSize)
	if err != nil {
		return fmt.Errorf("userstore: reload read %s: %w", path, err)
	}

	var uf UsersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		return fmt.Errorf("userstore: reload parse %s: %w", path, err)
	}

	if err := validateUsers(uf.Users); err != nil {
		return fmt.Errorf("userstore: reload validation: %w", err)
	}

	// A reload migrates in memory and does not write the file back. The
	// operator has just edited it; rewriting it underneath them, from a
	// signal handler, is not something a reload gets to do. The keys are
	// written on the next start, or by the next SaveToFile.
	migrated, err := migrateAccounts(uf.Users)
	if err != nil {
		return err
	}
	respelled := standardiseHashes(uf.Users)

	newUsers := make(map[string]*userEntry, len(uf.Users))

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range uf.Users {
		if oldEntry, ok := s.users[u.Username]; ok {
			// Preserve existing entry (keeps the same trafficDelta pointer
			// so in-flight TCP proxy goroutines continue counting correctly).
			oldEntry.account = u
			// Flush any unflushed delta into the base counter so the
			// new file state starts from an accurate baseline.
			oldEntry.account.TrafficUsedBytes += oldEntry.trafficDelta.Swap(0)
			newUsers[u.Username] = oldEntry
		} else {
			newUsers[u.Username] = &userEntry{account: u}
		}
	}

	s.users = newUsers
	s.filePath = path
	// Accounts that disappeared must not keep a cached verifier. Accounts
	// whose password changed need no handling here: their cache entry records
	// the hash it was verified against, and that hash no longer matches.
	s.verifier.retain(newUsers)
	s.logger.Info("User store reloaded", "path", path, "user_count", len(newUsers))
	if len(migrated) > 0 {
		s.reportMigration(migrated, path)
	}
	if len(respelled) > 0 {
		s.reportHashMigration(respelled)
	}
	return nil
}

// SaveToFile atomically writes the current state to a JSON file.
// Uses write-to-temp + rename for crash safety.
func (s *Store) SaveToFile(path string) error {
	s.mu.RLock()
	accounts := s.collectAccountsLocked()
	s.mu.RUnlock()
	return s.writeAccounts(path, accounts)
}

// writeAccounts performs the actual file write without holding the store lock.
func (s *Store) writeAccounts(path string, accounts []UserAccount) error {
	data, err := json.MarshalIndent(UsersFile{Users: accounts}, "", "  ")
	if err != nil {
		return fmt.Errorf("userstore: marshal: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".users-*.json.tmp")
	if err != nil {
		return fmt.Errorf("userstore: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("userstore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("userstore: close temp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("userstore: rename: %w", err)
	}

	return nil
}

// collectAccountsLocked returns a snapshot of all accounts with
// unflushed traffic deltas applied. Caller must hold at least s.mu.RLock().
func (s *Store) collectAccountsLocked() []UserAccount {
	accounts := make([]UserAccount, 0, len(s.users))
	for _, entry := range s.users {
		acc := entry.account
		acc.TrafficUsedBytes += entry.trafficDelta.Load()
		accounts = append(accounts, acc)
	}
	return accounts
}

// FlushTraffic applies all unflushed traffic deltas to the account
// structs and resets the atomic counters. Call under write lock or
// when no concurrent AddTraffic calls are expected.
func (s *Store) FlushTraffic() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.users {
		delta := entry.trafficDelta.Swap(0)
		entry.account.TrafficUsedBytes += delta
	}
}

// StartPeriodicFlush starts a background goroutine that periodically
// flushes traffic counters to the JSON file. Call Stop() to terminate.
// It is safe to call multiple times - if already running it is a no-op.
func (s *Store) StartPeriodicFlush(path string, interval time.Duration) {
	if path == "" {
		// A store with no file still counts traffic - the counters are what
		// quotas are checked against - it just has nowhere to write it. This
		// is the PROXY_USER deployment since plan task Ф6-3, and it is a
		// normal state, not a misconfiguration.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopFlush != nil {
		// already running
		return
	}
	// Канал захватывается в локальную переменную: StopPeriodicFlush обнуляет
	// поле под мьютексом, а горутина читает его без блокировки.
	stop := make(chan struct{})
	s.stopFlush = stop
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.FlushTraffic()
				if err := s.SaveToFile(path); err != nil {
					s.logger.Error("Failed to flush user traffic", "error", err)
				}
			case <-stop:
				return
			}
		}
	}()
	s.logger.Info("Periodic traffic flush started", "interval", interval, "path", path)
}

// StopPeriodicFlush stops the background flush goroutine and performs
// a final flush+save. It is safe to call multiple times.
func (s *Store) StopPeriodicFlush() {
	s.mu.Lock()
	if s.stopFlush != nil {
		select {
		case <-s.stopFlush:
			// already closed
		default:
			close(s.stopFlush)
		}
		s.stopFlush = nil
	}
	s.mu.Unlock()

	// Final flush
	s.FlushTraffic()
	s.mu.RLock()
	path := s.filePath
	s.mu.RUnlock()
	if path != "" {
		if err := s.SaveToFile(path); err != nil {
			s.logger.Error("Failed final traffic flush", "error", err)
		} else {
			s.logger.Info("Final traffic flush completed", "path", path)
		}
	}
}

// Lookup returns a copy of the user account if found.
func (s *Store) Lookup(username string) (UserAccount, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.users[username]
	if !ok {
		return UserAccount{}, false
	}
	acc := entry.account
	acc.TrafficUsedBytes += entry.trafficDelta.Load()
	return acc, true
}

// IsValid checks username/password and all business rules:
// enabled, TTL, traffic limit.
func (s *Store) IsValid(username, password string) bool {
	s.mu.RLock()
	entry, ok := s.users[username]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	acc := entry.account
	s.mu.RUnlock()

	// Every cheap reason to refuse is checked before the expensive one. An
	// account that is disabled, outside its validity window or out of quota
	// is refused whatever the password is, so running Argon2id first spent
	// 64 MiB and 110 ms to reach a conclusion already known - and spent it at
	// the request of whoever sent the connection, which is the whole of F06.
	//
	// This says nothing new to an attacker: the check already returned
	// immediately for a name that does not exist, so the timing has always
	// separated "no account" from "a live account". It now also separates
	// "a stopped account", which an operator can see in their own files and
	// an attacker cannot act on.
	if !acc.Enabled {
		return false
	}

	now := time.Now()
	if acc.IsExpired(now) || acc.IsNotYetActive(now) {
		return false
	}

	if acc.TrafficLimitBytes > 0 {
		s.mu.RLock()
		totalUsed := acc.TrafficUsedBytes + entry.trafficDelta.Load()
		s.mu.RUnlock()
		if totalUsed >= acc.TrafficLimitBytes {
			return false
		}
	}

	// Verify password: prefer Argon2id hash, fallback to plaintext.
	if acc.PasswordHash != "" {
		return s.verifyHashed(username, password, acc.PasswordHash)
	}
	if acc.Password != "" {
		return subtle.ConstantTimeCompare([]byte(acc.Password), []byte(password)) == 1
	}
	return false
}

// SessionStatus is what an account may still do right now. The relay turns
// it into a state of the session's account region, and the two non-allowed
// values are kept apart because they mean different things to an operator and
// resolve to different terminal states (plan task Ф6-1): a spent quota is a
// paid account that ran out this month, an expired one is an account that is
// gone.
type SessionStatus uint8

const (
	// SessionAllowed: enabled, inside its validity window and inside its
	// quota. Also the answer for an account nobody meters.
	SessionAllowed SessionStatus = iota
	// SessionQuotaExceeded: the traffic limit is spent.
	SessionQuotaExceeded
	// SessionExpired: disabled, outside its validity window, or removed or
	// renamed while the session was running.
	SessionExpired
)

// SessionStatus reports whether a user may keep transferring data right now:
// enabled, inside its validity window and inside its traffic quota, counting
// the bytes that have not been flushed to disk yet.
//
// The quota used to be read once, at authentication. A session that started
// with one byte of quota left ran until the client closed it, so an account
// could be hours and gigabytes past its limit while the file said it was
// stopped. The relay calls this on the boundary it already stops at - every
// 64 KiB - so the check costs one map read per 64 KiB, not one per packet.
func (s *Store) SessionStatus(username string) SessionStatus {
	s.mu.RLock()
	entry, ok := s.users[username]
	s.mu.RUnlock()
	if !ok {
		// An account removed or renamed mid-session is no longer valid under
		// its old name.
		return SessionExpired
	}

	s.mu.RLock()
	acc := entry.account
	s.mu.RUnlock()

	if !acc.Enabled {
		return SessionExpired
	}
	now := time.Now()
	if acc.IsExpired(now) || acc.IsNotYetActive(now) {
		return SessionExpired
	}
	if acc.TrafficLimitBytes > 0 && acc.TrafficUsedBytes+entry.trafficDelta.Load() >= acc.TrafficLimitBytes {
		return SessionQuotaExceeded
	}
	return SessionAllowed
}

// SessionAllowed reports whether a user may keep transferring. It is the
// boolean view of SessionStatus, kept for callers that do not care why.
func (s *Store) SessionAllowed(username string) bool {
	return s.SessionStatus(username) == SessionAllowed
}

// SetVerifyObserver installs a callback reporting which path answered each
// password check. Nil disables reporting. It must be set before the store
// starts serving connections.
func (s *Store) SetVerifyObserver(f func(path VerifyPath)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onVerify = f
}

// verifyHashed checks a password against an Argon2id hash, answering from the
// verifier cache when it can. The KDF runs on the first successful login for a
// given password and after that only when the stored hash changes or the entry
// expires - see verifier.go for why that is safe.
func (s *Store) verifyHashed(username, password, hash string) bool {
	s.mu.RLock()
	observe := s.onVerify
	s.mu.RUnlock()

	s.mu.RLock()
	gate := s.kdf
	s.mu.RUnlock()

	// The gate refusing is not an answer about this password, and saying so
	// takes a flag rather than a wider signature: slow runs in this
	// goroutine, so there is nothing to race with.
	refused := false
	ok, path := s.verifier.verify(username, password, hash, time.Now(), func() bool {
		verified, ran := gate.run(func() bool {
			got, err := passwordhash.Verify(password, hash)
			if err != nil {
				s.logger.Warn("Password hash could not be verified", "error", err)
				return false
			}
			return got
		})
		if !ran {
			refused = true
		}
		return verified
	})
	if refused {
		path = VerifyPathOverloaded
	}
	if observe != nil {
		observe(path)
	}
	return ok
}

// MigratePassword hashes a plaintext password using Argon2id and persists the
// change to disk. It is a no-op if the user already has a PasswordHash.
//
// The hashing happens with the lock released, because it costs 110 ms and
// every other connection would queue behind it. That makes this two separate
// visits to the store with a long gap in between, and what the store holds
// can change during the gap - SIGHUP re-reads the file from a signal handler.
// commitMigratedHash is where the second visit decides whether the hash it
// carries is still about the account in front of it.
func (s *Store) MigratePassword(username, password string) {
	s.mu.Lock()
	entry, ok := s.users[username]
	if !ok {
		s.mu.Unlock()
		return
	}
	if entry.account.PasswordHash != "" || entry.account.Password == "" {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	hash, err := passwordhash.Hash(password)
	if err != nil {
		s.logger.Error("Failed to hash password during migration", "user", username, "error", err)
		return
	}

	path, stored := s.commitMigratedHash(username, password, hash, entry)
	if !stored {
		// Dropped, not failed: the account this hash was made for is not the
		// account that is there now, and the plaintext login that started the
		// migration has already been answered. The next login migrates again,
		// from whatever the file says by then.
		s.logger.Info("Password migration dropped: the account changed while it was being hashed",
			"user", username)
		return
	}

	if path != "" {
		if err := s.SaveToFile(path); err != nil {
			s.logger.Error("Failed to save users file after password migration", "error", err)
		} else {
			s.logger.Info("Password migrated to Argon2id", "user", username)
		}
	}
}

// commitMigratedHash stores a hash Argon2id has just produced, provided the
// account it was produced for is still the one under that name, and returns
// the file to save and whether anything was stored.
//
// Every refusal here is a way the old code lost or undid an operator's edit
// (review finding R05). It wrote through a *UserAccount taken before the KDF
// ran, and Reload keeps the same *userEntry so that in-flight traffic keeps
// counting - so the write landed, silently, on whatever the reload had put
// there. An account whose password the operator had just changed got the hash
// of the old one; an account the reload had removed got a write nobody would
// ever read, and the file was then saved from a state Reload had deliberately
// not touched.
func (s *Store) commitMigratedHash(username, password, hash string, migrating *userEntry) (path string, stored bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, found := s.users[username]
	switch {
	case !found:
		// Removed or renamed while the KDF ran.
		return "", false
	case current != migrating:
		// The name is the same; the account behind it is not.
		return "", false
	case current.account.PasswordHash != "":
		// Something else gave this account a hash in the meantime. Ours is
		// for a password that is no longer the one on file.
		return "", false
	case subtle.ConstantTimeCompare([]byte(current.account.Password), []byte(password)) != 1:
		// The plaintext changed. Writing this hash would undo the change.
		return "", false
	}

	current.account.PasswordHash = hash
	current.account.Password = "" // clear plaintext
	return s.filePath, true
}

// AddTraffic atomically increments the traffic counter for a user.
// This is designed for the hot path and uses lock-free atomics.
func (s *Store) AddTraffic(username string, bytes int64) {
	s.mu.RLock()
	entry, ok := s.users[username]
	s.mu.RUnlock()

	if ok {
		entry.trafficDelta.Add(bytes)
	}
}

// TrafficCounterFor returns a raw *atomic.Int64 pointer for the given user.
// This allows lock-free traffic counting on the TCP hot path by resolving
// the pointer once at connection setup. Returns nil if user not found.
func (s *Store) TrafficCounterFor(username string) *atomic.Int64 {
	s.mu.RLock()
	entry, ok := s.users[username]
	s.mu.RUnlock()

	if !ok {
		return nil
	}
	return &entry.trafficDelta
}

// AddUser creates a new user with an Argon2id-hashed password and a tunnel
// key of its own.
//
// The key is not optional here. An account read from a file gets one
// (migrateAccounts), so an account created through this call that did not
// would be a second kind of account: invisible to the member directory,
// unable to raise a tunnel under OBFS_REQUIRE_MEMBER_KEY, and - worse -
// sharing the anonymous account's session secret without it. Two ways of
// creating an account that differ in what the tunnel can do with it is the
// split plan task Ф6-3 removed, and this is the last place it survived.
func (s *Store) AddUser(username, password string) error {
	hash, err := passwordhash.Hash(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	key := make([]byte, TunnelKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate a tunnel key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user %q already exists", username)
	}

	s.users[username] = &userEntry{
		account: UserAccount{
			ID:           username,
			Username:     username,
			PasswordHash: hash,
			TunnelKey:    base64.StdEncoding.EncodeToString(key),
			Enabled:      true,
		},
	}
	return nil
}

// SetRole changes what an account may do beyond passing traffic. It does not
// touch the password, the key or the quota: a role is orthogonal to all three
// (plan task Ф6-3).
func (s *Store) SetRole(username string, role identity.Role) error {
	if _, err := identity.ParseRole(string(role)); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}
	entry.account.Role = string(role)
	return nil
}

// RemoveUser deletes a user from the store.
func (s *Store) RemoveUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; !exists {
		return fmt.Errorf("user %q not found", username)
	}
	delete(s.users, username)
	s.verifier.forget(username)
	return nil
}

// UserCount returns the number of loaded users.
func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// validateUsers checks for duplicate usernames and IDs.
func validateUsers(users []UserAccount) error {
	seenUsers := make(map[string]struct{}, len(users))
	seenIDs := make(map[string]struct{}, len(users))

	for i, u := range users {
		if u.Username == "" {
			return fmt.Errorf("user at index %d has empty username", i)
		}
		if u.ID == "" {
			return fmt.Errorf("user %q has empty id", u.Username)
		}
		if _, dup := seenUsers[u.Username]; dup {
			return fmt.Errorf("duplicate username: %q", u.Username)
		}
		seenUsers[u.Username] = struct{}{}
		if _, dup := seenIDs[u.ID]; dup {
			return fmt.Errorf("duplicate id: %q", u.ID)
		}
		seenIDs[u.ID] = struct{}{}
		if _, err := identity.ParseRole(u.Role); err != nil {
			return fmt.Errorf("user %q: %w", u.Username, err)
		}
		// A hash is checked when the file is read, not when someone logs in.
		// Argon2id answers a malformed one with a panic rather than an error
		// (audit finding F15), so a hash nobody can check is a hash that must
		// not be in the store: the operator hears about it at the start or at
		// the reload that introduced it, while they are still looking at the
		// file.
		if u.PasswordHash != "" {
			if err := passwordhash.Validate(u.PasswordHash); err != nil {
				return fmt.Errorf("user %q: password hash: %w", u.Username, err)
			}
		}
	}
	return nil
}

// TunnelMember is one account as the obfuscation layer authenticates it: a
// name and a key, with nothing about passwords or quotas in it.
type TunnelMember struct {
	Username string
	Key      []byte
}

// TunnelMembers returns the accounts that carry a tunnel key and are
// currently allowed to connect. Accounts without a key are absent: they are
// not members, and they authenticate over the shared account as before.
//
// Expiry and quotas are checked here as well as at session time, so that a
// closed account stops being resolvable at the next reload rather than
// merely being refused later - the point of the key is that the refusal
// should not need a SOCKS5 handshake to happen.
func (s *Store) TunnelMembers() []TunnelMember {
	s.mu.RLock()
	accounts := make([]UserAccount, 0, len(s.users))
	deltas := make([]int64, 0, len(s.users))
	for _, entry := range s.users {
		accounts = append(accounts, entry.account)
		deltas = append(deltas, entry.trafficDelta.Load())
	}
	s.mu.RUnlock()

	now := time.Now()
	members := make([]TunnelMember, 0, len(accounts))
	for i, acc := range accounts {
		if acc.TunnelKey == "" || !acc.Enabled {
			continue
		}
		if acc.IsExpired(now) || acc.IsNotYetActive(now) {
			continue
		}
		if acc.TrafficLimitBytes > 0 && acc.TrafficUsedBytes+deltas[i] >= acc.TrafficLimitBytes {
			continue
		}
		key, err := DecodeTunnelKey(acc.TunnelKey)
		if err != nil {
			// Reported once per reload rather than per connection: a
			// malformed key is an operator's typo, and the account simply
			// is not a member until it is fixed.
			s.logger.Error("User has an unusable tunnel key", "username", acc.Username, "error", err)
			continue
		}
		members = append(members, TunnelMember{Username: acc.Username, Key: key})
	}
	return members
}

// TunnelKeySize is how long a decoded tunnel key must be.
const TunnelKeySize = 32

// DecodeTunnelKey turns the stored form of a tunnel key into bytes.
func DecodeTunnelKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("tunnel key is not valid base64: %w", err)
	}
	if len(key) != TunnelKeySize {
		return nil, fmt.Errorf("tunnel key is %d bytes, need %d", len(key), TunnelKeySize)
	}
	return key, nil
}
