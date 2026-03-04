package userstore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Store is a thread-safe in-memory user store backed by a JSON file.
// It supports periodic flushing of traffic counters and hot-reload.
type Store struct {
	mu    sync.RWMutex
	users map[string]*userEntry // keyed by username

	filePath  string
	logger    *slog.Logger
	stopFlush chan struct{}
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
		users:  make(map[string]*userEntry),
		logger: logger,
	}
}

// LoadFromFile reads and parses a users JSON file into the store.
// Existing users are replaced entirely. Traffic counters are reset.
func (s *Store) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
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

	users := make(map[string]*userEntry, len(uf.Users))
	for _, u := range uf.Users {
		users[u.Username] = &userEntry{account: u}
	}

	s.mu.Lock()
	s.users = users
	s.filePath = path
	s.mu.Unlock()

	s.logger.Info("User store loaded", "path", path, "user_count", len(users))
	return nil
}

// Reload re-reads the JSON file, merging current traffic counters
// into the freshly loaded data so in-flight traffic is not lost.
func (s *Store) Reload(path string) error {
	data, err := os.ReadFile(path)
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

	newUsers := make(map[string]*userEntry, len(uf.Users))
	for _, u := range uf.Users {
		newUsers[u.Username] = &userEntry{account: u}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Merge traffic: preserve current runtime traffic into new entries.
	for username, oldEntry := range s.users {
		if newEntry, ok := newUsers[username]; ok {
			// Add unflushed delta from runtime to the file's traffic_used_bytes
			delta := oldEntry.trafficDelta.Load()
			newEntry.account.TrafficUsedBytes = oldEntry.account.TrafficUsedBytes + delta
			// Reset the delta since we incorporated it
		}
	}

	s.users = newUsers
	s.filePath = path
	s.logger.Info("User store reloaded", "path", path, "user_count", len(newUsers))
	return nil
}

// SaveToFile atomically writes the current state to a JSON file.
// Uses write-to-temp + rename for crash safety.
func (s *Store) SaveToFile(path string) error {
	s.mu.RLock()
	accounts := s.collectAccountsLocked()
	s.mu.RUnlock()

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
func (s *Store) StartPeriodicFlush(path string, interval time.Duration) {
	s.stopFlush = make(chan struct{})
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
			case <-s.stopFlush:
				return
			}
		}
	}()
	s.logger.Info("Periodic traffic flush started", "interval", interval, "path", path)
}

// StopPeriodicFlush stops the background flush goroutine and performs
// a final flush+save.
func (s *Store) StopPeriodicFlush() {
	if s.stopFlush != nil {
		close(s.stopFlush)
	}

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
	defer s.mu.RUnlock()

	entry, ok := s.users[username]
	if !ok {
		return false
	}

	acc := &entry.account
	if !acc.Enabled {
		return false
	}
	if acc.Password != password {
		return false
	}

	now := time.Now()
	if acc.IsExpired(now) {
		return false
	}
	if acc.IsNotYetActive(now) {
		return false
	}

	// Check traffic limit with unflushed delta
	if acc.TrafficLimitBytes > 0 {
		totalUsed := acc.TrafficUsedBytes + entry.trafficDelta.Load()
		if totalUsed >= acc.TrafficLimitBytes {
			return false
		}
	}

	return true
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
	}
	return nil
}
