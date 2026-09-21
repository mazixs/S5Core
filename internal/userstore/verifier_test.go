package userstore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// The property these tests protect is the one measured in
// docs/benchmarks/argon2-cost.md: Argon2id costs 110 ms and 64 MiB, and SOCKS5
// authenticates once per TCP connection, so running the KDF per connection is
// what made USERS_FILE
// unusable in production. Every test here is about how often the KDF runs, not
// about whether the password check is correct - correctness is covered by the
// store tests.

type kdfCounter struct {
	kdf        atomic.Int64
	cached     atomic.Int64
	coalesced  atomic.Int64
	overloaded atomic.Int64
}

func (c *kdfCounter) observe(path VerifyPath) {
	switch path {
	case VerifyPathKDF:
		c.kdf.Add(1)
	case VerifyPathCache:
		c.cached.Add(1)
	case VerifyPathCoalesced:
		c.coalesced.Add(1)
	case VerifyPathOverloaded:
		c.overloaded.Add(1)
	}
}

// hashedStore returns a store holding one account with an Argon2id password,
// plus the counter recording which path answered each check.
func hashedStore(t *testing.T, username, password string) (*Store, *kdfCounter) {
	t.Helper()
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	path := createTestFile(t, []UserAccount{{
		ID:           "u-001",
		Username:     username,
		PasswordHash: hash,
		Enabled:      true,
	}})
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	c := &kdfCounter{}
	s.SetVerifyObserver(c.observe)
	return s, c
}

func TestArgon2idRunsOncePerPassword(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")

	const logins = 10 // one browser page is six to ten connections
	for i := 0; i < logins; i++ {
		if !s.IsValid("alice", "secret-password") {
			t.Fatalf("login %d rejected", i)
		}
	}

	if got := c.kdf.Load(); got != 1 {
		t.Fatalf("Argon2id ran %d times for %d logins, want exactly 1", got, logins)
	}
	if got := c.cached.Load(); got != logins-1 {
		t.Fatalf("cache answered %d checks, want %d", got, logins-1)
	}
}

// A wrong password must not be able to force the KDF: otherwise anyone who can
// open a TCP connection can make the server spend 64 MiB and 110 ms per guess.
func TestWrongPasswordIsAnsweredFromTheCache(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")

	if !s.IsValid("alice", "secret-password") {
		t.Fatal("first login rejected")
	}
	kdfAfterFirst := c.kdf.Load()

	for i := 0; i < 50; i++ {
		if s.IsValid("alice", "guess") {
			t.Fatal("wrong password accepted")
		}
	}

	if got := c.kdf.Load(); got != kdfAfterFirst {
		t.Fatalf("50 wrong guesses triggered %d extra KDF runs, want 0", got-kdfAfterFirst)
	}
}

// An unknown account never reaches the KDF at all - there is no hash to check
// against - so guessing user names is cheap for the server too.
func TestUnknownUserNeverReachesTheKDF(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")

	for i := 0; i < 20; i++ {
		if s.IsValid("nobody", "whatever") {
			t.Fatal("unknown user accepted")
		}
	}
	if got := c.kdf.Load() + c.cached.Load(); got != 0 {
		t.Fatalf("unknown user caused %d password checks, want 0", got)
	}
}

// The cache entry records the hash it was verified against, so changing the
// password in USERS_FILE invalidates it with no explicit cache clearing.
func TestPasswordChangeInvalidatesTheEntry(t *testing.T) {
	s, c := hashedStore(t, "alice", "old-password")
	if !s.IsValid("alice", "old-password") {
		t.Fatal("first login rejected")
	}

	newHash, err := passwordhash.Hash("new-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	path := createTestFile(t, []UserAccount{{
		ID:           "u-001",
		Username:     "alice",
		PasswordHash: newHash,
		Enabled:      true,
	}})
	if err := s.Reload(path); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if s.IsValid("alice", "old-password") {
		t.Fatal("old password still accepted after reload")
	}
	if !s.IsValid("alice", "new-password") {
		t.Fatal("new password rejected after reload")
	}
	if got := c.kdf.Load(); got < 2 {
		t.Fatalf("KDF ran %d times, want at least 2 (once per password)", got)
	}
}

func TestRemovedUserIsForgotten(t *testing.T) {
	s, _ := hashedStore(t, "alice", "secret-password")
	if !s.IsValid("alice", "secret-password") {
		t.Fatal("first login rejected")
	}
	if s.verifier.size() != 1 {
		t.Fatalf("cache holds %d entries, want 1", s.verifier.size())
	}

	if err := s.RemoveUser("alice"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if s.verifier.size() != 0 {
		t.Fatal("cache still holds the removed account")
	}
	if s.IsValid("alice", "secret-password") {
		t.Fatal("removed user still authenticates")
	}
}

// A reload that drops an account must drop its cached verifier too.
func TestReloadForgetsAccountsThatDisappeared(t *testing.T) {
	s, _ := hashedStore(t, "alice", "secret-password")
	if !s.IsValid("alice", "secret-password") {
		t.Fatal("first login rejected")
	}

	hash, err := passwordhash.Hash("other")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	path := createTestFile(t, []UserAccount{{
		ID:           "u-002",
		Username:     "bob",
		PasswordHash: hash,
		Enabled:      true,
	}})
	if err := s.Reload(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.verifier.size() != 0 {
		t.Fatalf("cache kept %d entries for accounts that no longer exist", s.verifier.size())
	}
}

func TestExpiredEntryFallsBackToTheKDF(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")
	s.verifier.ttl = time.Nanosecond

	if !s.IsValid("alice", "secret-password") {
		t.Fatal("first login rejected")
	}
	time.Sleep(time.Millisecond)
	if !s.IsValid("alice", "secret-password") {
		t.Fatal("second login rejected")
	}

	if got := c.kdf.Load(); got != 2 {
		t.Fatalf("KDF ran %d times, want 2 (the entry expired between logins)", got)
	}
}

func TestEvictionKeepsTheCacheBounded(t *testing.T) {
	c := newVerifierCache()
	c.max = 4
	now := time.Now()
	for i := 0; i < 20; i++ {
		c.remember(string(rune('a'+i)), "password", "hash", now.Add(time.Duration(i)*time.Minute))
	}
	if c.size() > c.max {
		t.Fatalf("cache holds %d entries, want at most %d", c.size(), c.max)
	}
}

// The store is used from every connection goroutine at once; the cache must
// not be the place that serialises them or races.
func TestConcurrentLoginsShareOneKDFRun(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.IsValid("alice", "secret-password") {
				t.Error("concurrent login rejected")
			}
		}()
	}
	wg.Wait()

	// This is the case that actually hurts: a cold cache and a burst of
	// connections arriving together, which is what a browser does on every
	// page. Without coalescing, all 32 run Argon2id at 64 MiB each.
	if got := c.kdf.Load(); got != 1 {
		t.Fatalf("Argon2id ran %d times for 32 concurrent logins, want exactly 1", got)
	}
	if got := c.coalesced.Load() + c.cached.Load(); got != 31 {
		t.Fatalf("%d checks avoided the KDF, want 31", got)
	}
}
