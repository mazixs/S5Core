package userstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Argon2id is the right way to store a password file and the wrong thing to
// run on every TCP connection. Measured on this code before the cache existed
// (docs/benchmarks/argon2-cost.md): 261 ms to first byte and +514 MiB of RSS
// for a single browser page, 18.7 GiB of peak RSS at 100 connections per
// second. The cost
// is per connection because SOCKS5 authenticates per connection, and a browser
// opens six to ten of them per page.
//
// verifierCache moves that cost from "once per connection" to "once per
// password". The first successful login still pays the full KDF; afterwards
// the store remembers an HMAC of the password under a key generated at
// startup and never written anywhere, and compares that in constant time.
//
// Two properties make this safe rather than merely fast:
//
//   - An entry records the exact Argon2id hash it was verified against, so a
//     password change in USERS_FILE invalidates it automatically - there is no
//     second place that has to remember to clear the cache.
//   - Once an entry exists, a wrong password is also answered from it. The
//     cache stores the one password that matches the hash, so anything else is
//     wrong by construction. That closes the obvious denial of service: an
//     attacker cannot make the server burn 64 MiB and 110 ms per connection by
//     guessing.
//
// A cache alone is not enough, because the case that hurts is a cold one: a
// browser opens six to ten connections for one page, all at the same instant,
// and all of them miss. Concurrent checks of the same credentials are
// therefore collapsed into one KDF run, and the others wait for its result.
//
// What is kept in memory is a keyed hash of the password, not the password.
// The key lives only in this process. A memory dump gives an attacker the same
// thing a memory dump of the legacy PROXY_PASSWORD mode gives them, and less
// than the plaintext fallback in the users file.
const (
	// defaultVerifierTTL bounds how long a derived password tag stays in
	// memory. It is not needed for correctness - a changed hash invalidates an
	// entry - it bounds exposure.
	defaultVerifierTTL = time.Hour
	// defaultVerifierMax caps the number of remembered accounts. Reaching it
	// means more distinct users than any single S5Core instance is expected to
	// serve; the cost of exceeding it is a KDF run, not a failure.
	defaultVerifierMax = 4096
)

// VerifyPath names what answered a password check. It exists so that the
// health of this mechanism is visible in metrics: a server whose kdf rate
// tracks its connection rate has lost the cache.
type VerifyPath string

const (
	// VerifyPathKDF means Argon2id ran.
	VerifyPathKDF VerifyPath = "kdf"
	// VerifyPathCache means a remembered verifier answered.
	VerifyPathCache VerifyPath = "cache"
	// VerifyPathCoalesced means another goroutine was already running the KDF
	// for the same credentials and this check waited for its result.
	VerifyPathCoalesced VerifyPath = "coalesced"
	// VerifyPathOverloaded means the KDF gate refused to start another run:
	// too many were already going and the queue was full or the wait ran
	// out. The check failed without an answer about the password, which is a
	// different thing from a wrong one and is counted separately - a server
	// whose overloaded rate is not zero is a server that needs either more
	// memory budget or fewer strangers.
	VerifyPathOverloaded VerifyPath = "overloaded"
)

// flight is one in-progress KDF run that other goroutines can wait on.
type flight struct {
	done chan struct{}
	ok   bool
}

type verifierEntry struct {
	tag     []byte // HMAC(key, username || 0x00 || password)
	against string // the Argon2id hash this password was checked against
	expires time.Time
}

type verifierCache struct {
	key []byte
	ttl time.Duration
	max int

	mu      sync.Mutex
	items   map[string]verifierEntry
	flights map[string]*flight
}

func newVerifierCache() *verifierCache {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand does not fail on any supported platform; if it ever
		// does, running without a cache is the safe answer.
		return &verifierCache{}
	}
	return &verifierCache{
		key:     key,
		ttl:     defaultVerifierTTL,
		max:     defaultVerifierMax,
		items:   make(map[string]verifierEntry),
		flights: make(map[string]*flight),
	}
}

func (c *verifierCache) tag(username, password string) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(username))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	return mac.Sum(nil)
}

// check answers whether the password is correct without running the KDF.
// known is false when the cache cannot answer and the caller must fall back to
// Argon2id.
func (c *verifierCache) check(username, password, hash string, now time.Time) (ok, known bool) {
	if c == nil || c.items == nil {
		return false, false
	}

	c.mu.Lock()
	entry, found := c.items[username]
	if found && (entry.against != hash || now.After(entry.expires)) {
		delete(c.items, username)
		found = false
	}
	c.mu.Unlock()

	if !found {
		return false, false
	}
	return hmac.Equal(entry.tag, c.tag(username, password)), true
}

// verify answers whether the password matches the hash, running the expensive
// check at most once per credential pair even under a burst. slow is the
// Argon2id verification itself; it is a parameter so that this file stays
// about scheduling and the KDF stays in one place.
func (c *verifierCache) verify(username, password, hash string, now time.Time, slow func() bool) (ok bool, path VerifyPath) {
	if c == nil || c.items == nil {
		return slow(), VerifyPathKDF
	}

	if ok, known := c.check(username, password, hash, now); known {
		return ok, VerifyPathCache
	}

	// The key names the whole question: this password, against this hash. The
	// hash used to be missing from it, and a waiter therefore inherited the
	// answer to a question nobody asked (audit finding F11) - a reload can
	// replace the hash while the KDF runs, and a check of the old password
	// against the new hash would join the running flight and be told yes.
	key := username + "\x00" + hash + "\x00" + hex.EncodeToString(c.tag(username, password))

	c.mu.Lock()
	if existing, running := c.flights[key]; running {
		c.mu.Unlock()
		<-existing.done
		return existing.ok, VerifyPathCoalesced
	}
	f := &flight{done: make(chan struct{})}
	c.flights[key] = f
	c.mu.Unlock()

	// The flight ends whatever slow does, including panicking. An entry left
	// in the map with a channel nobody closes is worse than the panic that
	// left it: every later check of the same credentials waits for a result
	// that will never come, and the account is locked out until a restart
	// (audit finding F15). Waiters see false, which is the right answer to a
	// check that did not happen.
	defer func() {
		c.mu.Lock()
		delete(c.flights, key)
		c.mu.Unlock()
		close(f.done)
	}()

	f.ok = slow()
	if f.ok {
		c.remember(username, password, hash, now)
	}

	return f.ok, VerifyPathKDF
}

// remember records a password that Argon2id has just accepted.
func (c *verifierCache) remember(username, password, hash string, now time.Time) {
	if c == nil || c.items == nil {
		return
	}
	entry := verifierEntry{
		tag:     c.tag(username, password),
		against: hash,
		expires: now.Add(c.ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.max {
		c.evictLocked(now)
	}
	c.items[username] = entry
}

// evictLocked drops expired entries, and if that frees nothing, the entry
// closest to expiry.
func (c *verifierCache) evictLocked(now time.Time) {
	oldestName := ""
	var oldest time.Time
	for name, e := range c.items {
		if now.After(e.expires) {
			delete(c.items, name)
			continue
		}
		if oldestName == "" || e.expires.Before(oldest) {
			oldestName, oldest = name, e.expires
		}
	}
	if len(c.items) >= c.max && oldestName != "" {
		delete(c.items, oldestName)
	}
}

// forget drops one account, for removal.
func (c *verifierCache) forget(username string) {
	if c == nil || c.items == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, username)
}

// retain drops every account that is not in the given set, for reload.
// Accounts whose password changed need no special handling: their entry no
// longer matches the hash it was verified against.
func (c *verifierCache) retain(keep map[string]*userEntry) {
	if c == nil || c.items == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for name := range c.items {
		if _, still := keep[name]; !still {
			delete(c.items, name)
		}
	}
}

func (c *verifierCache) size() int {
	if c == nil || c.items == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
