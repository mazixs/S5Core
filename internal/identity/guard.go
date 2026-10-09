// Package identity answers who a connection belongs to and whether it is
// allowed in.
//
// Plan task Ф6-2 moved it out of pkg/s5server, which knew about obfuscation,
// WebSockets, decoys, user files and lockouts at once. What lives here is the
// access decision and nothing else: it is given a credential store and
// returns a store that refuses brute force. It has no idea what a listener,
// a transport or a metric is - the caller passes hooks and gets to decide
// what those are.
package identity

import (
	"hash/fnv"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Store is the credential check this wraps: internal/socks5's CredentialStore
// by another name, declared here so that the access decision does not import
// the SOCKS5 codec to name one method.
type Store interface {
	Valid(user, password string) bool
}

// ResultStore distinguishes a bad credential from a check that could not
// run. Temporary resource failures must never contribute to lockouts.
type ResultStore interface {
	ValidResult(user, password string) (bool, error)
}

// Options configures a Guard. The two hooks are how it reports without
// knowing what telemetry is; both may be nil.
type Options struct {
	// MaxRetries is how many failures from one source end in a ban. Zero or
	// less disables the lockout - the whole of it, the hard limit on the
	// source and the soft one on the account alike. It used to disable
	// nothing: a counter that reaches 1 is already past a limit of 0, so the
	// setting documented as "off" banned a source after one wrong password
	// and held it for BanTime. Behind one NAT that is every subscriber of an
	// operator, locked out by one typo (R06, fixed in 2.0.0).
	MaxRetries int
	// BanTime is how long a source stays banned, and how long the per-account
	// counter remembers.
	BanTime time.Duration
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// OnAuthFailure is called once per refused attempt.
	OnAuthFailure func()
	// OnAccountAlert is called the first time an account is considered hot.
	OnAccountAlert func()
}

const guardShards = 256

// A guard retains at most this many sources and account names per shard.
// Unexpired bans are never evicted to admit a new source.
const guardEntriesPerShard = 256

// The lockout used to be keyed on the user name, which made the mechanism do
// the opposite of what it claimed twice over:
//
//   - a distributed run from a thousand addresses, each trying a different
//     name, never reached the limit on any key and was not slowed down at all;
//   - anyone who knew a user name could lock its owner out of their own
//     account with three wrong passwords, from a single address, for free.
//
// A brute-force run is a property of the client, so the hard limit is keyed on
// the source. The account still gets a counter, but a soft one: it raises an
// alert and slows the attempts down without ever refusing the owner.
const (
	// accountThrottle is how long an attempt against a hot account waits
	// before the password is checked at all. Enough to make an online guessing
	// run pointless, short enough that the owner's own retry is not an outage.
	accountThrottle = 250 * time.Millisecond
	// softFactor sets how many failures an account absorbs before it is
	// considered hot, as a multiple of the source limit. Higher than the hard
	// limit on purpose: several people behind one office address getting their
	// password wrong is normal.
	softFactor = 3
)

type sourceShard struct {
	mu          sync.RWMutex
	failures    map[string]sourceFailures
	banned      map[string]time.Time
	lastCleanup time.Time
}

type sourceFailures struct {
	count   int
	expires time.Time
}

// accountShard holds the soft per-account counters. They expire on their own:
// an account is "hot" only while failures keep arriving.
type accountShard struct {
	mu          sync.Mutex
	failures    map[string]accountFailures
	lastCleanup time.Time
}

type accountFailures struct {
	count   int
	expires time.Time
	alerted bool
}

// Guard is a Store with rate limiting and bans in front of it. It uses 256
// sharded maps to eliminate the global lock bottleneck.
type Guard struct {
	store      Store
	maxRetries int
	banTime    time.Duration
	logger     *slog.Logger

	onAuthFailure  func()
	onAccountAlert func()

	// lockout is whether there is a limit at all. It is decided once, from
	// MaxRetries, so that every path asks the same question: a guard that is
	// off counts nothing, bans nobody and slows nobody down.
	lockout  bool
	capacity int

	// sleep is the throttle applied to a hot account, replaceable in tests.
	sleep func(time.Duration)

	shards   [guardShards]sourceShard
	accounts [guardShards]accountShard
}

// NewGuard wraps store. The returned Guard is itself a Store, and also a
// socks5.SourcedCredentialStore by virtue of having ValidFrom - which is the
// method that makes the lockout key on the client rather than on the account.
func NewGuard(store Store, opts Options) *Guard {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	f := &Guard{
		store:          store,
		lockout:        opts.MaxRetries > 0,
		capacity:       guardEntriesPerShard,
		maxRetries:     opts.MaxRetries,
		banTime:        opts.BanTime,
		logger:         logger,
		onAuthFailure:  opts.OnAuthFailure,
		onAccountAlert: opts.OnAccountAlert,
		sleep:          time.Sleep,
	}
	for i := range f.shards {
		f.shards[i] = sourceShard{
			failures:    make(map[string]sourceFailures),
			banned:      make(map[string]time.Time),
			lastCleanup: time.Now(),
		}
	}
	for i := range f.accounts {
		f.accounts[i] = accountShard{
			failures:    make(map[string]accountFailures),
			lastCleanup: time.Now(),
		}
	}
	return f
}

func (s *Guard) shardFor(key string) *sourceShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &s.shards[h.Sum32()%guardShards]
}

func (s *Guard) accountShardFor(key string) *accountShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &s.accounts[h.Sum32()%guardShards]
}

// sourceKey normalizes the address an attempt came from. IPv6 is grouped by
// its /64, because a single client is routinely handed one and banning a
// single address would be banning one of its trillions.
//
// An empty source (an SDK caller that does not pass one) shares one bucket:
// unattributed attempts are still limited, they just cannot be told apart.
func sourceKey(source string) string {
	if source == "" {
		return "unknown"
	}
	ip := net.ParseIP(source)
	if ip == nil {
		return source
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Valid checks credentials without knowing where they came from. Everything
// that arrives this way shares one limit; see sourceKey.
func (s *Guard) Valid(user, password string) bool {
	return s.ValidFrom(user, password, "")
}

// ValidFrom is the real entry point: a hard limit on the source, a soft one on
// the account.
func (s *Guard) ValidFrom(user, password, source string) bool {
	key := sourceKey(source)
	now := time.Now()

	if s.sourceIsBanned(key, now) {
		s.countAuthFailure()
		return false
	}

	// Refuse a new source temporarily when its shard has no space. This is
	// admission pressure, not a bad password, and never removes active bans.
	if !s.reserveSource(key, now) {
		return false
	}

	// A hot account is slowed down, never refused: the owner waits a quarter
	// of a second, an online guessing run loses its throughput.
	if s.accountIsHot(user, now) {
		s.sleep(accountThrottle)
	}

	// Heavy validation (Argon2id etc.) outside any lock
	var valid bool
	if store, ok := s.store.(ResultStore); ok {
		var err error
		valid, err = store.ValidResult(user, password)
		if err != nil {
			s.forgetReservation(key)
			return false
		}
	} else {
		valid = s.store.Valid(user, password)
	}

	if !valid {
		s.recordSourceFailure(key, now)
		s.recordAccountFailure(user, now)
		s.countAuthFailure()
		return false
	}

	s.forgetSource(key)
	s.forgetAccount(user)
	return true
}

func (s *Guard) countAuthFailure() {
	if s.onAuthFailure != nil {
		s.onAuthFailure()
	}
}

func (s *Guard) sourceIsBanned(key string, now time.Time) bool {
	if !s.lockout {
		return false
	}
	shard := s.shardFor(key)
	shard.mu.RLock()
	banExpiry, isBanned := shard.banned[key]
	shard.mu.RUnlock()
	if !isBanned {
		return false
	}
	if now.Before(banExpiry) {
		return true
	}
	shard.mu.Lock()
	if expiry, exists := shard.banned[key]; exists && !now.Before(expiry) {
		delete(shard.banned, key)
		delete(shard.failures, key)
	}
	shard.mu.Unlock()
	return false
}

func (s *Guard) recordSourceFailure(key string, now time.Time) {
	if !s.lockout {
		return
	}
	shard := s.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, exists := shard.failures[key]
	if !exists && len(shard.failures) >= s.capacity {
		return
	}
	if entry.count < s.maxRetries {
		entry.count++
	}
	entry.expires = now.Add(s.banTime)
	shard.failures[key] = entry
	if entry.count >= s.maxRetries {
		_, already := shard.banned[key]
		shard.banned[key] = entry.expires
		if !already {
			s.logger.Warn("Source banned after repeated authentication failures",
				"failures", entry.count, "ban_seconds", s.banTime.Seconds())
		}
	}

}

func (s *Guard) forgetSource(key string) {
	shard := s.shardFor(key)
	shard.mu.Lock()
	delete(shard.failures, key)
	shard.mu.Unlock()
}

// accountIsHot reports whether this account has recently collected enough
// failures to be worth slowing down.
func (s *Guard) accountIsHot(user string, now time.Time) bool {
	if !s.lockout {
		return false
	}
	shard := s.accountShardFor(user)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.failures[user]
	if !ok || now.After(entry.expires) {
		return false
	}
	return entry.count >= s.softLimit()
}

func (s *Guard) softLimit() int {
	maxInt := int(^uint(0) >> 1)
	if s.maxRetries > maxInt/softFactor {
		return maxInt
	}
	limit := s.maxRetries * softFactor
	if limit < 1 {
		limit = 1
	}
	return limit
}

func (s *Guard) recordAccountFailure(user string, now time.Time) {
	if !s.lockout {
		return
	}
	shard := s.accountShardFor(user)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.failures[user]
	if !ok || now.After(entry.expires) {
		entry = accountFailures{}
	}
	if !ok && len(shard.failures) >= s.capacity {
		for key, old := range shard.failures {
			if !now.Before(old.expires) {
				delete(shard.failures, key)
			}
		}
		if len(shard.failures) >= s.capacity {
			return
		}
	}
	if entry.count < s.softLimit() {
		entry.count++
	}
	entry.expires = now.Add(s.banTime)

	if entry.count >= s.softLimit() && !entry.alerted {
		entry.alerted = true
		// Named, because an account under attack is what the operator has to
		// act on. No address here either.
		s.logger.Warn("Account is collecting authentication failures from multiple sources",
			"failures", entry.count,
		)
		if s.onAccountAlert != nil {
			s.onAccountAlert()
		}
	}
	shard.failures[user] = entry

	if now.Sub(shard.lastCleanup) > 5*time.Minute {
		for u, e := range shard.failures {
			if now.After(e.expires) {
				delete(shard.failures, u)
			}
		}
		shard.lastCleanup = now
	}
}

func (s *Guard) forgetAccount(user string) {
	shard := s.accountShardFor(user)
	shard.mu.Lock()
	delete(shard.failures, user)
	shard.mu.Unlock()
}

// reserveSource also expires partial failures. Fixed bounds apply on every
// insertion, rather than only at an occasional five-minute cleanup.
func (s *Guard) reserveSource(key string, now time.Time) bool {
	if !s.lockout {
		return true
	}
	shard := s.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.failures[key]; ok && now.Before(entry.expires) {
		return true
	}
	s.cleanupShardLocked(shard, now)
	if len(shard.failures) >= s.capacity {
		return false
	}
	shard.failures[key] = sourceFailures{expires: now.Add(s.banTime)}
	return true
}

func (s *Guard) forgetReservation(key string) {
	shard := s.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.failures[key]; ok && entry.count == 0 {
		delete(shard.failures, key)
	}
}

func (s *Guard) cleanupShardLocked(shard *sourceShard, now time.Time) {
	for key, entry := range shard.failures {
		if !now.Before(entry.expires) {
			delete(shard.failures, key)
			delete(shard.banned, key)
		}
	}
}
