package identity

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// staticCredentials is a map used directly as a Store - the same thing
// socks5.StaticCredentials is, declared here so that the tests of the access
// decision do not pull the SOCKS5 codec into this package.
type staticCredentials map[string]string

func (c staticCredentials) Valid(user, password string) bool {
	pass, ok := c[user]
	return ok && password == pass
}

// accounts used by the tests below. The password is the same everywhere; what
// varies is who is guessing it and from where.
func testAccounts(names ...string) staticCredentials {
	creds := staticCredentials{}
	for _, n := range names {
		creds[n] = "correct-horse"
	}
	return creds
}

// throttleRecorder replaces the sleep so that the soft limit can be observed
// without the test actually waiting.
type throttleRecorder struct {
	mu    sync.Mutex
	total time.Duration
	calls int
}

func (r *throttleRecorder) sleep(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total += d
	r.calls++
}

func (r *throttleRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// discardLogger is for the tests below, which assert on behaviour rather than
// on what was logged.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestStore(t *testing.T, creds Store, retries int, banTime time.Duration) (*Guard, *throttleRecorder, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f2b := NewGuard(creds, Options{MaxRetries: retries, BanTime: banTime, Logger: logger})
	rec := &throttleRecorder{}
	f2b.sleep = rec.sleep
	return f2b, rec, logs
}

// A distributed run - many addresses, a different account on each - used to
// sail straight through: the counter was keyed on the user name, so no key
// ever reached the limit. Now each address runs into its own limit, and the
// accounts it guessed at are untouched.
func TestDistributedRunIsStoppedBySourceAndLeavesAccountsAlone(t *testing.T) {
	const sources = 100
	const retries = 3

	names := make([]string, 0, sources)
	for i := 0; i < sources; i++ {
		names = append(names, fmt.Sprintf("user%02d", i))
	}
	f2b, _, _ := newTestStore(t, testAccounts(names...), retries, time.Minute)

	for i, name := range names {
		attacker := fmt.Sprintf("203.0.113.%d", i%256)
		for attempt := 0; attempt < retries; attempt++ {
			if f2b.ValidFrom(name, "guess", attacker) {
				t.Fatalf("wrong password accepted for %s", name)
			}
		}
		// The source has spent its budget: even a correct password from there
		// is refused now.
		if f2b.ValidFrom(name, "correct-horse", attacker) {
			t.Fatalf("source %d was not banned after %d failures", i, retries)
		}
	}

	// Every account guessed at is still usable by its owner, from anywhere
	// else.
	for i, name := range names {
		owner := fmt.Sprintf("198.51.100.%d", i%256)
		if !f2b.ValidFrom(name, "correct-horse", owner) {
			t.Fatalf("account %s was locked out by the attack on it", name)
		}
	}
}

// Knowing a user name used to be enough to lock its owner out: three wrong
// passwords from one address and the account was gone for the ban period.
func TestGuessingSomebodyElsesNameDoesNotLockThemOut(t *testing.T) {
	const retries = 3
	f2b, _, _ := newTestStore(t, testAccounts("victim"), retries, time.Minute)

	const attacker = "203.0.113.9"
	for i := 0; i < 5; i++ {
		if f2b.ValidFrom("victim", "guess", attacker) {
			t.Fatal("wrong password accepted")
		}
	}

	if f2b.ValidFrom("victim", "correct-horse", attacker) {
		t.Fatal("the attacking source was not banned")
	}
	if !f2b.ValidFrom("victim", "correct-horse", "198.51.100.4") {
		t.Fatal("the owner was locked out of their own account")
	}
}

// An account really under attack from many addresses is worth knowing about,
// and worth slowing down - but never worth refusing, because refusing is the
// attacker's goal.
func TestAccountUnderDistributedAttackIsThrottledNotLocked(t *testing.T) {
	const retries = 2
	f2b, throttle, logs := newTestStore(t, testAccounts("victim"), retries, time.Minute)

	// Enough distinct sources to cross the soft limit, each staying under the
	// hard one so that no ban is what stops them.
	limit := f2b.softLimit()
	for i := 0; i < limit; i++ {
		src := fmt.Sprintf("203.0.113.%d", i)
		if f2b.ValidFrom("victim", "guess", src) {
			t.Fatal("wrong password accepted")
		}
	}

	if !f2b.ValidFrom("victim", "correct-horse", "198.51.100.4") {
		t.Fatal("the owner was refused because their account was under attack")
	}
	if throttle.count() == 0 {
		t.Fatal("a hot account was not throttled at all")
	}
	if !strings.Contains(logs.String(), "Account is collecting authentication failures") {
		t.Fatalf("no alert was raised for the account under attack:\n%s", logs.String())
	}
}

// A successful login clears the soft counter: the throttle follows the attack,
// it does not accumulate over a day of ordinary typos.
func TestSuccessClearsTheSoftCounter(t *testing.T) {
	const retries = 2
	f2b, throttle, _ := newTestStore(t, testAccounts("victim"), retries, time.Minute)

	for i := 0; i < f2b.softLimit(); i++ {
		f2b.ValidFrom("victim", "guess", fmt.Sprintf("203.0.113.%d", i))
	}
	if !f2b.ValidFrom("victim", "correct-horse", "198.51.100.4") {
		t.Fatal("owner refused")
	}
	before := throttle.count()
	if !f2b.ValidFrom("victim", "correct-horse", "198.51.100.4") {
		t.Fatal("owner refused on the second login")
	}
	if throttle.count() != before {
		t.Fatal("the account was still throttled after a successful login")
	}
}

// Banning a single IPv6 address would be banning one of the trillions a
// client is routinely handed, so the limit applies to the /64.
func TestIPv6IsLimitedByPrefixNotByAddress(t *testing.T) {
	const retries = 3
	f2b, _, _ := newTestStore(t, testAccounts("victim"), retries, time.Minute)

	for i := 0; i < retries; i++ {
		src := fmt.Sprintf("2001:db8:1:1::%x", i+1)
		if f2b.ValidFrom("victim", "guess", src) {
			t.Fatal("wrong password accepted")
		}
	}

	// A different address in the same /64 is the same client.
	if f2b.ValidFrom("victim", "correct-horse", "2001:db8:1:1::ffff") {
		t.Fatal("rotating the address inside one /64 escaped the limit")
	}
	// A different /64 is not.
	if !f2b.ValidFrom("victim", "correct-horse", "2001:db8:1:2::1") {
		t.Fatal("an unrelated /64 was banned")
	}
}

// docs/design/observability-policy.md: a ban is worth logging, who was banned is not
// something this log gets to say.
func TestBansDoNotPutAddressesInTheLog(t *testing.T) {
	const attacker = "203.0.113.77"
	f2b, _, logs := newTestStore(t, testAccounts("victim"), 2, time.Minute)

	for i := 0; i < 3; i++ {
		f2b.ValidFrom("victim", "guess", attacker)
	}

	out := logs.String()
	if !strings.Contains(out, "Source banned") {
		t.Fatalf("the ban was not logged at all:\n%s", out)
	}
	if strings.Contains(out, attacker) {
		t.Fatalf("the log names the source address:\n%s", out)
	}
}

func TestFail2BanStore(t *testing.T) {
	mockStore := staticCredentials{
		"admin": "secret",
	}

	maxRetries := 3
	banTime := 50 * time.Millisecond
	f2b := NewGuard(mockStore, Options{MaxRetries: maxRetries, BanTime: banTime})

	// 1. Success login
	if !f2b.Valid("admin", "secret") {
		t.Error("Expected valid login for admin:secret")
	}

	// 2. Failed logins triggering ban
	for i := 0; i < maxRetries; i++ {
		if f2b.Valid("admin", "wrong") {
			t.Errorf("Expected invalid login on attempt %d", i+1)
		}
	}

	// 3. User should now be banned, even with correct password
	if f2b.Valid("admin", "secret") {
		t.Error("Expected user to be banned")
	}

	// 4. Wait for ban to expire
	time.Sleep(banTime + 10*time.Millisecond)

	// 5. User should be able to login again
	if !f2b.Valid("admin", "secret") {
		t.Error("Expected user to be unbanned and login successfully")
	}
}

func TestFail2BanStoreConcurrent(t *testing.T) {
	mockStore := staticCredentials{
		"admin": "secret",
	}

	maxRetries := 3
	banTime := 100 * time.Millisecond
	f2b := NewGuard(mockStore, Options{MaxRetries: maxRetries, BanTime: banTime})
	// The account throttle sleeps 250 ms per attempt once the account is hot.
	// This test is about the source ban, and with the real sleep in place the
	// 30 attempts below spend seconds asleep - long enough for the ban they
	// are supposed to produce to expire before it is checked.
	f2b.sleep = func(time.Duration) {}

	// Concurrent failed attempts from multiple goroutines
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < maxRetries; j++ {
				f2b.Valid("admin", "wrong")
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// User should be banned
	if f2b.Valid("admin", "secret") {
		t.Error("Expected user to be banned after concurrent failures")
	}

	// Wait for ban to expire. A banned attempt is refused without recording a
	// new failure, so polling does not extend the ban.
	deadline := time.Now().Add(5 * time.Second)
	for !f2b.Valid("admin", "secret") {
		if time.Now().After(deadline) {
			t.Fatal("Expected user to be unbanned and login successfully")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFail2BanStoreSharding(t *testing.T) {
	mockStore := staticCredentials{}
	f2b := NewGuard(mockStore, Options{MaxRetries: 3, BanTime: time.Minute})

	shards := make(map[uint32]struct{})
	for i := 0; i < 1000; i++ {
		user := fmt.Sprintf("user%d", i)
		shard := f2b.shardFor(user)
		// find shard index
		for idx := range f2b.shards {
			if &f2b.shards[idx] == shard {
				shards[uint32(idx)] = struct{}{}
				break
			}
		}
	}

	if len(shards) < 2 {
		t.Errorf("expected users distributed across multiple shards, got %d", len(shards))
	}
}

func TestFail2BanStoreCleanup(t *testing.T) {
	mockStore := staticCredentials{"alice": "secret"}
	f2b := NewGuard(mockStore, Options{MaxRetries: 2, BanTime: 50 * time.Millisecond})

	// Trigger ban
	f2b.Valid("alice", "wrong")
	f2b.Valid("alice", "wrong")

	if f2b.Valid("alice", "secret") {
		t.Error("expected alice to be banned")
	}

	// Wait for expiry + cleanup interval
	time.Sleep(60 * time.Millisecond)

	// This call should trigger cleanup and then succeed because ban expired
	if !f2b.Valid("alice", "secret") {
		t.Error("expected ban to be expired and valid login to succeed")
	}
}

// "Zero or less disables the lockout" is what the field says, and it used to
// do the opposite: a failure counter that reaches 1 is already past a limit of
// 0, so the first wrong password banned the source for the whole BanTime.
// Behind one NAT that is an operator's entire subscriber base, locked out by
// one typo.
//
// R06 of docs/fix-plan.md.
func TestAGuardWithNoLimitBansNobody(t *testing.T) {
	for _, retries := range []int{0, -1} {
		guard := NewGuard(staticCredentials{"alice": "right"}, Options{
			MaxRetries: retries,
			BanTime:    time.Hour,
			Logger:     discardLogger(),
		})
		slept := 0
		guard.sleep = func(time.Duration) { slept++ }

		for i := range 10 {
			if guard.ValidFrom("alice", "wrong", "198.51.100.4:1024") {
				t.Fatalf("MaxRetries=%d: attempt %d accepted a wrong password", retries, i)
			}
		}
		if !guard.ValidFrom("alice", "right", "198.51.100.4:1024") {
			t.Errorf("MaxRetries=%d: the owner was locked out by a guard that is off", retries)
		}
		if slept != 0 {
			t.Errorf("MaxRetries=%d: a guard that is off throttled %d attempts", retries, slept)
		}
	}
}

// A guard that is off keeps nothing: the maps that exist to hold failures stay
// empty, so a run from many addresses cannot grow them.
func TestAGuardWithNoLimitRemembersNothing(t *testing.T) {
	guard := NewGuard(staticCredentials{"alice": "right"}, Options{
		MaxRetries: 0,
		BanTime:    time.Hour,
		Logger:     discardLogger(),
	})
	for i := range 100 {
		source := fmt.Sprintf("203.0.113.%d:1024", i%256)
		guard.ValidFrom("alice", "wrong", source)
	}
	for i := range guard.shards {
		guard.shards[i].mu.RLock()
		failures, banned := len(guard.shards[i].failures), len(guard.shards[i].banned)
		guard.shards[i].mu.RUnlock()
		if failures != 0 || banned != 0 {
			t.Fatalf("shard %d holds %d failures and %d bans", i, failures, banned)
		}
	}
}

// And the limit still works when there is one: this is the same run against a
// guard that was asked for three.
func TestAGuardWithALimitStillBans(t *testing.T) {
	guard := NewGuard(staticCredentials{"alice": "right"}, Options{
		MaxRetries: 3,
		BanTime:    time.Hour,
		Logger:     discardLogger(),
	})
	guard.sleep = func(time.Duration) {}
	for range 3 {
		guard.ValidFrom("alice", "wrong", "198.51.100.4:1024")
	}
	if guard.ValidFrom("alice", "right", "198.51.100.4:1024") {
		t.Error("the right password was accepted from a banned source")
	}
	// A different source is unaffected: the limit is on the client.
	if !guard.ValidFrom("alice", "right", "198.51.100.5:1024") {
		t.Error("an unrelated source was caught by another source's ban")
	}
}
