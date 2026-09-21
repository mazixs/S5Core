package userstore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// F06 in docs/reports/code-quality-audit-2026-09-20.md. The verifier cache
// collapses concurrent checks of the *same* credentials; different wrong
// passwords against a cold account are different flights, so nothing stopped
// 32 of them running Argon2id at once and asking the machine for 2 GiB. These
// tests are about the bound: how many runs happen together, what happens to
// the rest, and which checks never reach the KDF at all.

// peak records the highest number of calls inside f at one time.
type peak struct {
	now atomic.Int64
	max atomic.Int64
}

func (p *peak) enter() {
	n := p.now.Add(1)
	for {
		old := p.max.Load()
		if n <= old || p.max.CompareAndSwap(old, n) {
			return
		}
	}
}

func (p *peak) leave() { p.now.Add(-1) }

// The memory budget is the whole point: the gate lets through as many runs as
// the budget pays for and not one more, however many arrive.
func TestTheGateRunsAsManyChecksAsTheBudgetPaysFor(t *testing.T) {
	for _, tc := range []struct {
		budget int64
		want   int64
	}{
		{budget: passwordhash.MemoryBytes, want: 1},
		{budget: 4 * passwordhash.MemoryBytes, want: 4},
		{budget: defaultKDFBudget, want: defaultKDFBudget / passwordhash.MemoryBytes},
		// Less than one run still has to allow one, or no password is ever
		// checked.
		{budget: passwordhash.MemoryBytes / 8, want: 1},
	} {
		g := newKDFGate(tc.budget)
		g.wait = 5 * time.Second

		var p peak
		release := make(chan struct{})
		var wg sync.WaitGroup
		// Exactly as many callers as the gate admits at once, plus its whole
		// queue: more would be refused and would not measure the bound.
		callers := cap(g.admitted)
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				g.run(func() bool {
					p.enter()
					<-release
					p.leave()
					return true
				})
			}()
		}

		// Wait for the gate to fill: the peak cannot rise once every permit
		// is held.
		deadline := time.Now().Add(5 * time.Second)
		for p.now.Load() < tc.want && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
		got := p.max.Load()
		close(release)
		wg.Wait()

		if got != tc.want {
			t.Errorf("a budget of %d MiB ran %d checks at once, want %d",
				tc.budget>>20, got, tc.want)
		}
	}
}

// Past the queue the gate refuses instead of waiting. A queue that grows with
// the arrival rate is the unbounded thing the gate exists to stop.
func TestTheGateRefusesRatherThanQueueWithoutEnd(t *testing.T) {
	g := newKDFGate(passwordhash.MemoryBytes)
	g.wait = 5 * time.Second

	release := make(chan struct{})
	inside := make(chan struct{}, cap(g.admitted))
	var wg sync.WaitGroup
	for i := 0; i < cap(g.admitted); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.run(func() bool {
				inside <- struct{}{}
				<-release
				return true
			})
		}()
	}

	// One caller is running; the rest are queued. Give them time to occupy
	// the queue before the one that must be refused arrives.
	<-inside
	deadline := time.Now().Add(5 * time.Second)
	for len(g.admitted) < cap(g.admitted) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	ok, ran := g.run(func() bool {
		t.Error("the gate ran a check although its queue was full")
		return true
	})
	waited := time.Since(start)

	close(release)
	wg.Wait()

	if ran {
		t.Fatalf("a check past a full queue of %d reported that it ran", cap(g.admitted))
	}
	if ok {
		t.Fatal("a refused check reported success; a refusal is not an answer about the password")
	}
	if waited > time.Second {
		t.Fatalf("the refusal took %v; a full queue is refused at once, not waited out", waited)
	}
}

// Inside the queue a check waits, and the wait is bounded. The bound is the
// backstop for a machine where the KDF is slower than the queue depth assumed.
func TestAQueuedCheckWaitsButNotForever(t *testing.T) {
	g := newKDFGate(passwordhash.MemoryBytes)
	g.wait = 100 * time.Millisecond

	release := make(chan struct{})
	running := make(chan struct{})
	go func() {
		g.run(func() bool {
			close(running)
			<-release
			return true
		})
	}()
	<-running

	start := time.Now()
	ok, ran := g.run(func() bool {
		t.Error("the gate ran a check although the permit was held")
		return true
	})
	waited := time.Since(start)
	close(release)

	if ran || ok {
		t.Fatalf("a check that outwaited the gate reported ran=%v ok=%v, want false false", ran, ok)
	}
	if waited < g.wait {
		t.Fatalf("the check gave up after %v, want at least the %v it is allowed to wait", waited, g.wait)
	}
	if waited > 10*g.wait {
		t.Fatalf("the check waited %v, want the wait bounded near %v", waited, g.wait)
	}
}

// A gate is a bound a caller asks for. Asking for none is a decision, not an
// accident, and it has to be expressible.
func TestNoBudgetMeansNoGate(t *testing.T) {
	if g := newKDFGate(-1); g != nil {
		t.Fatal("a negative budget built a gate; it asks for no bound at all")
	}

	var g *kdfGate
	ran := false
	ok, did := g.run(func() bool { ran = true; return true })
	if !ok || !did || !ran {
		t.Fatalf("a nil gate answered ok=%v ran=%v called=%v, want it to simply run the check", ok, did, ran)
	}
}

// The store's own path: many different wrong passwords against one cold
// account. This is the shape of the finding - each is a different flight, so
// coalescing does nothing - and the bound has to hold through IsValid, not
// only in the gate's own unit test.
func TestDifferentWrongPasswordsDoNotAllReachTheKDF(t *testing.T) {
	const attempts = 16

	s, c := hashedStore(t, "alice", "secret-password")
	// One run at a time, so the queue is five deep and the rest must be
	// refused. At the default budget this test would need 2 GiB to state the
	// same thing.
	s.SetKDFBudget(passwordhash.MemoryBytes)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if s.IsValid("alice", "wrong-password-"+string(rune('a'+i))) {
				t.Error("a wrong password was accepted")
			}
		}(i)
	}
	wg.Wait()

	kdf, refused := c.kdf.Load(), c.overloaded.Load()
	if kdf+refused != attempts {
		t.Fatalf("%d checks ran the KDF and %d were refused, want the two to account for all %d",
			kdf, refused, attempts)
	}
	if refused == 0 {
		t.Fatalf("all %d different wrong passwords reached Argon2id; at 64 MiB a run that is %d MiB "+
			"asked for by whoever opened the connections", attempts, attempts*passwordhash.MemoryBytes>>20)
	}
	if kdf > int64(cap(s.kdf.admitted)) {
		t.Fatalf("%d checks reached the KDF although the gate admits %d at a time including its queue",
			kdf, cap(s.kdf.admitted))
	}
}

// An ordinary login is not collateral damage: the gate is sized so that a
// browser opening a page does not meet it.
func TestTheGateDoesNotStandInTheWayOfLoggingIn(t *testing.T) {
	s, c := hashedStore(t, "alice", "secret-password")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.IsValid("alice", "secret-password") {
				t.Error("a correct password was refused")
			}
		}()
	}
	wg.Wait()

	if got := c.overloaded.Load(); got != 0 {
		t.Fatalf("%d of 10 concurrent logins with the same correct password were refused by the gate", got)
	}
}

// Every cheap reason to say no is checked before the expensive one. An
// account that cannot connect whatever its password is must not be able to
// make the server run Argon2id by trying.
func TestAnAccountThatCannotConnectNeverPaysForTheKDF(t *testing.T) {
	hash, err := passwordhash.Hash("secret-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	for _, tc := range []struct {
		name    string
		account UserAccount
	}{
		{"disabled", UserAccount{Username: "u", PasswordHash: hash}},
		{"expired", UserAccount{Username: "u", PasswordHash: hash, Enabled: true, ValidUntil: &past}},
		{"not yet valid", UserAccount{Username: "u", PasswordHash: hash, Enabled: true, ValidFrom: &future}},
		{"out of quota", UserAccount{
			Username: "u", PasswordHash: hash, Enabled: true,
			TrafficLimitBytes: 1000, TrafficUsedBytes: 1000,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.account.ID = "u-001"
			path := createTestFile(t, []UserAccount{tc.account})
			s := NewStore(nil)
			if err := s.LoadFromFile(path); err != nil {
				t.Fatalf("load: %v", err)
			}
			c := &kdfCounter{}
			s.SetVerifyObserver(c.observe)

			if s.IsValid("u", "secret-password") {
				t.Fatal("an account that cannot connect was let in")
			}
			if got := c.kdf.Load(); got != 0 {
				t.Fatalf("Argon2id ran %d times for an account refused for a reason a map lookup "+
					"already knew; that is 64 MiB and 110 ms spent to reach a decision already made", got)
			}
		})
	}
}
