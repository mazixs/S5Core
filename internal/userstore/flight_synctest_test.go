package userstore

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Coalescing means one KDF run answers several checks. That is only sound
// while those checks are asking the same question, and a reload can change
// the question underneath a running flight: USERS_FILE is re-read on SIGHUP,
// so an account's hash can be replaced in the middle of the 110 ms Argon2id
// spends on the old one.
//
// These tests drive verifierCache directly, with the KDF replaced by a
// function the test holds still. What is being tested is the scheduling - who
// waits for whom, and who is told what - and that is not reachable through a
// store without racing a real Argon2id run against a real reload.
//
// They run in a testing/synctest bubble because every assertion here is about
// a goroutine that is, or is not, waiting. synctest.Wait returns only when
// every other goroutine in the bubble is blocked, which is how the test knows
// a waiter has arrived before it releases the run it waits on; without it the
// test would be racing the code it checks. The same bubble makes a check that
// never answers cost no wall clock: the fake clock jumps to the deadline as
// soon as everything is blocked.

// answer is what one verify call came back with.
type answer struct {
	ok   bool
	path VerifyPath
}

// verifyAsync runs one check in its own goroutine and hands back a channel
// carrying its answer. A check that never answers is the defect these tests
// look for, so nothing here may block the test goroutine.
func verifyAsync(c *verifierCache, username, password, hash string, now time.Time, slow func() bool) <-chan answer {
	out := make(chan answer, 1)
	go func() {
		ok, path := c.verify(username, password, hash, now, slow)
		out <- answer{ok, path}
	}()
	return out
}

func awaitAnswer(t *testing.T, ch <-chan answer, what string) answer {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(time.Minute):
		t.Fatalf("%s never finished; it is waiting for a KDF run that is not answering its question", what)
		return answer{}
	}
}

func TestACheckAgainstANewHashDoesNotJoinTheRunForTheOldOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newVerifierCache()
		now := time.Now()

		var runs atomic.Int64
		started := make(chan struct{})
		release := make(chan struct{})

		// alice logs in with the password the file had. Argon2id starts.
		first := verifyAsync(c, "alice", "old-password", "hash-before-the-reload", now, func() bool {
			runs.Add(1)
			close(started)
			<-release
			return true
		})
		<-started

		// SIGHUP arrives and the operator's new file gives alice a new hash.
		// The password still being checked is now the wrong one.
		second := awaitAnswer(t, verifyAsync(c, "alice", "old-password", "hash-after-the-reload", now, func() bool {
			runs.Add(1)
			return false
		}), "the check against the new hash")

		if second.ok {
			t.Fatal("the old password was accepted against the new hash: the waiter inherited the answer to a different question")
		}
		if second.path != VerifyPathKDF {
			t.Fatalf("the check against the new hash was answered by %q, want its own KDF run", second.path)
		}

		close(release)
		if a := awaitAnswer(t, first, "the check against the old hash"); !a.ok {
			t.Fatal("the check that started before the reload was refused")
		}
		if got := runs.Load(); got != 2 {
			t.Fatalf("the KDF ran %d times for two different hashes, want 2", got)
		}
	})
}

// Two checks of the same password against the same hash still share one run:
// naming the hash in the key must not cost the coalescing that pays for it.
func TestTheSameQuestionIsStillAskedOnlyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newVerifierCache()
		now := time.Now()

		var runs atomic.Int64
		started := make(chan struct{})
		release := make(chan struct{})

		first := verifyAsync(c, "alice", "password", "the-hash", now, func() bool {
			runs.Add(1)
			close(started)
			<-release
			return true
		})
		<-started

		second := verifyAsync(c, "alice", "password", "the-hash", now, func() bool {
			runs.Add(1)
			return true
		})
		// The second check has arrived and is waiting, not merely scheduled.
		synctest.Wait()

		close(release)
		if a := awaitAnswer(t, first, "the first check"); !a.ok {
			t.Fatal("the first check was refused")
		}
		a := awaitAnswer(t, second, "the second check")
		if !a.ok {
			t.Fatal("the second check was refused")
		}
		if a.path != VerifyPathCoalesced {
			t.Fatalf("the second check was answered by %q, want it to wait for the run already going", a.path)
		}
		if got := runs.Load(); got != 1 {
			t.Fatalf("the KDF ran %d times for one question, want 1", got)
		}
	})
}

// A panic in the KDF is not supposed to happen - passwordhash refuses what
// Argon2id would panic on - but if one ever does, it must not take the
// account with it. The flight entry has to be gone, and its channel closed,
// by the time the panic leaves verify.
func TestAPanicInTheKDFDoesNotStrandTheAccount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newVerifierCache()
		now := time.Now()

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Error("the panic was swallowed; verify must not hide what the KDF did")
				}
			}()
			c.verify("alice", "password", "the-hash", now, func() bool {
				panic("argon2: number of rounds too small")
			})
		}()

		a := awaitAnswer(t, verifyAsync(c, "alice", "password", "the-hash", now, func() bool {
			return true
		}), "the login after the panic")
		if !a.ok {
			t.Fatal("the login after the panic was refused")
		}
		if a.path != VerifyPathKDF {
			t.Fatalf("the login after the panic was answered by %q, want a fresh KDF run", a.path)
		}
	})
}

// A goroutine already waiting on the flight has to be told something. Before
// the flight was finished in a defer, it was told nothing at all, forever.
func TestAWaiterIsReleasedWhenTheKDFPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newVerifierCache()
		now := time.Now()

		started := make(chan struct{})
		release := make(chan struct{})

		go func() {
			defer func() { _ = recover() }()
			c.verify("alice", "password", "the-hash", now, func() bool {
				close(started)
				<-release
				panic("argon2: parallelism degree too low")
			})
		}()
		<-started

		waiter := verifyAsync(c, "alice", "password", "the-hash", now, func() bool {
			t.Error("the waiter ran its own KDF instead of waiting for the run already going")
			return true
		})
		synctest.Wait()
		close(release)

		a := awaitAnswer(t, waiter, "the check waiting on the panicking run")
		if a.ok {
			t.Fatal("a check that never happened was answered yes")
		}
		if a.path != VerifyPathCoalesced {
			t.Fatalf("the waiter was answered by %q, want the path that waited", a.path)
		}
	})
}
