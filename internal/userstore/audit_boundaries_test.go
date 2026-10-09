package userstore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

func TestDuplicateMemberKeysAreRejectedEvenWhenDisabled(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	users := []UserAccount{{ID: "a", Username: "alice", Enabled: true, TunnelKey: key}, {ID: "b", Username: "bob", Enabled: false, TunnelKey: key}}
	if err := validateUsers(users); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestDuplicateAccountsFailAtStartupAndReloadWithoutReplacingLiveState(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for _, kind := range []string{"key", "username", "ID", "name-versus-ID"} {
		t.Run(kind, func(t *testing.T) {
			users := []UserAccount{{ID: "a", Username: "alice", Enabled: true, TunnelKey: key}, {ID: "b", Username: "bob", Enabled: false, TunnelKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))}}
			switch kind {
			case "key":
				users[1].TunnelKey = key
			case "username":
				users[1].Username = "alice"
			case "ID":
				users[1].ID = "a"
			case "name-versus-ID":
				users[1].Username = "a"
			}
			bad := createTestFile(t, users)
			if err := NewStore(nil).LoadFromFile(bad); err == nil {
				t.Fatal("invalid initial file accepted")
			}
			store, path := loadedCounterStore(t)
			body, err := os.ReadFile(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if err = store.Reload(path); err == nil {
				t.Fatal("invalid reload accepted")
			}
			acc, ok := store.Lookup("alice")
			if store.UserCount() != 1 || !ok || acc.TrafficUsedBytes != 100 {
				t.Fatal("failed reload replaced live state")
			}
		})
	}
}

func TestAddUserRejectsEmptyNamesAndExistingIDsWithoutChangingStore(t *testing.T) {
	store, path := loadedCounterStore(t)
	for _, name := range []string{"", "a"} {
		if err := store.AddUser(name, "p"); err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
	if store.UserCount() != 1 {
		t.Fatal("invalid addition changed store")
	}
	if err := store.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(nil).LoadFromFile(path); err != nil {
		t.Fatalf("invalid add corrupted file: %v", err)
	}
}

func TestKDFGateAccountsForActualPHCMemory(t *testing.T) {
	gate := newKDFGate(256 << 20)
	var inUse, peak atomic.Int64
	var workers sync.WaitGroup
	release := make(chan struct{})
	for _, cost := range []int64{128 << 20, 64 << 20, 128 << 20, 64 << 20} {
		workers.Go(func() {
			gate.runWithMemory(cost, func() bool {
				used := inUse.Add(cost)
				for old := peak.Load(); used > old; old = peak.Load() {
					if peak.CompareAndSwap(old, used) {
						break
					}
				}
				<-release
				inUse.Add(-cost)
				return true
			})
		})
	}
	deadline := time.Now().Add(time.Second)
	for len(gate.admitted) < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	workers.Wait()
	if peak.Load() > 256<<20 || peak.Load() == 0 {
		t.Fatalf("memory budget violated: %d", peak.Load())
	}
	if _, ran := gate.runWithMemory(512<<20, func() bool { t.Error("oversized PHC ran"); return true }); ran {
		t.Fatal("job larger than budget admitted")
	}
	cost, err := passwordhash.MemoryCost("$argon2id$v=19$m=524288,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil || cost != 512<<20 {
		t.Fatalf("wrong PHC cost: %d %v", cost, err)
	}
}

func TestCoalescedChecksPreserveUnavailableResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newVerifierCache()
		release := make(chan struct{})
		results := make(chan error, 2)
		check := func() {
			_, _, err := cache.verifyResult("alice", "p", "hash", time.Now(), func() (bool, error) { <-release; return false, ErrVerificationUnavailable })
			results <- err
		}
		go check()
		synctest.Wait()
		go check()
		synctest.Wait()
		close(release)
		synctest.Wait()
		for range 2 {
			if err := <-results; !errors.Is(err, ErrVerificationUnavailable) {
				t.Fatalf("unavailability lost: %v", err)
			}
		}
	})
}

func TestNegativeStoreBudgetRetainsTheDefaultGate(t *testing.T) {
	store := NewStore(nil)
	store.SetKDFBudget(-1)
	if store.kdf == nil || store.kdf.budget != defaultKDFBudget {
		t.Fatal("negative setting disabled gate")
	}
}

func TestNextMemberBoundaryIgnoresDisabledKeysAndExpiresAfterInclusiveUntil(t *testing.T) {
	now := time.Now()
	from, until := now.Add(2*time.Second), now.Add(4*time.Second)
	store := NewStore(nil)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store.users["dated"] = &userEntry{account: UserAccount{Enabled: true, TunnelKey: key, ValidFrom: &from, ValidUntil: &until}}
	store.users["disabled"] = &userEntry{account: UserAccount{Enabled: false, TunnelKey: key, ValidFrom: &now}}
	store.users["without-key"] = &userEntry{account: UserAccount{Enabled: true, ValidFrom: &now}}
	store.users["undated"] = &userEntry{account: UserAccount{Enabled: true, TunnelKey: key}}
	if got := store.NextTunnelValidityChange(now); !got.Equal(from) {
		t.Fatal("wrong activation boundary", got)
	}
	if got := store.NextTunnelValidityChange(from); !got.Equal(until.Add(time.Nanosecond)) {
		t.Fatal("until boundary excluded its exact timestamp", got)
	}
	if got := store.NextTunnelValidityChange(until.Add(time.Second)); !got.IsZero() {
		t.Fatal("expired dates scheduled again", got)
	}
}
