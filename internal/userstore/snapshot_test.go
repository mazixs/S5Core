package userstore

import (
	"testing"
	"time"
)

func TestAccountSnapshotsOwnTheirValidityDates(t *testing.T) {
	for _, view := range []string{"lookup", "policy", "identity", "identities", "save snapshot"} {
		t.Run(view, func(t *testing.T) {
			until := time.Now().Add(-time.Hour)
			from := until.Add(-time.Hour)
			store := NewStore(nil)
			path := createTestFile(t, []UserAccount{{ID: "a", Username: "alice", Password: "p", Enabled: true, ValidFrom: &from, ValidUntil: &until}})
			if err := store.LoadFromFile(path); err != nil {
				t.Fatal(err)
			}
			var gotFrom, gotUntil *time.Time
			switch view {
			case "lookup":
				acc, _ := store.Lookup("alice")
				gotFrom, gotUntil = acc.ValidFrom, acc.ValidUntil
			case "policy":
				store.mu.RLock()
				policy := store.users["alice"].account.Policy()
				store.mu.RUnlock()
				gotFrom, gotUntil = policy.ValidFrom, policy.ValidUntil
			case "identity":
				acc, _ := store.Identity("alice")
				gotFrom, gotUntil = acc.Policy.ValidFrom, acc.Policy.ValidUntil
			case "identities":
				acc := store.Identities()[0]
				gotFrom, gotUntil = acc.Policy.ValidFrom, acc.Policy.ValidUntil
			case "save snapshot":
				store.mu.RLock()
				acc := store.collectAccountsLocked()[0]
				store.mu.RUnlock()
				gotFrom, gotUntil = acc.ValidFrom, acc.ValidUntil
			}
			*gotFrom = time.Now()
			*gotUntil = time.Now().Add(time.Hour)
			acc, _ := store.Lookup("alice")
			if !acc.ValidFrom.Equal(from) || !acc.ValidUntil.Equal(until) || store.SessionStatus("alice") != SessionExpired {
				t.Fatal("editing a snapshot changed the stored validity window")
			}
		})
	}
}
