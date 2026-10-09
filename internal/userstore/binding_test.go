package userstore

import (
	"testing"

	"github.com/mazixs/S5Core/internal/identity"
)

func TestBindingFollowsPolicyButNotReplacement(t *testing.T) {
	path := createTestFile(t, []UserAccount{{ID: "a", Username: "alice", Password: "p", Enabled: true}})
	store := NewStore(nil)
	if err := store.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	bound := store.Bind("alice")
	if bound == nil {
		t.Fatal("missing binding")
	}
	ref := store.TunnelMembers()[0].Reference
	bound.Counter().Add(100)
	editAccountFile(t, path, func(file *UsersFile) { file.Users[0].Role = "operator"; file.Users[0].TrafficLimitBytes = 100 })
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	if bound.Status() != SessionQuotaExceeded {
		t.Fatal("same account binding missed new policy")
	}
	actor, ok := bound.Identity()
	if !ok || actor.Role != identity.RoleOperator || actor.Policy.TrafficUsedBytes != 100 {
		t.Fatalf("old binding missed role/usage: %+v", actor)
	}
	if store.BindMember(ref) == nil {
		t.Fatal("ordinary reload invalidated current member")
	}
	editAccountFile(t, path, func(file *UsersFile) {
		file.Users[0].ID = "replacement"
		file.Users[0].TrafficUsedBytes = 0
		file.Users[0].TrafficLimitBytes = 1
	})
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	if bound.Status() != SessionExpired {
		t.Fatal("binding adopted replacement quota")
	}
	if _, ok := bound.Identity(); ok {
		t.Fatal("binding adopted replacement identity")
	}
	if store.BindMember(ref) != nil {
		t.Fatal("stale roster reference resolved replacement")
	}
	fresh := store.Bind("alice")
	if fresh == nil || fresh.Counter() == bound.Counter() || fresh.Status() != SessionAllowed {
		t.Fatal("replacement did not receive a separate binding")
	}
	bound.Counter().Add(128 << 10)
	acc, _ := store.Lookup("alice")
	if acc.TrafficUsedBytes != 0 {
		t.Fatalf("replacement billed old session: %d", acc.TrafficUsedBytes)
	}
	fresh.Counter().Add(1)
	if fresh.Status() != SessionQuotaExceeded {
		t.Fatal("replacement quota is not enforced")
	}
}

func TestRemovedAndRecreatedIDCannotReviveBinding(t *testing.T) {
	store := NewStore(nil)
	if err := store.AddUser("alice", "p"); err != nil {
		t.Fatal(err)
	}
	old := store.Bind("alice")
	before, ok := old.Identity()
	if !ok {
		t.Fatal("missing old identity")
	}
	ref := store.TunnelMembers()[0].Reference
	if err := store.RemoveUser("alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.AddUser("alice", "q"); err != nil {
		t.Fatal(err)
	}
	fresh := store.Bind("alice")
	after, ok := fresh.Identity()
	if !ok || after.ID != before.ID {
		t.Fatal("test requires recreation with the same ID")
	}
	if old.Status() != SessionExpired || old.Counter() == fresh.Counter() {
		t.Fatal("recreation revived old binding")
	}
	if _, ok := old.Identity(); ok {
		t.Fatal("old actor survived recreation")
	}
	if store.BindMember(ref) != nil {
		t.Fatal("old member reference survived recreation")
	}
	if store.BindMember(store.TunnelMembers()[0].Reference) == nil {
		t.Fatal("new member reference not resolvable")
	}
}

func TestRenamePreservesCounterButRevokesOldNameBinding(t *testing.T) {
	path := createTestFile(t, []UserAccount{{ID: "a", Username: "alice", Password: "p", Enabled: true}})
	store := NewStore(nil)
	if err := store.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	old := store.Bind("alice")
	old.Counter().Add(42)
	ref := store.TunnelMembers()[0].Reference
	editAccountFile(t, path, func(file *UsersFile) { file.Users[0].Username = "renamed" })
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	fresh := store.Bind("renamed")
	if fresh == nil || fresh.Counter() != old.Counter() || old.Status() != SessionExpired || store.BindMember(ref) != nil {
		t.Fatal("rename lost billing or preserved obsolete credentials")
	}
	acc, _ := store.Lookup("renamed")
	if acc.TrafficUsedBytes != 42 {
		t.Fatal("rename lost traffic")
	}
	if store.Bind("missing") != nil || store.BindMember("unqualified") != nil || store.BindMember("missing:renamed") != nil {
		t.Fatal("unknown binding accepted")
	}
}
