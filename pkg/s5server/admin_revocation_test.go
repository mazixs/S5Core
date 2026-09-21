package s5server

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/mazixs/S5Core/internal/identity"
	"github.com/mazixs/S5Core/internal/userstore"
)

// writeUsers replaces the account file the way an operator does before a
// SIGHUP.
func writeUsers(t *testing.T, path string, accounts []userstore.UserAccount) {
	t.Helper()
	body, err := json.Marshal(userstore.UsersFile{Users: accounts})
	if err != nil {
		t.Fatalf("marshal the users file: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write the users file: %v", err)
	}
}

// A handle from Server.As is not a session and not a capability: it holds a
// name, and the store answers for that name every time. These tests are that
// property from the three directions it can be lost - a demotion, a removal
// and a disabling - plus the one thing the listing must never carry.
//
// Findings F07 and F08 of docs/reports/code-quality-audit-2026-09-20.md.

// F07. An admin that demotes itself has demoted itself. The handle it is
// holding used to carry the role it was issued with, so the call that took
// the permission away was the last call that needed it: everything after it
// went on working.
func TestDemotingYourselfTakesEffectOnTheHandleYouHold(t *testing.T) {
	srv := adminServer(t)
	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}

	if err := admin.SetRole("root", identity.RoleUser); err != nil {
		t.Fatalf("an admin may not demote itself: %v", err)
	}

	if role, err := admin.Role(); err != nil || role != identity.RoleUser {
		t.Fatalf("Role() = %q, %v after the demotion; want user and no error", role, err)
	}
	if admin.Can(identity.ManageAccountsAction) {
		t.Error("the handle says it may still manage accounts after being demoted")
	}
	refused(t, admin.SetRole("alice", identity.RoleAdmin),
		identity.RoleUser, identity.ManageAccountsAction)
	if got := srv.userStore.Role("alice"); got != identity.RoleUser {
		t.Fatalf("alice is %q: the demoted handle promoted somebody", got)
	}
	refused(t, admin.AddUser("mallory", "correct horse"),
		identity.RoleUser, identity.ManageAccountsAction)
	refused(t, admin.ReloadUsers(), identity.RoleUser, identity.ManageServerAction)
}

// F07. An account that is gone is nobody. A handle to it must not keep the
// permissions of an account the server no longer has, and the error has to
// say so rather than quietly degrade to the least privileged role - a panel
// that got "user" back would render a working session for a deleted account.
func TestAHandleToARemovedAccountStopsWorking(t *testing.T) {
	srv := adminServer(t)
	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}
	if err := admin.RemoveUser("root"); err != nil {
		t.Fatalf("RemoveUser(root): %v", err)
	}

	if _, err := admin.Role(); err == nil {
		t.Error("Role succeeded for an account that was removed")
	}
	if _, err := admin.Actor(); err == nil {
		t.Error("Actor succeeded for an account that was removed")
	}
	if admin.Can(identity.ViewAccountsAction) {
		t.Error("a removed account says it may view accounts")
	}
	if err := admin.SetRole("alice", identity.RoleAdmin); err == nil {
		t.Fatal("a handle to a removed account promoted an account")
	}
	if got := srv.userStore.Role("alice"); got != identity.RoleUser {
		t.Fatalf("alice is %q: the removed admin's handle still works", got)
	}
	// The name it acts as does not change with its fate: that is what makes
	// the error reportable.
	if admin.Name() != "root" {
		t.Errorf("the handle acts as %q, want root", admin.Name())
	}
}

// F07. Disabling an account is the operator's way of saying "not this one,
// not now". It has to reach management too, or the account that may not pass
// a byte of traffic goes on running the server.
func TestADisabledAccountMayNotManageTheServer(t *testing.T) {
	srv := adminServer(t)
	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}

	// Disabled the way an operator does it: in the file, then reloaded.
	writeUsers(t, srv.cfg.UsersFile, []userstore.UserAccount{
		{ID: "1", Username: "root", Password: "x", Role: "admin", Enabled: false},
		{ID: "2", Username: "noc", Password: "x", Role: "operator", Enabled: true},
		{ID: "3", Username: "alice", Password: "x", Enabled: true},
	})
	if err := admin.ReloadUsers(); err != nil {
		t.Fatalf("ReloadUsers: %v", err)
	}

	if admin.Can(identity.ManageServerAction) {
		t.Error("a disabled account says it may manage the server")
	}
	if err := admin.AddUser("mallory", "correct horse"); err == nil {
		t.Fatal("a disabled account added an account")
	}
	if _, ok := srv.userStore.Identity("mallory"); ok {
		t.Fatal("the account a disabled admin was refused exists anyway")
	}
}

// F08. Viewing the accounts is not holding their keys. A tunnel key is what
// an account is on the wire, so a listing that carried one handed every
// operator the ability to raise a tunnel as any member - including as the
// admins - under a permission that was meant to be read-only.
func TestTheAccountListingCarriesNoTunnelKeys(t *testing.T) {
	srv := adminServer(t)
	// Every account here has a key: the file had none, so loading it issued
	// one per account. If the listing leaks, it leaks all of them.
	for _, name := range []string{"root", "noc", "alice"} {
		account, ok := srv.userStore.Identity(name)
		if !ok || len(account.Key) != userstore.TunnelKeySize {
			t.Fatalf("%q has no tunnel key to leak; this test proves nothing", name)
		}
	}

	for _, actor := range []string{"root", "noc"} {
		handle, err := srv.As(actor)
		if err != nil {
			t.Fatalf("As(%s): %v", actor, err)
		}
		accounts, err := handle.Accounts()
		if err != nil {
			t.Fatalf("Accounts as %s: %v", actor, err)
		}
		if len(accounts) != 3 {
			t.Fatalf("%s sees %d accounts, want 3", actor, len(accounts))
		}
		for _, acc := range accounts {
			if acc.HasKey() {
				t.Errorf("the listing handed %s the tunnel key of %q", actor, acc.Name)
			}
			// The listing still has to be worth reading.
			if acc.Name == "" {
				t.Error("the listing dropped the account names along with the keys")
			}
		}
	}
}

// F08. The key is still handed out - that is how a member's client is
// configured - but handing it out is managing an account, not viewing one.
func TestHandingOutATunnelKeyCostsTheAdminRole(t *testing.T) {
	srv := adminServer(t)

	operator, err := srv.As("noc")
	if err != nil {
		t.Fatalf("As(noc): %v", err)
	}
	_, err = operator.TunnelKey("root")
	refused(t, err, identity.RoleOperator, identity.ManageAccountsAction)

	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}
	key, err := admin.TunnelKey("alice")
	if err != nil {
		t.Fatalf("an admin may not read a tunnel key: %v", err)
	}
	stored, _ := srv.userStore.Identity("alice")
	if !bytes.Equal(key, stored.Key) {
		t.Fatal("TunnelKey returned something other than the account's key")
	}
	// A copy, not the directory's own slice: an SDK caller must not be able
	// to edit who a member is by writing into what it was handed.
	key[0] ^= 0xff
	again, _ := srv.userStore.Identity("alice")
	if !bytes.Equal(again.Key, stored.Key) {
		t.Fatal("writing into the returned key changed the account")
	}

	if _, err := admin.TunnelKey("nobody"); err == nil {
		t.Error("TunnelKey invented a key for an account that does not exist")
	}
}
