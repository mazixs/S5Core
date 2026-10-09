package s5server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/identity"
	"github.com/mazixs/S5Core/internal/userstore"
)

func TestAnExistingAdminHandleExpiresAndSnapshotsCannotExtendIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := adminServer(t)
		root, _ := srv.userStore.Lookup("root")
		until := time.Now().Add(2 * time.Second)
		from := time.Now().Add(-time.Second)
		root.ValidFrom, root.ValidUntil = &from, &until
		body, err := json.Marshal(userstore.UsersFile{Users: []userstore.UserAccount{root}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(srv.cfg.UsersFile, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := srv.ReloadUsers(); err != nil {
			t.Fatal(err)
		}
		admin, err := srv.As("root")
		if err != nil {
			t.Fatal(err)
		}
		actor, err := admin.Actor()
		if err != nil {
			t.Fatal(err)
		}
		accounts, err := admin.Accounts()
		if err != nil {
			t.Fatal(err)
		}
		*actor.Policy.ValidUntil = until.Add(time.Hour)
		*accounts[0].Policy.ValidUntil = until.Add(time.Hour)
		*accounts[0].Policy.ValidFrom = until.Add(time.Hour)
		time.Sleep(3 * time.Second)
		if admin.Can(ManageAccountsAction) {
			t.Fatal("expired handle kept permissions")
		}
		for _, action := range []func() error{
			func() error { _, err := admin.Actor(); return err },
			func() error { _, err := admin.Accounts(); return err },
			func() error { return admin.AddUser("late", "p") },
			func() error { return admin.RemoveUser("root") },
			func() error { return admin.SetRole("root", RoleUser) },
			func() error { return admin.UpdateWhitelist(nil) },
			admin.ReloadUsers,
		} {
			if err := action(); err == nil {
				t.Fatal("expired handle executed an operation")
			}
		}
	})
}

func TestAdminOperationsEnforceTheCurrentValidityWindow(t *testing.T) {
	for _, state := range []string{"expired", "not yet active"} {
		t.Run(state, func(t *testing.T) {
			boundary := time.Now().Add(-time.Hour)
			root := userstore.UserAccount{ID: "1", Username: "root", Password: "x", Role: "admin", Enabled: true}
			if state == "expired" {
				root.ValidUntil = &boundary
			} else {
				boundary = time.Now().Add(time.Hour)
				root.ValidFrom = &boundary
			}
			path := filepath.Join(t.TempDir(), "users.json")
			body, err := json.Marshal(userstore.UsersFile{Users: []userstore.UserAccount{root, {ID: "2", Username: "alice", Password: "x", Enabled: true}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := DefaultConfig()
			cfg.RequireAuth, cfg.UsersFile = true, path
			srv, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			admin, err := srv.As("root")
			if err != nil {
				t.Fatal(err)
			}
			if err := admin.SetRole("alice", RoleAdmin); err == nil {
				t.Error("inactive admin changed a role")
			}
			if _, err := admin.Actor(); err == nil {
				t.Error("inactive admin has an actor")
			}
			if _, err := admin.Role(); err == nil {
				t.Error("inactive admin has a role")
			}
			if _, err := admin.Accounts(); err == nil {
				t.Error("inactive admin listed accounts")
			}
			if admin.Can(ManageServerAction) {
				t.Error("inactive admin may manage the server")
			}
			if err := admin.UpdateWhitelist([]string{"127.0.0.1"}); err == nil {
				t.Error("inactive admin changed the whitelist")
			}
			if err := admin.ReloadUsers(); err == nil {
				t.Error("inactive admin reloaded accounts")
			}
			if srv.userStore.Role("alice") != RoleUser {
				t.Error("alice gained administrative permissions")
			}
		})
	}
}

// adminServer builds a server - not started, because none of this touches the
// network - whose account file holds one account per role.
func adminServer(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	body, err := json.Marshal(userstore.UsersFile{Users: []userstore.UserAccount{
		{ID: "1", Username: "root", Password: "x", Role: "admin", Enabled: true},
		{ID: "2", Username: "noc", Password: "x", Role: "operator", Enabled: true},
		{ID: "3", Username: "alice", Password: "x", Enabled: true},
	}})
	if err != nil {
		t.Fatalf("marshal the users file: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write the users file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.RequireAuth = true
	cfg.UsersFile = path
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func refused(t *testing.T, err error, role identity.Role, action identity.Action) {
	t.Helper()
	var e *identity.ErrNotAllowed
	if !errors.As(err, &e) {
		t.Fatalf("got %v (%T), want an *identity.ErrNotAllowed", err, err)
	}
	if e.Role != role || e.Action != action {
		t.Fatalf("refused role %q action %s, want %q / %s", e.Role, e.Action, role, action)
	}
}

// Plan task Ф6-3: management used to be available to anyone holding a
// *Server. Acting on behalf of an account now goes through As, and what that
// account may do is its role's business.
func TestWhatEachRoleMayDoThroughTheSDK(t *testing.T) {
	srv := adminServer(t)

	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}
	operator, err := srv.As("noc")
	if err != nil {
		t.Fatalf("As(noc): %v", err)
	}
	user, err := srv.As("alice")
	if err != nil {
		t.Fatalf("As(alice): %v", err)
	}

	// A user may do nothing but pass traffic.
	refused(t, user.AddUser("mallory", "x"), identity.RoleUser, identity.ManageAccountsAction)
	refused(t, user.RemoveUser("root"), identity.RoleUser, identity.ManageAccountsAction)
	refused(t, user.SetRole("alice", identity.RoleAdmin), identity.RoleUser, identity.ManageAccountsAction)
	refused(t, user.UpdateWhitelist([]string{"10.0.0.1"}), identity.RoleUser, identity.ManageServerAction)
	refused(t, user.ReloadUsers(), identity.RoleUser, identity.ManageServerAction)
	if _, err := user.Accounts(); err == nil {
		t.Fatal("a user listed the accounts")
	} else {
		refused(t, err, identity.RoleUser, identity.ViewAccountsAction)
	}

	// An operator runs the server but does not hand out accounts - which is
	// also what stops one from promoting itself.
	refused(t, operator.AddUser("mallory", "x"), identity.RoleOperator, identity.ManageAccountsAction)
	refused(t, operator.SetRole("noc", identity.RoleAdmin), identity.RoleOperator, identity.ManageAccountsAction)
	if err := operator.UpdateWhitelist([]string{"10.0.0.1"}); err != nil {
		t.Fatalf("an operator may not change the whitelist: %v", err)
	}
	if err := operator.ReloadUsers(); err != nil {
		t.Fatalf("an operator may not reload the accounts: %v", err)
	}
	accounts, err := operator.Accounts()
	if err != nil {
		t.Fatalf("an operator may not list the accounts: %v", err)
	}
	if len(accounts) != 3 {
		t.Fatalf("the account list holds %d entries, want 3", len(accounts))
	}

	// An admin may do all of it.
	if err := admin.AddUser("mallory", "correct horse"); err != nil {
		t.Fatalf("an admin may not add an account: %v", err)
	}
	if err := admin.SetRole("mallory", identity.RoleOperator); err != nil {
		t.Fatalf("an admin may not set a role: %v", err)
	}
	if got := srv.userStore.Role("mallory"); got != identity.RoleOperator {
		t.Fatalf("mallory is %q after being promoted", got)
	}
	if err := admin.RemoveUser("mallory"); err != nil {
		t.Fatalf("an admin may not remove an account: %v", err)
	}
	if _, ok := srv.userStore.Identity("mallory"); ok {
		t.Fatal("the account survived being removed")
	}
}

func TestCanAnswersWithoutDoing(t *testing.T) {
	srv := adminServer(t)
	operator, err := srv.As("noc")
	if err != nil {
		t.Fatalf("As(noc): %v", err)
	}
	role, err := operator.Role()
	if err != nil {
		t.Fatalf("Role: %v", err)
	}
	if role != identity.RoleOperator {
		t.Fatalf("Role() = %q, want operator", role)
	}
	if !operator.Can(identity.ViewAccountsAction) {
		t.Error("an operator says it may not view accounts")
	}
	if operator.Can(identity.ManageAccountsAction) {
		t.Error("an operator says it may manage accounts")
	}
	// Nothing happened: the account it was told it could not create is still
	// absent.
	if _, ok := srv.userStore.Identity("mallory"); ok {
		t.Fatal("Can created an account")
	}
}

// A handle is bound to an account that exists. A name that is not one must
// not become a set of permissions - not even the empty one, because the
// caller would then be holding a handle it could show as proof of something.
func TestAsRefusesANameThatIsNotAnAccount(t *testing.T) {
	srv := adminServer(t)
	if _, err := srv.As("nobody"); err == nil {
		t.Fatal("As succeeded for an account that does not exist")
	}

	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.RequireAuth = false
	open, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if _, err := open.As("anyone"); err == nil {
		t.Fatal("As succeeded on a server with no authentication")
	}
}

// The key is what the tunnel trusts, so neither the handle a panel holds nor
// the listing it renders carries one. Handing a key out is a separate call
// with a separate permission.
func TestTheActorDoesNotCarryItsKey(t *testing.T) {
	srv := adminServer(t)
	admin, err := srv.As("root")
	if err != nil {
		t.Fatalf("As(root): %v", err)
	}
	actor, err := admin.Actor()
	if err != nil {
		t.Fatalf("Actor: %v", err)
	}
	if actor.HasKey() {
		t.Fatal("the actor handed out its own tunnel key")
	}
	if actor.Name != "root" {
		t.Fatalf("the actor is named %q, want root", actor.Name)
	}
}

// The second half of the Ф6-3 gate: two parallel mechanisms reduced to one.
// Without USERS_FILE there used to be a plain map of passwords with no
// quotas, no expiry and no Argon2id. There is now one store either way.
func TestADeploymentWithoutAFileUsesTheSameStore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.RequireAuth = true
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.userStore == nil {
		t.Fatal("a server with no users file has no user store, so the two mechanisms are still two")
	}
	if err := srv.AddUser("alice", "correct horse"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if !srv.userStore.IsValid("alice", "correct horse") {
		t.Fatal("the account cannot authenticate")
	}
	if srv.userStore.IsValid("alice", "wrong") {
		t.Fatal("the wrong password authenticated")
	}
	acc, _ := srv.userStore.Lookup("alice")
	if acc.Password != "" || acc.PasswordHash == "" {
		t.Fatalf("the file-less deployment stored the password in the clear: %+v", acc)
	}

	// The role machinery works there too, and a reload does not, because
	// there is no file to reload from.
	admin, err := srv.As("alice")
	if err != nil {
		t.Fatalf("As(alice): %v", err)
	}
	refused(t, admin.AddUser("bob", "x"), identity.RoleUser, identity.ManageAccountsAction)
	if err := srv.ReloadUsers(); err == nil {
		t.Fatal("a server with no users file reloaded one")
	}
}
