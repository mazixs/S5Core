package userstore

import (
	"os"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// A plaintext password in USERS_FILE is migrated to Argon2id on the first
// login that uses it. The hashing is the expensive part, so the store is
// unlocked while it runs - 110 ms with the lock held would stall every other
// connection. The account can therefore change under the migration, and the
// only place that can notice is the write itself.
//
// The dangerous change is the ordinary one: an operator edits USERS_FILE and
// sends SIGHUP. Reload reuses the same *userEntry so that in-flight traffic
// keeps counting, which is exactly why a stale pointer used to land silently.

// plaintextAccount is the shape of an account that has not been migrated yet.
func plaintextAccount(username, password string) UserAccount {
	return UserAccount{
		ID:       "u-" + username,
		Username: username,
		Password: password,
		Enabled:  true,
	}
}

// fileMTime is how a test sees whether the file was written at all. A
// migration that lost its race has nothing to persist, and the file it would
// have written is the one the operator has just saved.
func fileMTime(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.ModTime()
}

// kdfWindow measures one Argon2id run on this machine, so a test can act
// inside the window instead of guessing how wide it is.
func kdfWindow(t *testing.T) time.Duration {
	t.Helper()
	start := time.Now()
	if _, err := passwordhash.Hash("measuring what a run costs here"); err != nil {
		t.Fatalf("hash: %v", err)
	}
	return time.Since(start)
}

// The commit is the decision, so it is tested as one: each case is a way the
// store can differ from what the migration left it as.
func TestAMigratedHashIsOnlyStoredForTheAccountItWasMadeFor(t *testing.T) {
	const password = "old-password"
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	cases := []struct {
		name string
		// change is what happened to the store while the KDF ran.
		change     func(t *testing.T, s *Store, entry *userEntry)
		wantStored bool
	}{
		{
			name:       "nothing changed",
			change:     func(*testing.T, *Store, *userEntry) {},
			wantStored: true,
		},
		{
			name: "the account was removed",
			change: func(_ *testing.T, s *Store, _ *userEntry) {
				delete(s.users, "alice")
			},
		},
		{
			name: "a different account answers to the name",
			change: func(_ *testing.T, s *Store, _ *userEntry) {
				s.users["alice"] = &userEntry{account: plaintextAccount("alice", password)}
			},
		},
		{
			name: "the account already has a hash",
			change: func(_ *testing.T, s *Store, entry *userEntry) {
				entry.account.PasswordHash = wellFormedHash
			},
		},
		{
			name: "the operator changed the password",
			change: func(_ *testing.T, s *Store, entry *userEntry) {
				entry.account.Password = "new-password"
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewStore(nil)
			if err := s.LoadFromFile(createTestFile(t, []UserAccount{plaintextAccount("alice", password)})); err != nil {
				t.Fatalf("load: %v", err)
			}
			entry := s.users["alice"]

			c.change(t, s, entry)

			_, stored := s.commitMigratedHash("alice", password, hash, entry)
			if stored != c.wantStored {
				t.Fatalf("commitMigratedHash stored=%v, want %v", stored, c.wantStored)
			}

			acc, present := s.Lookup("alice")
			switch {
			case c.wantStored:
				if acc.PasswordHash != hash {
					t.Errorf("the hash was not stored: %q", acc.PasswordHash)
				}
				if acc.Password != "" {
					t.Errorf("the plaintext was left behind: %q", acc.Password)
				}
			case present && acc.PasswordHash == hash:
				t.Error("a hash made for a state the store has left was written anyway")
			}
		})
	}
}

// The whole point, end to end: the operator's edit wins over a migration that
// was already running when they made it.
func TestAReloadDuringTheMigrationKeepsTheOperatorsPassword(t *testing.T) {
	window := kdfWindow(t)

	s := NewStore(nil)
	if err := s.LoadFromFile(createTestFile(t, []UserAccount{plaintextAccount("alice", "old-password")})); err != nil {
		t.Fatalf("load: %v", err)
	}

	migrated := make(chan struct{})
	go func() {
		defer close(migrated)
		s.MigratePassword("alice", "old-password")
	}()

	// Land inside the window rather than at the edge of it.
	time.Sleep(window / 4)
	select {
	case <-migrated:
		t.Fatalf("the migration finished in under %s; the window this test needs to act in was not open", window/4)
	default:
	}

	edited := createTestFile(t, []UserAccount{plaintextAccount("alice", "new-password")})
	if err := s.Reload(edited); err != nil {
		t.Fatalf("reload: %v", err)
	}
	saved := fileMTime(t, edited)
	<-migrated

	acc, ok := s.Lookup("alice")
	if !ok {
		t.Fatal("alice is gone from the store")
	}
	if acc.PasswordHash != "" {
		t.Fatalf("the migration wrote a hash of the old password over the edit: %q", acc.PasswordHash)
	}
	if acc.Password != "new-password" {
		t.Fatalf("the store holds %q, want the password the operator just set", acc.Password)
	}
	if !s.IsValid("alice", "new-password") {
		t.Fatal("the password the operator set does not work")
	}
	if s.IsValid("alice", "old-password") {
		t.Fatal("the password the operator replaced still works")
	}

	// The file the operator saved must be the file that is still there: a
	// migration that lost the race has nothing to persist.
	if users := readUsers(t, edited); len(users) != 1 || users[0].Password != "new-password" || users[0].PasswordHash != "" {
		t.Fatalf("the file was rewritten from the losing migration: %+v", users)
	}
	if now := fileMTime(t, edited); !now.Equal(saved) {
		t.Fatalf("the file was written again at %s, having been saved at %s", now, saved)
	}
}

// A migration whose account disappeared writes nothing, and the account that
// comes back later migrates from what the file says then.
func TestAMigrationDoesNotFollowAnAccountThatWasRemoved(t *testing.T) {
	window := kdfWindow(t)

	s := NewStore(nil)
	if err := s.LoadFromFile(createTestFile(t, []UserAccount{
		plaintextAccount("alice", "old-password"),
		plaintextAccount("bob", "bobs-password"),
	})); err != nil {
		t.Fatalf("load: %v", err)
	}

	migrated := make(chan struct{})
	go func() {
		defer close(migrated)
		s.MigratePassword("alice", "old-password")
	}()
	time.Sleep(window / 4)

	withoutAlice := createTestFile(t, []UserAccount{plaintextAccount("bob", "bobs-password")})
	if err := s.Reload(withoutAlice); err != nil {
		t.Fatalf("reload: %v", err)
	}
	saved := fileMTime(t, withoutAlice)
	<-migrated

	if _, ok := s.Lookup("alice"); ok {
		t.Fatal("the migration put back an account the operator removed")
	}
	if users := readUsers(t, withoutAlice); len(users) != 1 || users[0].Username != "bob" {
		t.Fatalf("the file grew an account the operator had removed: %+v", users)
	}
	// Saving here would rewrite, from a signal handler, the file Reload
	// deliberately left alone - for a migration that has been dropped.
	if now := fileMTime(t, withoutAlice); !now.Equal(saved) {
		t.Fatalf("the file was written again at %s, having been saved at %s", now, saved)
	}

	// The account comes back, and the login after that migrates it properly.
	back := createTestFile(t, []UserAccount{plaintextAccount("alice", "third-password")})
	if err := s.Reload(back); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !NewCredentialAdapter(s).Valid("alice", "third-password") {
		t.Fatal("alice cannot log in after coming back")
	}
	acc, _ := s.Lookup("alice")
	if acc.PasswordHash == "" {
		t.Fatal("the login after the account came back did not migrate it")
	}
	if acc.Password != "" {
		t.Fatalf("the plaintext survived the migration: %q", acc.Password)
	}
}
