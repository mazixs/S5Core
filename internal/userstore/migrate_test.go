package userstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/identity"
)

// writeRawUsers writes a users file exactly as given, so that a test can put
// a pre-Ф6-3 file on disk - one with no tunnel_key and no role anywhere - and
// see what reading it does.
func writeRawUsers(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the users file: %v", err)
	}
	return path
}

func readUsers(t *testing.T, path string) []UserAccount {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back the users file: %v", err)
	}
	var uf UsersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		t.Fatalf("parse the users file: %v", err)
	}
	return uf.Users
}

const preF63File = `{"users":[
  {"id":"1","username":"alice","password_hash":"$argon2id$v=19$m=65536,t=3,p=4$YWJjZGVmZ2hpamtsbW5vcA$3Fm1J8xGx0h8ynFj3aB4fA","enabled":true},
  {"id":"2","username":"bob","password":"plaintext-from-2024","enabled":true,"traffic_limit_bytes":1024}
]}`

// The Ф6-3 gate, first half: "existing account files migrate with no manual
// intervention". Reading a file written before tunnel keys existed gives
// every account one, writes it back, and changes nothing else about the
// accounts.
func TestAPreF63FileMigratesOnLoad(t *testing.T) {
	path := writeRawUsers(t, preF63File)

	var logged bytes.Buffer
	store := NewStore(slog.New(slog.NewTextHandler(&logged, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	// The keys exist, are the right size, and differ between accounts.
	keys := map[string][]byte{}
	for _, name := range []string{"alice", "bob"} {
		id, ok := store.Identity(name)
		if !ok {
			t.Fatalf("account %q is gone after the migration", name)
		}
		if !id.HasKey() {
			t.Fatalf("account %q was not given a tunnel key", name)
		}
		if len(id.Key) != TunnelKeySize {
			t.Fatalf("account %q got a %d-byte key, want %d", name, len(id.Key), TunnelKeySize)
		}
		keys[name] = id.Key
	}
	if bytes.Equal(keys["alice"], keys["bob"]) {
		t.Fatal("two accounts were given the same key, so the key is not random")
	}

	// The file on disk carries them, or a restart would hand out new ones.
	written := readUsers(t, path)
	if len(written) != 2 {
		t.Fatalf("the file holds %d accounts after the migration, want 2", len(written))
	}
	for _, acc := range written {
		raw, err := base64.StdEncoding.DecodeString(acc.TunnelKey)
		if err != nil || len(raw) != TunnelKeySize {
			t.Fatalf("account %q was written with an unusable key %q", acc.Username, acc.TunnelKey)
		}
		if !bytes.Equal(raw, keys[acc.Username]) {
			t.Fatalf("account %q holds one key in memory and another on disk", acc.Username)
		}
	}

	// Nothing else about the accounts moved. A migration that quietly reset a
	// quota or dropped a password would be worse than one that failed.
	byName := map[string]UserAccount{}
	for _, acc := range written {
		byName[acc.Username] = acc
	}
	if h := byName["alice"].PasswordHash; !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("alice lost her password hash: %q", h)
	}
	if p := byName["bob"].Password; p != "plaintext-from-2024" {
		t.Fatalf("bob's password was changed by the migration: %q", p)
	}
	if got := byName["bob"].TrafficLimitBytes; got != 1024 {
		t.Fatalf("bob's quota is %d after the migration, want 1024", got)
	}
	// No role field anywhere in the old file, and every account in it is a
	// user.
	for _, acc := range written {
		if acc.Role != "" {
			t.Fatalf("the migration invented a role %q for %q", acc.Role, acc.Username)
		}
		if got := store.Role(acc.Username); got != identity.RoleUser {
			t.Fatalf("account %q reads as role %q, want user", acc.Username, got)
		}
	}

	// The operator is told, and the key is not in what they are told. A log
	// line is shipped, rotated and read by people who are not the account's
	// owner.
	out := logged.String()
	if !strings.Contains(out, "tunnel key") {
		t.Fatalf("the migration was silent:\n%s", out)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Fatalf("the warning does not name the accounts it changed:\n%s", out)
	}
	for name, key := range keys {
		if strings.Contains(out, base64.StdEncoding.EncodeToString(key)) {
			t.Fatalf("%q's key was written to the log", name)
		}
	}
}

// A second load must not churn the keys, or every restart would invalidate
// every client that had been given one.
func TestMigratingTwiceKeepsTheSameKeys(t *testing.T) {
	path := writeRawUsers(t, preF63File)

	first := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := first.LoadFromFile(path); err != nil {
		t.Fatalf("first load: %v", err)
	}
	before, _ := first.Identity("alice")

	var logged bytes.Buffer
	second := NewStore(slog.New(slog.NewTextHandler(&logged, nil)))
	if err := second.LoadFromFile(path); err != nil {
		t.Fatalf("second load: %v", err)
	}
	after, _ := second.Identity("alice")

	if !bytes.Equal(before.Key, after.Key) {
		t.Fatal("a second load handed alice a different key")
	}
	if strings.Contains(logged.String(), "tunnel key") {
		t.Fatalf("a file that needs no migration still warned:\n%s", logged.String())
	}
}

// A reload is a signal handler running while the operator has the file open
// in an editor. It migrates in memory so the server keeps working, and does
// not write the file back underneath them.
func TestAReloadMigratesInMemoryAndLeavesTheFileAlone(t *testing.T) {
	path := writeRawUsers(t, preF63File)
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	// Put the old file back, as an edit would, and reload.
	if err := os.WriteFile(path, []byte(preF63File), 0o600); err != nil {
		t.Fatalf("rewrite the file: %v", err)
	}
	if err := store.Reload(path); err != nil {
		t.Fatalf("reload: %v", err)
	}

	id, ok := store.Identity("alice")
	if !ok || !id.HasKey() {
		t.Fatal("the reload left alice without a key, so the server would refuse her")
	}
	for _, acc := range readUsers(t, path) {
		if acc.TunnelKey != "" {
			t.Fatalf("the reload rewrote the file: %q now has a key in it", acc.Username)
		}
	}
}

// A role that nobody defined is refused when the file is read, not resolved
// to something convenient later.
func TestAnUnknownRoleIsRefusedAtLoad(t *testing.T) {
	path := writeRawUsers(t, `{"users":[{"id":"1","username":"alice","password":"x","role":"root","enabled":true}]}`)
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	err := store.LoadFromFile(path)
	if err == nil {
		t.Fatal("a file with role \"root\" loaded")
	}
	if !strings.Contains(err.Error(), "role") {
		t.Fatalf("the refusal does not mention the role: %v", err)
	}
}

func TestRolesSurviveALoad(t *testing.T) {
	path := writeRawUsers(t, `{"users":[
      {"id":"1","username":"alice","password":"x","role":"admin","enabled":true},
      {"id":"2","username":"bob","password":"x","role":"operator","enabled":true},
      {"id":"3","username":"carol","password":"x","enabled":true}
    ]}`)
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	want := map[string]identity.Role{
		"alice": identity.RoleAdmin,
		"bob":   identity.RoleOperator,
		"carol": identity.RoleUser,
		// An account that does not exist is the least privileged answer, so
		// that a missing name can never be a way to gain a permission.
		"nobody": identity.RoleUser,
	}
	for name, role := range want {
		if got := store.Role(name); got != role {
			t.Errorf("%q has role %q, want %q", name, got, role)
		}
	}
	if _, ok := store.Identity("nobody"); ok {
		t.Error("an account that does not exist resolved to an identity")
	}
}

func TestSetRole(t *testing.T) {
	path := writeRawUsers(t, `{"users":[{"id":"1","username":"alice","password_hash":"`+wellFormedHash+`","enabled":true}]}`)
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	before, _ := store.Identity("alice")

	if err := store.SetRole("alice", identity.RoleAdmin); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if got := store.Role("alice"); got != identity.RoleAdmin {
		t.Fatalf("alice is %q after being made an admin", got)
	}
	// A role is orthogonal to the key and the password: promoting an account
	// must not re-key it or lock it out.
	after, _ := store.Identity("alice")
	if !bytes.Equal(before.Key, after.Key) {
		t.Fatal("changing the role changed the tunnel key")
	}
	if acc, _ := store.Lookup("alice"); acc.PasswordHash != wellFormedHash {
		t.Fatalf("changing the role touched the password hash: %q", acc.PasswordHash)
	}

	if err := store.SetRole("alice", identity.Role("root")); err == nil {
		t.Fatal("alice was given a role that does not exist")
	}
	if got := store.Role("alice"); got != identity.RoleAdmin {
		t.Fatalf("a refused SetRole still changed the role to %q", got)
	}
	if err := store.SetRole("nobody", identity.RoleAdmin); err == nil {
		t.Fatal("a role was set on an account that does not exist")
	}
}

// Identities is what a control panel lists. It must show the quota as spent
// as it actually is, not as of the last flush, or an account at its limit
// looks like it has room.
func TestIdentitiesIncludeTrafficThatHasNotBeenFlushed(t *testing.T) {
	path := writeRawUsers(t, `{"users":[{"id":"1","username":"alice","password":"x","enabled":true,
      "traffic_limit_bytes":1000,"traffic_used_bytes":100}]}`)
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	store.AddTraffic("alice", 250)

	ids := store.Identities()
	if len(ids) != 1 {
		t.Fatalf("Identities returned %d accounts, want 1", len(ids))
	}
	if got := ids[0].Policy.TrafficUsedBytes; got != 350 {
		t.Fatalf("the panel would show %d bytes spent, want 350", got)
	}
	if got := ids[0].Policy.TrafficLimitBytes; got != 1000 {
		t.Fatalf("the quota reads as %d, want 1000", got)
	}
	if !ids[0].Policy.Enabled {
		t.Fatal("an enabled account reads as disabled")
	}
}

// A store with no file is the PROXY_USER deployment. It is the same store, so
// it migrates the same way - an account added through AddUser gets a key.
func TestAnAccountAddedAtRuntimeGetsNoKeyButStillResolves(t *testing.T) {
	store := NewStore(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := store.AddUser("alice", "correct horse"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	id, ok := store.Identity("alice")
	if !ok {
		t.Fatal("an account added at runtime does not resolve to an identity")
	}
	if id.Role != identity.RoleUser {
		t.Fatalf("a new account is role %q, want user", id.Role)
	}
	if !store.IsValid("alice", "correct horse") {
		t.Fatal("an account added at runtime cannot authenticate")
	}
	if store.IsValid("alice", "wrong") {
		t.Fatal("the wrong password authenticated")
	}
	// The password is hashed, not held. That is the Ф6-3 point of having one
	// mechanism: the file-less deployment gets Argon2id too.
	acc, _ := store.Lookup("alice")
	if acc.Password != "" {
		t.Fatalf("the password was stored in the clear: %q", acc.Password)
	}
	if !strings.HasPrefix(acc.PasswordHash, "$argon2id$") {
		t.Fatalf("the password was not hashed with Argon2id: %q", acc.PasswordHash)
	}
}
