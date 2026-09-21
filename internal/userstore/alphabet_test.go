package userstore

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// Audit finding P3-1. A hash written by an earlier build is spelled in the
// URL-safe base64 alphabet, which no other Argon2id implementation reads.
// Reading the account file rewrites it in the standard alphabet - the same
// bytes, the same password - and writes the file back, so the file becomes
// portable without anyone touching a password.

// legacySpelling turns a PHC string into the spelling earlier builds wrote.
func legacySpelling(t *testing.T, hash string) string {
	t.Helper()
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("not a PHC string: %s", hash)
	}
	for _, i := range [...]int{4, 5} {
		raw, err := base64.RawStdEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatalf("decode field %d: %v", i, err)
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return strings.Join(parts, "$")
}

// legacyAccountFile writes a file whose single account carries a hash in the
// old alphabet, and returns the path and the password that hash was made from.
func legacyAccountFile(t *testing.T) (string, string) {
	t.Helper()
	const password = "the password nobody is changing"

	// Draw until the spelling actually differs, otherwise the test would pass
	// without the migration doing anything.
	var old string
	for i := 0; i < 64 && old == ""; i++ {
		hash, err := passwordhash.Hash(password)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if spelled := legacySpelling(t, hash); strings.ContainsAny(spelled, "-_") {
			old = spelled
		}
	}
	if old == "" {
		t.Fatal("64 draws produced no hash with a URL-only character")
	}

	users := []UserAccount{{
		ID:           "1",
		Username:     "alice",
		PasswordHash: old,
		TunnelKey:    base64.StdEncoding.EncodeToString(make([]byte, TunnelKeySize)),
		Enabled:      true,
	}}
	return createTestFile(t, users), password
}

func TestLoadingRespellsHashesAndKeepsThePassword(t *testing.T) {
	path, password := legacyAccountFile(t)

	store := NewStore(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	// The account still authenticates with the password it always had.
	if !store.IsValid("alice", password) {
		t.Fatal("the account stopped authenticating after the respelling")
	}
	if store.IsValid("alice", "not the password") {
		t.Fatal("the wrong password was accepted")
	}

	// And the file on disk is now portable.
	back := readUsers(t, path)
	if len(back) != 1 {
		t.Fatalf("the file has %d accounts, want 1", len(back))
	}
	if strings.ContainsAny(back[0].PasswordHash, "-_") {
		t.Fatalf("the stored hash is still in the URL alphabet: %s", back[0].PasswordHash)
	}
	for _, field := range strings.Split(back[0].PasswordHash, "$")[4:] {
		if _, err := base64.RawStdEncoding.DecodeString(field); err != nil {
			t.Fatalf("field %q does not decode in the standard alphabet: %v", field, err)
		}
	}
}

// A second load must not rewrite anything: the migration is done, and a store
// that kept rewriting its file on every start would be writing for nothing.
func TestASecondLoadLeavesTheFileAlone(t *testing.T) {
	path, _ := legacyAccountFile(t)

	store := NewStore(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := store.LoadFromFile(path); err != nil {
		t.Fatalf("first load: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the file back: %v", err)
	}

	second := NewStore(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := second.LoadFromFile(path); err != nil {
		t.Fatalf("second load: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the file back: %v", err)
	}
	if string(first) != string(after) {
		t.Fatal("the second load rewrote a file that was already standard")
	}
}

// A reload respells in memory like a load does, but leaves the file to the
// operator - the same rule the tunnel-key migration follows.
func TestAReloadRespellsInMemoryOnly(t *testing.T) {
	path, password := legacyAccountFile(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the file: %v", err)
	}

	store := NewStore(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := store.Reload(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !store.IsValid("alice", password) {
		t.Fatal("the account stopped authenticating after a reload")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the file back: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("a reload rewrote the users file")
	}

	var uf UsersFile
	if err := json.Unmarshal(after, &uf); err != nil {
		t.Fatalf("parse the users file: %v", err)
	}
	if !strings.ContainsAny(uf.Users[0].PasswordHash, "-_") {
		t.Fatal("the file lost its old spelling, so the reload did write it")
	}
}
