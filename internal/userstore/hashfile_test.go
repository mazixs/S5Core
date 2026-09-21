package userstore

import (
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// The account file is edited by hand and written by migrations from other
// tools, so a hash in it is input. Argon2id answers some malformed input with
// a panic rather than an error (audit finding F15), and the store used to
// carry such a string all the way to the login that triggered it - by which
// time the operator who mistyped it is long gone and the process dies on
// someone else's connection.
//
// A hash nobody can check is therefore refused where the file is read: at the
// start, and at the reload that introduced it.

// brokenHashes are strings that used to load fine and blow up later. Each is
// a plausible mistake, not a crafted attack: the whole reason this is checked
// at load time is that the file is written by people and by other tools.
var brokenHashes = map[string]string{
	"no rounds":            "$argon2id$v=19$m=65536,t=0,p=1$" + goodTestSalt + "$" + goodTestTag,
	"no parallelism":       "$argon2id$v=19$m=65536,t=3,p=0$" + goodTestSalt + "$" + goodTestTag,
	"an empty tag":         "$argon2id$v=19$m=65536,t=3,p=1$" + goodTestSalt + "$",
	"a truncated string":   "$argon2id$v=19$m=65536,t=3,p=1",
	"a negative parameter": "$argon2id$v=19$m=-1,t=3,p=1$" + goodTestSalt + "$" + goodTestTag,
	"a copy-paste tail":    "$argon2id$v=19$m=65536,t=3,p=1$" + goodTestSalt + "$" + goodTestTag + " ",
}

const (
	goodTestSalt = "AAAAAAAAAAAAAAAAAAAAAA"
	goodTestTag  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// wellFormedHash is a PHC string of the right shape whose password nobody
	// knows. Tests that need a hash to survive an operation, without logging
	// in, use it: a placeholder has to be well formed now that the store
	// refuses to load one it could not check.
	wellFormedHash = "$argon2id$v=19$m=65536,t=3,p=1$" + goodTestSalt + "$" + goodTestTag
)

func TestAnAccountFileWithAHashNobodyCanCheckIsRefused(t *testing.T) {
	for name, hash := range brokenHashes {
		t.Run(name, func(t *testing.T) {
			path := createTestFile(t, []UserAccount{{
				ID:           "u-001",
				Username:     "alice",
				PasswordHash: hash,
				Enabled:      true,
			}})

			s := NewStore(nil)
			err := s.LoadFromFile(path)
			if err == nil {
				t.Fatalf("the store loaded a hash it cannot check: %q", hash)
			}
			if !strings.Contains(err.Error(), "alice") {
				t.Errorf("the refusal does not name the account: %v", err)
			}
			if got := s.UserCount(); got != 0 {
				t.Errorf("%d accounts were kept from a file that was refused", got)
			}
		})
	}
}

// A reload is a signal handler acting on a file the operator has just saved.
// If that file cannot be read, the accounts already serving traffic have to
// stay exactly as they were - the running server is the last good copy.
func TestAReloadWithABrokenHashKeepsTheAccountsItHad(t *testing.T) {
	hash, err := passwordhash.Hash("secret-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	good := []UserAccount{{
		ID:           "u-001",
		Username:     "alice",
		PasswordHash: hash,
		Enabled:      true,
	}}

	s := NewStore(nil)
	if err := s.LoadFromFile(createTestFile(t, good)); err != nil {
		t.Fatalf("load: %v", err)
	}

	broken := []UserAccount{{
		ID:           "u-001",
		Username:     "alice",
		PasswordHash: brokenHashes["no rounds"],
		Enabled:      true,
	}}
	if err := s.Reload(createTestFile(t, broken)); err == nil {
		t.Fatal("the reload accepted a hash nobody can check")
	}

	if !s.IsValid("alice", "secret-password") {
		t.Fatal("a refused reload took the account with it")
	}
	if s.IsValid("alice", "wrong-password") {
		t.Fatal("a refused reload left the account accepting anything")
	}
}

// The opposite mistake would be just as bad: hashes written by earlier builds
// of this server use the URL-safe base64 alphabet, and a file full of them
// must still load. The check at the door has to be the same check Verify
// does, not a stricter one.
func TestAFileOfHashesFromEarlierBuildsStillLoads(t *testing.T) {
	hash, err := passwordhash.Hash("secret-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	legacy := strings.NewReplacer("+", "-", "/", "_").Replace(hash)

	path := createTestFile(t, []UserAccount{{
		ID:           "u-001",
		Username:     "alice",
		PasswordHash: legacy,
		Enabled:      true,
	}})

	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatalf("a hash an earlier build wrote was refused: %v", err)
	}
	if !s.IsValid("alice", "secret-password") {
		t.Fatal("the account cannot log in with the password that made its hash")
	}
}
