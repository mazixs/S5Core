package userstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

// What a password costs on the connection path once the verifier cache has
// warmed up. This is the number the roster of plan task Ф5-5 competes with -
// not the 100 ms of a cold Argon2id, which task Ф3-6 already took off this
// path (docs/benchmarks/argon2-cost.md).
func BenchmarkValidCachedPassword(b *testing.B) {
	const username, password = "alice", "secret-password"
	hash, err := passwordhash.Hash(password)
	if err != nil {
		b.Fatal(err)
	}
	data, err := json.Marshal(UsersFile{Users: []UserAccount{{
		ID:           "u-001",
		Username:     username,
		PasswordHash: hash,
		Enabled:      true,
	}}})
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		b.Fatal(err)
	}
	if !s.IsValid(username, password) {
		b.Fatal("the account does not accept its own password")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !s.IsValid(username, password) {
			b.Fatal("rejected")
		}
	}
}
