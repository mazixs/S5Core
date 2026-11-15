package userstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
)

// writeKeyedUsers writes an account file that needs no migration, so that
// reading it writes nothing back.
func writeKeyedUsers(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	data, err := json.MarshalIndent(UsersFile{Users: []UserAccount{{
		ID:        "u-001",
		Username:  "alice",
		Password:  "pass1",
		TunnelKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, TunnelKeySize)),
		Enabled:   true,
	}}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
}

// A rewritten account file is private, and no temporary file stays next to
// it, after a rewrite or after one that failed.
func TestARewrittenAccountFileIsPrivate(t *testing.T) {
	path := createTestFile(t, testUsers())
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	s.AddTraffic("alice", 10)
	s.FlushTraffic()
	if err := s.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, path)
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("left next to the file: %v", entries)
	}

	// The rename fails over a directory, after the temporary file is written.
	blocked := filepath.Join(t.TempDir(), "users.json")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveToFile(blocked); err == nil {
		t.Fatal("saved over a directory")
	}
	if entries, _ := os.ReadDir(filepath.Dir(blocked)); len(entries) != 1 {
		t.Errorf("left after the failure: %v", entries)
	}
}
