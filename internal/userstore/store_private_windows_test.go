package userstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
)

// An account file an older version left with the access of its directory,
// here read access for every local user, keeps it while the server only reads
// the file, as on POSIX; the first rewrite makes it private.
func TestAnAccountFileWithABroadACLIsPrivateAfterTheFirstRewrite(t *testing.T) {
	dir := t.TempDir()
	privatefstest.SetDACL(t, dir, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)")
	path := filepath.Join(dir, "users.json")
	writeKeyedUsers(t, path, 0o600)
	before := privatefstest.DACL(t, path)
	if !strings.Contains(before, ";;;BU)") {
		t.Fatalf("the file does not inherit the directory: %s", before)
	}
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(path); err != nil {
		t.Fatal(err)
	}
	if after := privatefstest.DACL(t, path); after != before {
		t.Errorf("reading changed the access: %s, was %s", after, before)
	}
	if err := s.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, path)
	if err := s.Reload(path); err != nil || !s.IsValid("alice", "pass1") {
		t.Errorf("the rewritten file does not read back: %v", err)
	}
}
