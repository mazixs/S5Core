//go:build !windows

package userstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
)

// An account file others may read keeps its mode while the server only reads
// it; the first rewrite makes it 0600.
func TestAnAccountFileOthersMayReadIsPrivateAfterTheFirstRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	writeKeyedUsers(t, path, 0o644)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("reading changed the mode to %v", mode)
	}
	if err := s.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, path)
}
