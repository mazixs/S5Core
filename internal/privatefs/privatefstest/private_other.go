//go:build !windows

package privatefstest

import (
	"os"
	"path/filepath"
	"testing"
)

// RequirePrivate fails the test unless only the owner may reach path: a file
// is 0600, a directory 0700.
func RequirePrivate(t testing.TB, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if info.IsDir() {
		want = 0o700
	}
	if mode := info.Mode().Perm(); mode != want {
		t.Errorf("%s is %v, want %v", filepath.Base(path), mode, want)
	}
}
