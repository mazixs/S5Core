//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"testing"
)

// requirePrivate fails the test unless only the owner may read or write path.
func requirePrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s is %v, want 0600", filepath.Base(path), mode)
	}
}
