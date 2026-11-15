//go:build !windows

package s5server

import (
	"os"
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
		t.Errorf("the journal is %v, want 0600", mode)
	}
}
