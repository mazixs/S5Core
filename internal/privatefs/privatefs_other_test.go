//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

// A directory that exists keeps the mode its owner gave it.
func TestMkdirAllLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Errorf("%v, want 0755", mode)
	}
}
