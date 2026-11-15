//go:build unix

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDirTakesOnlyADirectoryOfTheUserAlone(t *testing.T) {
	base := t.TempDir()
	private := filepath.Join(base, "private")
	if err := MkdirAll(private); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(private); err != nil {
		t.Fatalf("a directory MkdirAll made: %v", err)
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o701, 0o710} {
		dir := filepath.Join(base, mode.String())
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckDir(dir); err == nil {
			t.Errorf("%v passed", mode)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, file, filepath.Join(base, "missing")} {
		if err := CheckDir(path); err == nil {
			t.Errorf("%s passed", filepath.Base(path))
		}
	}
}

// A directory of another user is refused even at 0700: a test cannot make
// one without root, so it asks with another effective uid.
func TestCheckDirRefusesADirectoryOfAnotherUser(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "own")
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	euid := os.Geteuid()
	if err := checkDir(info, euid); err != nil {
		t.Fatalf("own directory: %v", err)
	}
	if err := checkDir(info, euid+1); err == nil {
		t.Fatal("a directory of uid", euid, "passed for uid", euid+1)
	}
}
