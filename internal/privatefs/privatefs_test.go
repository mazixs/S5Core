package privatefs

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
)

// The temporary file is private, next to the target and named by the pattern,
// and two of them never share a name.
func TestCreateTempMakesAPrivateFileInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	f, err := CreateTemp(dir, ".users-*.json.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got := filepath.Dir(f.Name()); got != dir {
		t.Errorf("created in %s, want %s", got, dir)
	}
	base := filepath.Base(f.Name())
	middle, prefixed := strings.CutPrefix(base, ".users-")
	middle, suffixed := strings.CutSuffix(middle, ".json.tmp")
	if !prefixed || !suffixed || middle == "" {
		t.Errorf("name %q does not follow the pattern", base)
	}
	if _, err := f.WriteString("secret\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(f); err != nil || string(b) != "secret\n" {
		t.Errorf("read back %q (%v)", b, err)
	}
	privatefstest.RequirePrivate(t, f.Name())

	g, err := CreateTemp(dir, ".users-*.json.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if g.Name() == f.Name() {
		t.Errorf("both files are %s", f.Name())
	}
}

// Every directory MkdirAll creates is private; one that exists is no error,
// and neither is a trailing separator; a file in the way is.
func TestMkdirAllMakesEveryDirectoryItCreatesPrivate(t *testing.T) {
	base := t.TempDir()
	leaf := filepath.Join(base, "logs", "s5", "archive")
	if err := MkdirAll(leaf); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(base, "logs"), filepath.Join(base, "logs", "s5"), leaf} {
		privatefstest.RequirePrivate(t, dir)
	}
	// A temporary file is private inside such a directory too.
	f, err := CreateTemp(leaf, "x-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	privatefstest.RequirePrivate(t, f.Name())
	sep := string(os.PathSeparator)
	for _, again := range []string{leaf, leaf + sep, leaf + sep + "."} {
		if err := MkdirAll(again); err != nil {
			t.Errorf("%s: %v", again, err)
		}
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(file, "sub")} {
		if err := MkdirAll(path); err == nil {
			t.Errorf("%s: no error with a file in the way", path)
		}
	}
}
