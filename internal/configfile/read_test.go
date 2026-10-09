package configfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRegularFileBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	want := bytes.Repeat([]byte{'x'}, 32)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(path, 32); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("boundary length=%d error=%v", len(got), err)
	}
	if _, err := Read(path, 31); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := Read(t.TempDir(), 100); err == nil {
		t.Fatal("directory accepted")
	}
}
