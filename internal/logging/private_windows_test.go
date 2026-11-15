package logging

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
	"golang.org/x/sys/windows"
)

// broadDir is a directory whose files inherit read access for every local
// user, as a file an older version wrote there did.
func broadDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	privatefstest.SetDACL(t, dir, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)")
	return dir
}

// A file an older version left with the directory's access is made private
// when the journal opens it, when it rotates and when RotateOnOpen moves it to
// the archive; the directory keeps its own access.
func TestALogLeftWithInheritedAccessIsMadePrivate(t *testing.T) {
	for name, opts := range map[string]FileOptions{
		"append":                {},
		"append and compress":   {Compress: true},
		"rotate on open":        {RotateOnOpen: true},
		"rotate on open and gz": {RotateOnOpen: true, Compress: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := broadDir(t)
			before := privatefstest.DACL(t, dir)
			opts.Path = filepath.Join(dir, "sessions.jsonl")
			if err := os.WriteFile(opts.Path, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if sd, err := windows.GetNamedSecurityInfo(opts.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); err != nil {
				t.Fatal(err)
			} else if control, _, _ := sd.Control(); control&windows.SE_DACL_PROTECTED != 0 {
				t.Fatal("the old file does not inherit its access")
			}
			r, err := OpenRotating(opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Write([]byte("new\n")); err != nil {
				t.Fatal(err)
			}
			privatefstest.RequirePrivate(t, opts.Path)
			if err := r.Rotate(); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var held []string
			for _, e := range entries {
				path := filepath.Join(dir, e.Name())
				privatefstest.RequirePrivate(t, path)
				if !opts.Compress {
					b, _ := os.ReadFile(path)
					held = append(held, string(b))
				}
			}
			want := 2
			if opts.RotateOnOpen {
				want = 3 // the old file is archived on its own
			}
			if len(entries) != want {
				t.Errorf("%d files, want %d: %v", len(entries), want, entries)
			}
			if all := strings.Join(held, ""); !opts.Compress && (!strings.Contains(all, "old\n") || !strings.Contains(all, "new\n")) {
				t.Errorf("lines were lost: %q", held)
			}
			if after := privatefstest.DACL(t, dir); after != before {
				t.Errorf("the directory changed: %s, was %s", after, before)
			}
		})
	}
}

// An existing file whose DACL this account may not change stops the start
// with an error that says so, and the file is left as it was.
func TestALogThisAccountCannotMakePrivateIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	if err := os.WriteFile(path, []byte("theirs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// OWNER RIGHTS takes the implicit WRITE_DAC of the owner away.
	privatefstest.SetDACL(t, path, "D:P(A;;FRFW;;;%s)(A;;FRFW;;;OW)")
	before := privatefstest.DACL(t, path)
	for _, opts := range []FileOptions{{Path: path}, {Path: path, RotateOnOpen: true}} {
		r, err := OpenRotating(opts)
		if err == nil {
			_ = r.Close()
			t.Fatalf("%+v opened a file it cannot make private", opts)
		}
		if !strings.Contains(err.Error(), "cannot be made private") || !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%+v: %v", opts, err)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != "theirs\n" {
		t.Errorf("the file changed: %q", b)
	}
	if after := privatefstest.DACL(t, path); after != before {
		t.Errorf("the DACL changed: %s", after)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the file was moved: %v", entries)
	}
}

// While another process writes the file, RotateOnOpen refuses to move it to
// the archive: a second copy of the client on the same LOG_FILE stops at start
// and the first keeps its file.
func TestAWriterElsewhereKeepsTheLogFromTheArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s5client.log")
	archive := filepath.Join(dir, "archive")
	first, err := OpenRotating(FileOptions{Path: path, ArchiveDir: archive, RotateOnOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	// An older version opened its file with os.OpenFile.
	older, err := os.OpenFile(filepath.Join(dir, "older.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer older.Close()
	if _, err := older.Write([]byte("older\n")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, older.Name()} {
		second, err := OpenRotating(FileOptions{Path: p, ArchiveDir: archive, RotateOnOpen: true})
		if err == nil {
			_ = second.Close()
			t.Fatalf("%s went to the archive while it was open", filepath.Base(p))
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Errorf("%s: %v", filepath.Base(p), err)
		}
	}
	if _, err := first.Write([]byte("still first\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "first\nstill first\n" {
		t.Errorf("live file %q", b)
	}
	if entries, _ := os.ReadDir(archive); len(entries) != 0 {
		t.Errorf("archive %v", entries)
	}
}

// Another mode leaves the file the access it inherits, as before.
func TestAnotherModeKeepsTheInheritedAccess(t *testing.T) {
	dir := broadDir(t)
	reference := filepath.Join(dir, "reference.log")
	if err := os.WriteFile(reference, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sessions.jsonl")
	r, err := OpenRotating(FileOptions{Path: path, Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := privatefstest.DACL(t, path), privatefstest.DACL(t, reference); got != want {
		t.Errorf("DACL %s, want the inherited %s", got, want)
	}
}
