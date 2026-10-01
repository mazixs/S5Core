package logging

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func archived(t *testing.T, dir, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// Past MaxSize the file moves aside, compressed, and the archive keeps Keep
// of them; nothing written is lost on the way.
func TestTheFileRotatesBySizeAndKeepsABoundedArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	r, err := OpenRotating(FileOptions{Path: path, MaxSize: 100, Keep: 3, Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 59) + "\n"
	for range 12 {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	gz := archived(t, dir, "sessions-")
	if len(gz) != 3 {
		t.Fatalf("archive %v, want 3 files", gz)
	}
	for _, name := range gz {
		if !strings.HasSuffix(name, ".jsonl.gz") {
			t.Errorf("%s is not compressed", name)
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(zr)
		_ = f.Close()
		if err != nil || string(body) != line {
			t.Errorf("%s holds %q (%v)", name, body, err)
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(filepath.Join(dir, name))
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s is %v", name, info.Mode().Perm())
			}
		}
	}
	live, _ := os.ReadFile(path)
	if string(live) != line {
		t.Errorf("live file %q", live)
	}
}

// Each run starts a file of its own: what the last run left goes to the
// archive directory, and the archive keeps Keep runs.
func TestEveryRunStartsAFileOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s5client.log")
	archive := filepath.Join(dir, "archive")
	for run := range 5 {
		r, err := OpenRotating(FileOptions{Path: path, Keep: 2, ArchiveDir: archive, RotateOnOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Write([]byte{byte('a' + run), '\n'}); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	runs := archived(t, archive, "s5client-")
	if len(runs) != 2 {
		t.Fatalf("archive %v, want the last 2 runs", runs)
	}
	// Runs within one millisecond share the time and are told apart by the
	// count, which orders them too.
	var held []string
	for _, name := range runs {
		b, _ := os.ReadFile(filepath.Join(archive, name))
		held = append(held, string(b))
	}
	if strings.Join(held, "") != "c\nd\n" && strings.Join(held, "") != "d\nc\n" {
		t.Errorf("the archive holds %q, want the runs c and d", held)
	}
	live, _ := os.ReadFile(path)
	if string(live) != "e\n" {
		t.Errorf("live file %q", live)
	}
}

func TestOldArchivesAgeOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	old := filepath.Join(dir, "sessions-20200101T000000.000Z.jsonl.gz")
	if err := os.WriteFile(old, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	stranger := filepath.Join(dir, "other.jsonl")
	if err := os.WriteFile(stranger, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same prefix, but not a name the rotation makes: an operator's copy.
	backup := filepath.Join(dir, "sessions-backup.jsonl")
	if err := os.WriteFile(backup, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(backup, past, past); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRotating(FileOptions{Path: path, MaxAge: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Write([]byte("x\n"))
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("an archive older than MaxAge survived")
	}
	for _, p := range []string{stranger, backup} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s, which the journal did not write, was removed", filepath.Base(p))
		}
	}
	if got := archived(t, dir, "sessions-2"); len(got) != 1 {
		t.Errorf("archive %v", got)
	}
}

// A new file is private; a file that already existed keeps the mode its
// owner gave it.
func TestOnlyANewFileGetsTheMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.jsonl")
	r, err := OpenRotating(FileOptions{Path: fresh})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o600 {
		t.Errorf("new file %v", info.Mode().Perm())
	}
	existing := filepath.Join(dir, "sessions.jsonl")
	if err := os.WriteFile(existing, []byte("x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(existing, 0o640); err != nil {
		t.Fatal(err)
	}
	r, err = OpenRotating(FileOptions{Path: existing})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if info, _ := os.Stat(existing); info.Mode().Perm() != 0o640 {
		t.Errorf("existing file %v", info.Mode().Perm())
	}
}

// A link on the path stops the start, and what it points to is left as it
// was: the journal is never appended to, renamed over or chmodded through it.
func TestALinkOnThePathStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sessions.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	for _, opts := range []FileOptions{{Path: path}, {Path: path, RotateOnOpen: true}} {
		if r, err := OpenRotating(opts); err == nil {
			_ = r.Close()
			t.Errorf("%+v opened through a link", opts)
		}
	}
	body, _ := os.ReadFile(target)
	info, _ := os.Stat(target)
	if string(body) != "theirs\n" || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o644) {
		t.Errorf("the target changed: %q %v", body, info.Mode().Perm())
	}
	if l, err := os.Lstat(path); err != nil || l.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was moved")
	}
}

// A link put on the path after the start is not followed when the file is
// opened again.
func TestReopenDoesNotFollowALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no O_NOFOLLOW")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	r, err := OpenRotating(FileOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err == nil {
		t.Error("Reopen followed a link")
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("the target got %q", b)
	}
}

func TestOnlyTheRotationsOwnNamesAreArchives(t *testing.T) {
	for name, want := range map[string]bool{
		"sessions-20261001T120000.000Z.jsonl":        true,
		"sessions-20261001T120000.000Z.jsonl.gz":     true,
		"sessions-20261001T120000.000Z-3.jsonl.gz":   true,
		"sessions-backup.jsonl":                      false,
		"sessions-20261001T120000.000Z-x.jsonl":      false,
		"sessions-20261001T120000.000Z-03.jsonl":     false,
		"sessions-20261001T120000.000Z.jsonl.old":    false,
		"sessions-20261001T120000.000Z.jsonl.gz.tmp": false,
		"sessions-2026-10-01.jsonl":                  false,
		"other-20261001T120000.000Z.jsonl":           false,
	} {
		if _, ok := parseArchived(name, "sessions", ".jsonl"); ok != want {
			t.Errorf("%s: %v, want %v", name, ok, want)
		}
	}
}

// Reopen follows a rename done from outside, as logrotate with create does.
func TestReopenFollowsAnOutsideRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.jsonl")
	r, err := OpenRotating(FileOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, _ = r.Write([]byte("one\n"))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	_, _ = r.Write([]byte("two\n"))
	if b, _ := os.ReadFile(path); string(b) != "two\n" {
		t.Errorf("new file %q", b)
	}
	if b, _ := os.ReadFile(path + ".1"); string(b) != "one\n" {
		t.Errorf("rotated file %q", b)
	}
}
