package privatefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
	"golang.org/x/sys/windows"
)

// broadDir is a directory whose files inherit read access for every local
// user.
func broadDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	privatefstest.SetDACL(t, dir, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)")
	return dir
}

func processUser(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// In a directory that grants every local user read access, the temporary file
// grants it to nobody, before and after it is renamed over a file that did.
func TestATemporaryFileDoesNotInheritTheDirectory(t *testing.T) {
	dir := broadDir(t)
	target := filepath.Join(dir, "users.json")
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(privatefstest.DACL(t, target), ";;;BU)") {
		t.Fatal("the target does not inherit the directory")
	}
	f, err := CreateTemp(dir, ".users-*.json.tmp")
	if err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, f.Name())
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), target); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, target)
	if b, _ := os.ReadFile(target); string(b) != "new\n" {
		t.Errorf("target holds %q", b)
	}
}

func TestCreateTempRefusesAPatternWithASeparator(t *testing.T) {
	dir := t.TempDir()
	for _, pattern := range []string{`..\x*`, "../x*"} {
		if f, err := CreateTemp(dir, pattern); err == nil {
			_ = f.Close()
			t.Errorf("%q: created %s", pattern, f.Name())
		}
	}
}

// What MkdirAll creates in a broad directory is private and passes that on:
// a file or a directory created inside by any means gets the same three
// entries and nothing else. The directory it started from keeps its DACL.
func TestMkdirAllPassesThePrivateDACLOnToTheContent(t *testing.T) {
	dir := broadDir(t)
	before := privatefstest.DACL(t, dir)
	leaf := filepath.Join(dir, "logs", "archive")
	if err := MkdirAll(leaf); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, filepath.Join(dir, "logs"))
	privatefstest.RequirePrivate(t, leaf)
	if after := privatefstest.DACL(t, dir); after != before {
		t.Errorf("the directory changed: %s, was %s", after, before)
	}
	file := filepath.Join(leaf, "plain.log")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(leaf, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	user := processUser(t)
	for path, want := range map[string]string{
		file: "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;" + user + ")",
		sub:  "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;" + user + ")",
	} {
		// SDDL prints some SIDs as aliases (the built-in Administrator as
		// LA), so the expectation goes through the same printing.
		sd, err := windows.SecurityDescriptorFromString(want)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := privatefstest.DACL(t, path), sd.String(); got != want {
			t.Errorf("%s: %s, want %s", filepath.Base(path), got, want)
		}
	}
}

// A directory that exists, the volume root included, is left as it is.
func TestMkdirAllLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := broadDir(t)
	root := filepath.VolumeName(dir) + `\`
	for _, path := range []string{dir, root} {
		before := privatefstest.DACL(t, path)
		if err := MkdirAll(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if after := privatefstest.DACL(t, path); after != before {
			t.Errorf("%s changed: %s, was %s", path, after, before)
		}
	}
}

// A relative path, with either separator, is created below the working
// directory, every new step private.
func TestMkdirAllTakesARelativePath(t *testing.T) {
	dir := broadDir(t)
	t.Chdir(dir)
	if err := MkdirAll("rel/sub"); err != nil {
		t.Fatal(err)
	}
	privatefstest.RequirePrivate(t, filepath.Join(dir, "rel"))
	privatefstest.RequirePrivate(t, filepath.Join(dir, "rel", "sub"))
}

func TestOnlyTheGrantedIdentitiesAreTrustedOwners(t *testing.T) {
	sd, err := FileDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	for sid, want := range map[string]bool{
		processUser(t): true,
		"S-1-5-18":     true,
		"S-1-5-32-544": true,
		"S-1-5-32-545": false,
		"S-1-5-11":     false,
		"S-1-1-0":      false,
	} {
		owner, err := windows.StringToSid(sid)
		if err != nil {
			t.Fatal(err)
		}
		if got := TrustedOwner(sd, owner); got != want {
			t.Errorf("owner %s: %v, want %v", sid, got, want)
		}
	}
}
