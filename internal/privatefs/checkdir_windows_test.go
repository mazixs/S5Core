package privatefs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
	"golang.org/x/sys/windows"
)

func TestCheckDirTakesOnlyAPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	private := filepath.Join(base, "private")
	if err := MkdirAll(private); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(private); err != nil {
		t.Fatalf("a directory MkdirAll made: %v", err)
	}
	// What the user itself set up: only the user, protected, nothing passed on.
	own := filepath.Join(base, "own")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	privatefstest.SetDACL(t, own, "D:P(A;;FA;;;%s)")
	if err := CheckDir(own); err != nil {
		t.Errorf("a directory only the user may reach: %v", err)
	}

	inherited := filepath.Join(base, "inherited")
	if err := os.Mkdir(inherited, 0o700); err != nil {
		t.Fatal(err)
	}
	broad := filepath.Join(base, "broad")
	if err := os.Mkdir(broad, 0o700); err != nil {
		t.Fatal(err)
	}
	privatefstest.SetDACL(t, broad, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)")
	// A file as private as a directory may be.
	f, err := CreateTemp(base, "file-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	junction := filepath.Join(base, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, private).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	for _, path := range []string{inherited, broad, f.Name(), junction, filepath.Join(base, "missing")} {
		if err := CheckDir(path); err == nil {
			t.Errorf("%s passed", filepath.Base(path))
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Logf("no symbolic link without the privilege: %v", err)
	} else if err := CheckDir(link); err == nil {
		t.Error("a symbolic link to a private directory passed")
	}
}

// The descriptor of a directory against the one FileDescriptor gives, %s
// standing for the process user. SIDs go in through SDDL and are compared as
// SIDs, never as printed SDDL.
func TestOnlyTrustedChecksTheOwnerTheProtectionAndEveryEntry(t *testing.T) {
	ours, err := FileDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	user := processUser(t)
	for sddl, want := range map[string]bool{
		"O:%sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)": true,
		"O:BAD:P(A;;FA;;;%s)":                         true,
		"O:SYD:P(A;;FA;;;SY)":                         true,
		"O:%sD:P(D;;FA;;;WD)(A;;FA;;;%s)":             true,
		"O:%sD:P":                                     true,
		"O:%sD:P(A;;FA;;;%s)(A;;FR;;;BU)":             false,
		"O:%sD:P(A;;FA;;;%s)(A;;FR;;;WD)":             false,
		"O:%sD:P(A;OICIIO;FA;;;CO)(A;;FA;;;%s)":       false,
		"O:%sD:(A;;FA;;;%s)":                          false,
		"O:%sD:NO_ACCESS_CONTROL":                     false,
		"O:%sD:PNO_ACCESS_CONTROL":                    false,
		"O:%sD:P(A;;FA;;;%s)(XA;;FA;;;WD;(Exists x))": false,
		"O:BUD:P(A;;FA;;;%s)":                         false,
		"O:WDD:P(A;;FA;;;%s)":                         false,
		"O:%sD:PAI(A;;FA;;;%s)(A;ID;FA;;;AU)":         false,
		"O:%sD:P(A;;FA;;;%s)(A;;0x1;;;S-1-5-11)":      false,
		"O:%sD:P(A;;FA;;;%s)(A;CI;FA;;;S-1-1-0)":      false,
		"O:%sD:P(A;;FA;;;S-1-5-32-545)(A;;FA;;;%s)":   false,
	} {
		sd, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(sddl, "%s", user))
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		if got := onlyTrusted(sd, ours) == nil; got != want {
			t.Errorf("%s: passed %v, want %v (%v)", sddl, got, want, onlyTrusted(sd, ours))
		}
	}
}
