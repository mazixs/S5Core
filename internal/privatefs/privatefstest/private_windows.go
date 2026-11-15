package privatefstest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RequirePrivate fails the test unless only the process user, SYSTEM and
// local Administrators may reach path: the DACL inherits nothing from the
// directory, grants nobody else and belongs to one of the three. A directory
// must also pass every entry on to the files and directories created inside.
func RequirePrivate(t testing.TB, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !trusted(owner) {
		t.Errorf("%s belongs to %s", name, owner)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s inherits access from its directory", name)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", name, err)
	}
	const passOn = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	userGranted := false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("%s has an ACE of type %d", name, ace.Header.AceType)
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) {
			t.Errorf("%s grants access to %s", name, sid)
		}
		if sid.Equals(user.User.Sid) {
			userGranted = true
		}
		if info.IsDir() && ace.Header.AceFlags&passOn != passOn {
			t.Errorf("%s does not pass the entry for %s on to what is created inside", name, sid)
		}
	}
	if !userGranted {
		t.Errorf("%s grants nothing to the process user", name)
	}
}

// SetDACL replaces the DACL of path with sddl, protected from inheritance, %s
// standing for the process user.
func SetDACL(t testing.TB, path, sddl string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(sddl, "%s", user.User.Sid.String()))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// DACL is the DACL of path in SDDL, from "D:" on.
func DACL(t testing.TB, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	// The owner and the group may come along; no alias or SID in them holds "D:".
	s := sd.String()
	if i := strings.Index(s, "D:"); i >= 0 {
		s = s[i:]
	}
	return s
}
