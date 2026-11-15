package logging

import "golang.org/x/sys/windows"

// privateDescriptor is owned by the process user and grants full access to
// that user, SYSTEM and local Administrators only, inheriting nothing from the
// directory.
func privateDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	t, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	user := t.User.Sid.String()
	return windows.SecurityDescriptorFromString("O:" + user + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user + ")")
}

// privateOwner reports whether owner is one of the identities sd grants: the
// owner of a file may rewrite its DACL whatever the DACL says.
func privateOwner(sd *windows.SECURITY_DESCRIPTOR, owner *windows.SID) bool {
	if user, _, err := sd.Owner(); err == nil && owner.Equals(user) {
		return true
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
