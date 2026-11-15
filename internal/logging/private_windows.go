package logging

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/mazixs/S5Core/internal/privatefs"
	"golang.org/x/sys/windows"
)

// openLogFile opens a log as os.OpenFile does for O_WRONLY with O_CREATE,
// O_APPEND and O_TRUNC. With mode 0600 the file gets the private DACL: a new
// one at creation, an existing one before anything is written. Its handle lets
// another process rename the file, as a rotation from outside does on POSIX.
// Any other mode keeps the access the file inherits from its directory.
func openLogFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	if mode.Perm() != 0o600 {
		return os.OpenFile(path, flag|noFollow, mode)
	}
	access := uint32(windows.GENERIC_WRITE)
	if flag&os.O_APPEND != 0 {
		// Without FILE_WRITE_DATA every write goes to the end of the file, as
		// os.OpenFile does it for O_APPEND.
		access = windows.FILE_APPEND_DATA | windows.SYNCHRONIZE
	}
	creation := uint32(windows.OPEN_EXISTING)
	if flag&os.O_CREATE != 0 {
		creation = windows.OPEN_ALWAYS
	}
	f, err := openPrivate(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, creation)
	if err != nil {
		return nil, err
	}
	if flag&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// protectLogFile gives an existing log the private DACL before archive renames
// it, so that a file an older version left goes to the archive private too.
// DELETE puts the open under the sharing check, and without FILE_SHARE_WRITE
// it fails while another process writes the file - a second copy of the client
// on the same LOG_FILE - instead of moving the file from under that process.
func protectLogFile(path string, mode os.FileMode) error {
	if mode.Perm() != 0o600 {
		return nil
	}
	f, err := openPrivate(path, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	return f.Close()
}

// openPrivate opens path with access and gives the file the private DACL
// through the handle, since CreateFile applies a descriptor only to a file it
// creates. A reparse point is opened itself, not followed, and refused with
// anything else that is not a regular file. So is a file this account cannot
// make private: its DACL is not ours to change, or its owner can change it back.
func openPrivate(path string, access, share, creation uint32) (*os.File, error) {
	sd, err := privatefs.FileDescriptor()
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	const flags = windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT
	h, err := windows.CreateFile(name, access|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC, share, &sa, creation, flags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// Open without WRITE_DAC only to tell this case from no access at all.
		if h, e := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0); e == nil {
			_ = windows.CloseHandle(h)
			return nil, fmt.Errorf("%s cannot be made private: this account may not change its permissions; remove the file or take ownership of it: %w", path, err)
		}
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", path))
	}
	current, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fail(&os.PathError{Op: "protect", Path: path, Err: err})
	}
	owner, _, err := current.Owner()
	if err != nil {
		return fail(&os.PathError{Op: "protect", Path: path, Err: err})
	}
	if !privatefs.TrustedOwner(sd, owner) {
		return fail(fmt.Errorf("%s cannot be made private: it belongs to %s, which may change its permissions at any time; remove the file or take ownership of it", path, owner))
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fail(&os.PathError{Op: "protect", Path: path, Err: err})
	}
	return f, nil
}
