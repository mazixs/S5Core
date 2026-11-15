package privatefs

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FileDescriptor is owned by the process user and grants full access to that
// user, SYSTEM and local Administrators only, inheriting nothing from the
// directory.
func FileDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return descriptor("")
}

// dirDescriptor is FileDescriptor for a directory whose entries pass on to
// the files and directories created inside it.
func dirDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	return descriptor("OICI")
}

func descriptor(inherit string) (*windows.SECURITY_DESCRIPTOR, error) {
	t, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	user := t.User.Sid.String()
	ace := func(sid string) string { return "(A;" + inherit + ";FA;;;" + sid + ")" }
	return windows.SecurityDescriptorFromString("O:" + user + "D:P" + ace("SY") + ace("BA") + ace(user))
}

// TrustedOwner reports whether owner is one of the identities sd grants: the
// owner of a file may rewrite its DACL whatever the DACL says.
func TrustedOwner(sd *windows.SECURITY_DESCRIPTOR, owner *windows.SID) bool {
	if user, _, err := sd.Owner(); err == nil && owner.Equals(user) {
		return true
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// CheckDir returns an error unless path is a directory only the identities
// FileDescriptor grants may reach: one of them owns it, and its DACL is
// protected from inheritance and allows access to nobody else. A symbolic
// link or a junction is refused, whatever it points to.
func CheckDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	// Lstat reports a symbolic link and a junction as no directory.
	if !info.IsDir() {
		return &os.PathError{Op: "checkdir", Path: path, Err: syscall.ENOTDIR}
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		var ours *windows.SECURITY_DESCRIPTOR
		if ours, err = FileDescriptor(); err == nil {
			err = onlyTrusted(sd, ours)
		}
	}
	if err != nil {
		return &os.PathError{Op: "checkdir", Path: path, Err: err}
	}
	return nil
}

// onlyTrusted checks sd against ours, the descriptor FileDescriptor gives:
// an owner it trusts, a protected DACL, and allow entries for its identities
// only. A deny entry takes access away and passes.
func onlyTrusted(sd, ours *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !TrustedOwner(ours, owner) {
		return fmt.Errorf("owned by %s", owner)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("the DACL inherits from the parent directory")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("no DACL: everyone has access")
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !TrustedOwner(ours, sid) {
				return fmt.Errorf("grants access to %s", sid)
			}
		default:
			return fmt.Errorf("an access entry of type %d", ace.Header.AceType)
		}
	}
	return nil
}

func attributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
}

// CreateTemp is os.CreateTemp with the file private from its creation: the
// descriptor goes to CreateFile, so no other account can open the file before
// anything is written to it. Renamed over another file, it keeps its DACL.
func CreateTemp(dir, pattern string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `\/`) {
		return nil, &os.PathError{Op: "createtemp", Path: pattern, Err: errors.New("pattern contains path separator")}
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	sd, err := FileDescriptor()
	if err != nil {
		return nil, err
	}
	for try := 0; ; try++ {
		name := filepath.Join(dir, prefix+strconv.FormatUint(uint64(rand.Uint32()), 10)+suffix)
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		// As os.OpenFile does for O_RDWR|O_CREATE|O_EXCL.
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			attributes(sd), windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if errors.Is(err, fs.ErrExist) && try < 10000 {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		return os.NewFile(uintptr(h), name), nil
	}
}

// MkdirAll is os.MkdirAll in which every directory this call creates gets the
// private DACL, passed on to what is created inside it. A directory that
// already exists, the volume root among them, is left as it is.
func MkdirAll(path string) error {
	// The steps of os.MkdirAll, with mkdir for os.Mkdir.
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}
	i := len(path) - 1
	for i >= 0 && os.IsPathSeparator(path[i]) {
		i--
	}
	for i >= 0 && !os.IsPathSeparator(path[i]) {
		i--
	}
	if i < 0 {
		i = 0
	}
	if parent := path[:i]; len(parent) > len(filepath.VolumeName(path)) {
		if err := MkdirAll(parent); err != nil {
			return err
		}
	}
	if err := mkdir(path); err != nil {
		// "dir/." and the like: the directory is there after all.
		if info, e := os.Lstat(path); e == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func mkdir(path string) error {
	sd, err := dirDescriptor()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err == nil {
		err = windows.CreateDirectory(p, attributes(sd))
	}
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}
