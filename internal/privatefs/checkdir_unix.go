//go:build unix

package privatefs

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// CheckDir returns an error unless path is a directory of the process's
// effective user that no group and no other user may reach. A symbolic link
// is refused, whatever it points to.
func CheckDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := checkDir(info, os.Geteuid()); err != nil {
		return &os.PathError{Op: "checkdir", Path: path, Err: err}
	}
	return nil
}

func checkDir(info fs.FileInfo, euid int) error {
	if !info.IsDir() {
		return syscall.ENOTDIR
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %v lets others in", perm)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("no owner in %T", info.Sys())
	}
	if int(st.Uid) != euid {
		return fmt.Errorf("owned by uid %d, not %d", st.Uid, euid)
	}
	return nil
}
