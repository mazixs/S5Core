//go:build !windows

package sockerr

import (
	"errors"
	"syscall"
)

// Is reports whether err carries code. Outside Windows the socket calls
// return the POSIX errno itself.
func Is(err error, code syscall.Errno) bool { return errors.Is(err, code) }
