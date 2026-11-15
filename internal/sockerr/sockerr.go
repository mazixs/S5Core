// Package sockerr tells socket failures apart by their errno on every
// platform. On Windows a socket call fails with a Winsock code
// (WSAECONNRESET and the like), which errors.Is does not match against the
// POSIX syscall.E* values: a check written against them alone silently
// misses there.
package sockerr

import (
	"errors"
	"net"
	"syscall"
)

// Timeout reports whether err is a timeout: a deadline that expired, or the
// system giving up on the peer (ETIMEDOUT). net.Error.Timeout covers both on
// Unix, but on Windows WSAETIMEDOUT does not report itself as a timeout.
func Timeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || Is(err, syscall.ETIMEDOUT)
}
