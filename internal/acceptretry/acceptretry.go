// Package acceptretry decides whether a failed Accept is worth another try
// and how long to wait before it. The server's SOCKS5 listeners and the
// client's local listener share it, so the two cannot drift apart again.
package acceptretry

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// The retry schedule. A descriptor shortage clears once the load drops, so
// the pause exists to stop the loop spinning through the backlog at full
// speed, and the ceiling exists so that a listener which recovers after a
// long outage is serving again within a second.
const (
	First = 5 * time.Millisecond
	Max   = time.Second
)

// Next is the wait after current: First after a success (zero), then doubled
// up to Max.
func Next(current time.Duration) time.Duration {
	if current == 0 {
		return First
	}
	if next := current * 2; next < Max {
		return next
	}
	return Max
}

// Recoverable reports whether the next Accept on the same listener can
// succeed. Everything listed here is about this moment and not about the
// listening socket: the process is out of descriptors (EMFILE) or the system
// is (ENFILE), the kernel has no buffer space (ENOBUFS, ENOMEM), the client
// disappeared between SYN and accept (ECONNABORTED), or the call was
// interrupted (EINTR, EAGAIN). Returning from Accept on any of them takes the
// whole port down and keeps it down long after the cause has passed.
//
// A closed listener is the opposite and must not be retried: it never comes
// back, and a retry loop over it spins.
func Recoverable(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, e := range errnos {
		if errors.Is(err, e) {
			return true
		}
	}
	// A listener with a deadline set - only tests do this - reports the
	// expiry as a timeout, and the next call is expected to work.
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var errnos = []error{
	syscall.EMFILE,
	syscall.ENFILE,
	syscall.ENOBUFS,
	syscall.ENOMEM,
	syscall.ECONNABORTED,
	syscall.EINTR,
	syscall.EAGAIN,
}
