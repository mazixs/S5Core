package sockerr

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// winsock lists the Winsock codes that stand for the POSIX errnos Is is asked
// about. Windows reports a connection the peer closed as WSAECONNABORTED
// (after its FIN) or WSAECONNRESET (after its RST), and a write after a local
// shutdown as WSAESHUTDOWN. A client that resets before AcceptEx completes
// never gets here: the runtime retries WSAECONNRESET itself.
var winsock = map[syscall.Errno][]syscall.Errno{
	syscall.ECONNRESET:   {windows.WSAECONNRESET, windows.WSAECONNABORTED},
	syscall.EPIPE:        {windows.WSAECONNABORTED, windows.WSAESHUTDOWN},
	syscall.ECONNREFUSED: {windows.WSAECONNREFUSED},
	syscall.ENETUNREACH:  {windows.WSAENETUNREACH},
	syscall.EHOSTUNREACH: {windows.WSAEHOSTUNREACH},
	syscall.EHOSTDOWN:    {windows.WSAEHOSTDOWN},
	syscall.EAFNOSUPPORT: {windows.WSAEAFNOSUPPORT},
	syscall.EMSGSIZE:     {windows.WSAEMSGSIZE},
	syscall.ENOBUFS:      {windows.WSAENOBUFS},
	syscall.EMFILE:       {windows.WSAEMFILE},
	syscall.ETIMEDOUT:    {windows.WSAETIMEDOUT},
}

// Is reports whether err carries code or a Winsock code that stands for it.
// It matches the numeric cause, never the localized message. The POSIX value
// still matches, for Dial hooks that return it.
func Is(err error, code syscall.Errno) bool {
	if errors.Is(err, code) {
		return true
	}
	for _, c := range winsock[code] {
		if errors.Is(err, c) {
			return true
		}
	}
	return false
}
