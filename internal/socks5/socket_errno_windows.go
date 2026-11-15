package socks5

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// winsock lists the Winsock codes that stand for the POSIX errnos socketErrno
// is asked about. Windows reports a connection the peer closed as
// WSAECONNABORTED (after its FIN) or WSAECONNRESET (after its RST), and a
// write after a local shutdown as WSAESHUTDOWN.
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
}

// socketErrno reports whether err carries code or its Winsock counterpart. It
// matches the numeric cause, never the localized message. The POSIX value
// still matches, for Dial hooks that return it.
func socketErrno(err error, code syscall.Errno) bool {
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
