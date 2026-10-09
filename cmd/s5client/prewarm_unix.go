//go:build unix

package main

import (
	"errors"
	"net"
	"syscall"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// hungUp reports, without blocking, whether the server has already closed
// the socket under a spare. Where the kernel tells the TCP state (Linux),
// anything but established is gone: a TLS server sends close_notify ahead
// of its FIN, so bytes waiting prove nothing. Elsewhere a peek has to do,
// and it sees a close only when nothing is waiting in front of it.
func hungUp(c net.Conn) bool {
	if info, ok := tcptune.InfoOf(c); ok {
		return info.State != tcptune.StateEstablished
	}
	sc, err := tcptune.Socket(c)
	if err != nil {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var gone bool
	var buf [1]byte
	_ = raw.Read(func(fd uintptr) bool {
		n, _, err := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case err == nil:
			gone = n == 0
		case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EINTR):
		default:
			gone = true
		}
		return true
	})
	return gone
}
