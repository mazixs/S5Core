//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package udpbuf

import (
	"golang.org/x/sys/unix"
	"net"
)

func disableBroadcast(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) { optErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 0) }); err != nil {
		return err
	}
	return optErr
}
