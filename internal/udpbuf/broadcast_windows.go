package udpbuf

import (
	"net"
	"syscall"
)

func disableBroadcast(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return optErr
}
