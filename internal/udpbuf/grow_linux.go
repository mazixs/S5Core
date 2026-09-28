package udpbuf

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Grow asks for Want. SO_RCVBUFFORCE passes net.core.rmem_max for a process
// with CAP_NET_ADMIN; without it the kernel refuses, and SO_RCVBUF takes what
// rmem_max allows. The size is read back, because neither says what it gave.
func Grow(c *net.UDPConn) (Got, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return Got{}, err
	}
	var got int
	var setErr, getErr error
	if err := rc.Control(func(fd uintptr) {
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, Want) != nil {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, Want)
		}
		got, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return Got{}, err
	}
	if getErr != nil {
		return Got{}, errors.Join(setErr, getErr)
	}
	return Got{Bytes: got, Full: got >= 2*Want, Limit: limit()}, setErr
}

func limit() int {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
