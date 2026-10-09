//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package udpbuf

import (
	"errors"
	"net"
)

func disableBroadcast(*net.UDPConn) error {
	return errors.New("UDP relay: cannot disable broadcast on this platform")
}
