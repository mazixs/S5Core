//go:build linux

package main

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// bytesAcked reports how many bytes of this connection the peer has
// acknowledged. It is the only measurement here that does not depend on the
// peer's application: a server that refuses the handshake by going silent
// still acknowledges at the TCP level, so a payload that was never
// acknowledged after retransmissions was dropped on the way.
func bytesAcked(conn net.Conn) (uint64, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, errors.New("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, err
	}

	var info *unix.TCPInfo
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return 0, err
	}
	if infoErr != nil {
		return 0, infoErr
	}
	return info.Bytes_acked, nil
}
