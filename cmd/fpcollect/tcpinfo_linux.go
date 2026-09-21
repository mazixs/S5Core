//go:build linux

package main

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// pathInfo reports the round trip and the MSS the local stack measured for
// this connection. Both come from the kernel rather than from timing the
// application, so neither includes whatever the peer was doing between
// packets - which is the only way the number is comparable between runs.
func pathInfo(conn net.Conn) (rttMicros uint32, mss uint32, err error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, 0, errors.New("не TCP-соединение")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var info *unix.TCPInfo
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return 0, 0, err
	}
	if infoErr != nil {
		return 0, 0, infoErr
	}
	return info.Rtt, info.Snd_mss, nil
}
