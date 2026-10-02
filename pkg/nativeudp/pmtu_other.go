//go:build !linux

package nativeudp

import "net"

// DontFragment leaves the socket to the kernel elsewhere, and datagrams longer
// than the path may be fragmented (docs/veil-spec.md, 10.7).
func DontFragment(*net.UDPConn) error { return nil }
