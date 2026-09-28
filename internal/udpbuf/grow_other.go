//go:build !linux

package udpbuf

import "net"

// Grow asks for Want. Windows and macOS give it or refuse it, without a
// ceiling taken silently or a doubling, so there is nothing to read back.
func Grow(c *net.UDPConn) (Got, error) {
	if err := c.SetReadBuffer(Want); err != nil {
		return Got{}, err
	}
	return Got{Bytes: Want, Full: true}, nil
}
