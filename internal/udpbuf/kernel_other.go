//go:build !linux

package udpbuf

import "net"

// Outside Linux the size is given whole or refused, so there is nothing to
// read back.
func grow(c *net.UDPConn) (Got, error) {
	if err := c.SetReadBuffer(Want); err != nil {
		return Got{}, err
	}
	return Got{Bytes: Want, Full: true}, nil
}

func limit() int { return 0 }

// ReceiveDrops has no count to read outside Linux.
func ReceiveDrops() (uint64, bool) { return 0, false }
