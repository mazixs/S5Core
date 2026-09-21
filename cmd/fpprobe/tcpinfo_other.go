//go:build !linux

package main

import (
	"errors"
	"net"
)

// bytesAcked needs TCP_INFO, which this probe only reads on Linux. Everywhere
// else the probe still builds, and says why it cannot answer instead of
// guessing from the peer's silence.
func bytesAcked(net.Conn) (uint64, error) {
	return 0, errors.New("fpprobe reads TCP_INFO, which it only supports on Linux")
}
