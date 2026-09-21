//go:build !linux

package main

import (
	"errors"
	"net"
)

// pathInfo needs TCP_INFO, which this collector only reads on Linux. The
// fingerprint itself does not depend on it, so everywhere else the collector
// still runs and simply leaves the timing fields out.
func pathInfo(net.Conn) (uint32, uint32, error) {
	return 0, 0, errors.New("fpcollect читает TCP_INFO только на Linux")
}
