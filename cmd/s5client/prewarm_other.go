//go:build !unix

package main

import "net"

// hungUp has no non-blocking peek here; a dead spare fails like a dead path.
func hungUp(net.Conn) bool { return false }
