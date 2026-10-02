//go:build !linux

package nativeudp

import (
	"net"
	"net/netip"
)

// Elsewhere a hub on a wildcard address answers from the address the kernel
// picks (docs/veil-spec.md, 10.6).
type sourceFamily int

const sourceOff sourceFamily = 0

const sourceSpace = 0

func askForDestination(*net.UDPConn) sourceFamily   { return sourceOff }
func destinationOf([]byte) (netip.Addr, bool)       { return netip.Addr{}, false }
func sourceControl(sourceFamily, netip.Addr) []byte { return nil }

func readFrom(c *net.UDPConn, b, _ []byte) (int, int, netip.AddrPort, error) {
	n, peer, err := c.ReadFromUDPAddrPort(b)
	return n, 0, peer, err
}

func writeTo(c *net.UDPConn, b, _ []byte, peer netip.AddrPort) error {
	_, err := c.WriteToUDPAddrPort(b, peer)
	return err
}
