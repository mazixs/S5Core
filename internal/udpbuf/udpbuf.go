// Package udpbuf grows the receive buffers of the relay's UDP sockets, which
// take bursts of answers nobody paces for them (docs/plan/draft.md, Ч-2;
// docs/benchmarks/udp-burst-2026-09-28.md).
package udpbuf

import (
	"log/slog"
	"net"
	"strconv"
)

// Want is what every relay UDP socket asks for.
const Want = 2 << 20

// Got is what the kernel gave a socket.
type Got struct {
	// Bytes is the size the kernel reports; Linux reports twice what it gave.
	Bytes int
	// Full is whether that is all Want asked for.
	Full bool
	// Limit is net.core.rmem_max on Linux, the ceiling of a process without
	// CAP_NET_ADMIN, and 0 elsewhere.
	Limit int
}

// ListenUDP is net.ListenUDP with the receive buffer grown. A refusal leaves
// the kernel's size; Probe tells the operator once, for every socket.
func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	c, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	_, _ = grow(c)
	return c, nil
}

// DialUDP is net.DialUDP with the receive buffer grown.
func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	c, err := net.DialUDP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	_, _ = grow(c)
	return c, nil
}

// Grow asks for Want and reports what the socket got, with the ceiling.
func Grow(c *net.UDPConn) (Got, error) {
	got, err := grow(c)
	if got.Bytes > 0 {
		got.Limit = limit()
	}
	return got, err
}

// Probe grows a socket of its own and reports what it got. Every socket of
// the process gets the same, so this is the one answer to log.
func Probe() (Got, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return Got{}, err
	}
	defer func() { _ = c.Close() }()
	return Grow(c)
}

// Report logs Probe once: at Info when every socket gets Want, at Warn with
// the ceiling to raise when it does not.
func Report(log *slog.Logger) {
	got, err := Probe()
	report(log, got, err)
}

func report(log *slog.Logger, got Got, err error) {
	switch {
	case got.Bytes == 0:
		log.Warn("UDP receive buffer unknown", "error", err)
	case got.Full:
		log.Info("UDP receive buffer", "bytes", got.Bytes)
	default:
		log.Warn("UDP receive buffer below what answer bursts need, set net.core.rmem_max="+strconv.Itoa(Want)+" on the host",
			"bytes", got.Bytes, "rmem_max", got.Limit)
	}
}
