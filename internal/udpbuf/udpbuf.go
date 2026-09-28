// Package udpbuf sizes the receive buffers of the UDP sockets that take
// traffic nobody paces for them: the answers of targets to an association,
// and the datagrams of the native path.
//
// A game server answers in bursts: a wave of some 450 datagrams within 5-10
// ms, up to 128 in one millisecond, then a tail of about 2000 a second. The
// kernel gives a socket net.core.rmem_default, 212 992 bytes on every node
// measured, and counts a datagram at the memory the network card gave it,
// some 2304 bytes, so the socket holds about 90. A reader that forwards each
// datagram before it takes the next falls behind such a wave however idle
// the server is, so the buffer has to hold the wave: without that a node lost
// 250-440 datagrams of every burst, 5% of a match on a clean path
// (docs/field/nodes.md, "Узел B для игры"; docs/plan/draft.md, Ч-2).
package udpbuf

import (
	"log/slog"
	"net"
	"strconv"
)

// Want is what every such socket asks for. Linux doubles it for its own
// bookkeeping, so a socket that gets it holds some 1800 datagrams of a game
// burst; a quiet socket costs nothing more, because the memory is taken as
// datagrams arrive.
const Want = 2 << 20

// Got is what the kernel gave a socket.
type Got struct {
	// Bytes is the size as the kernel reports it. Linux reports twice what
	// a socket asked for, the memory it accounts, which is also what ss
	// shows: 4 MiB for Want, twice rmem_max when that is lower, and
	// rmem_default, not doubled, on a socket that never asked.
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
	_, _ = Grow(c)
	return c, nil
}

// DialUDP is net.DialUDP with the receive buffer grown.
func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	c, err := net.DialUDP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	_, _ = Grow(c)
	return c, nil
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
