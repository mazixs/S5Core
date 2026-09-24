// Package tcptune sets the retransmission behaviour a UDP-over-TCP tunnel
// (command 0x83) wants from the TCP socket that carries it.
//
// A game or a call sends a few small datagrams per tick, so a lost segment
// is recovered by the retransmission timer rather than by fast retransmit,
// and Linux never lets that timer go under 200 ms and doubles it on every
// repeated loss. The datagrams behind the lost segment wait all that time
// (docs/benchmarks/game-loss.md). The options here shorten the wait; they
// cannot remove it, which is what the UDP transport is for
// (docs/plan/game-fixes.md, stage Т).
//
// Only tunnel connections get them. A CONNECT relay carries bulk transfers,
// for which an early retransmission is a duplicate and a collapsed window
// that buys no latency.
package tcptune

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"syscall"
)

// maxWrappers bounds the walk down the connection wrappers, like
// obfs.IdentityOf does.
const maxWrappers = 10

// ErrNoSocket means the walk found nothing with a file descriptor under the
// connection: a pipe in a test, or a wrapper that hides what it wraps.
var ErrNoSocket = errors.New("tcptune: no socket under the connection")

// Socket walks the wrappers (NetConn, then Unwrap) down to the connection
// that owns a file descriptor. Every layer between the tunnel and the
// socket - the server's metering and deadline wrappers, the obfuscation,
// WebSocket and TLS - answers NetConn.
func Socket(c net.Conn) (syscall.Conn, error) {
	for range maxWrappers {
		switch v := c.(type) {
		case nil:
			return nil, ErrNoSocket
		case *net.TCPConn:
			return v, nil
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		case interface{ Unwrap() net.Conn }:
			c = v.Unwrap()
		default:
			if sc, ok := c.(syscall.Conn); ok {
				return sc, nil
			}
			return nil, ErrNoSocket
		}
	}
	return nil, ErrNoSocket
}

// Skipped names the options the kernel refused, with its reason. An option
// that the kernel does not know is skipped rather than fatal: a router with
// an old kernel keeps its UDP, only slower.
type Skipped map[string]error

// ForDatagrams sets the tunnel options on the socket under c. The error is
// for a missing socket only; refused options are in Skipped.
func ForDatagrams(c net.Conn) (Skipped, error) {
	sc, err := Socket(c)
	if err != nil {
		return nil, err
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	skipped := Skipped{}
	if err := raw.Control(func(fd uintptr) { apply(fd, skipped) }); err != nil {
		return nil, err
	}
	return skipped, nil
}

// Tuner returns ForDatagrams for a stream of associations. What the kernel
// refuses is logged once per option at debug level: an old kernel refuses
// the same option on every association, and that is not an error. A nil
// logger means slog.Default at the time of the call.
func Tuner(logger *slog.Logger) func(net.Conn) {
	var said sync.Map
	once := func(key string, msg string, args ...any) {
		if _, dup := said.LoadOrStore(key, true); dup {
			return
		}
		l := logger
		if l == nil {
			l = slog.Default()
		}
		l.Debug(msg, args...)
	}
	return func(c net.Conn) {
		skipped, err := ForDatagrams(c)
		if err != nil {
			once("", "udp tunnel: no socket to tune", "error", err)
			return
		}
		for name, why := range skipped {
			once(name, "udp tunnel: the kernel refused a socket option", "option", name, "error", why)
		}
	}
}
