// Package tcptune sets TCP options on the socket of a UDP-over-TCP tunnel
// (0x83 and 0x84) so that a lost segment is retransmitted sooner, bounds how
// long the socket of a CONNECT tunnel may keep data unacknowledged
// (ForStream), and reads the kernel's state of a tunnel's socket (InfoOf).
// Why and what it buys: docs/benchmarks/game-tuning.md, docs/plan/draft.md (Ч-29).
package tcptune

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
)

// maxWrappers bounds the walk down the connection wrappers, like obfs.IdentityOf.
const maxWrappers = 10

// ErrNoSocket means the walk found nothing with a file descriptor under the
// connection: a pipe in a test, or a wrapper that hides what it wraps.
var ErrNoSocket = errors.New("tcptune: no socket under the connection")

var errUnsupported = errors.New("tcptune: the option is not supported on this system")

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

// ForStream makes the kernel close the connection under c, with ETIMEDOUT,
// once data sent on it has gone unacknowledged for d. Without it a dead path
// is noticed only after tcp_retries2, up to a quarter of an hour, and the
// application waits that long for a socket that cannot deliver. Zero leaves
// the kernel's rule. An error means the option was not set.
func ForStream(c net.Conn, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	sc, err := Socket(c)
	if err != nil {
		return err
	}
	return setDeadAfter(sc, d)
}

// control runs f on the file descriptor under sc.
func control(sc syscall.Conn, f func(fd uintptr) error) error {
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := raw.Control(func(fd uintptr) { ferr = f(fd) }); err != nil {
		return err
	}
	return ferr
}

// Skipped names the options the kernel refused, with its reason. An option
// that the kernel does not know is skipped rather than fatal: a router with
// an old kernel keeps its UDP, only slower.
type Skipped map[string]error

// ForDatagrams sets the tunnel options on the socket under c. An error means
// nothing was set: no socket, a closed one, or not Linux. Refused options are
// in Skipped.
func ForDatagrams(c net.Conn) (Skipped, error) {
	sc, err := Socket(c)
	if err != nil {
		return nil, err
	}
	return set(sc)
}

// Tuner returns ForDatagrams for a stream of associations. Each refused option
// is logged once at debug level; a nil logger means slog.Default when it logs.
func Tuner(logger *slog.Logger) func(net.Conn) {
	var said sync.Map
	debug := func(once, msg string, args ...any) {
		if once != "" {
			if _, dup := said.LoadOrStore(once, true); dup {
				return
			}
		}
		l := logger
		if l == nil {
			l = slog.Default()
		}
		l.Debug(msg, args...)
	}
	return func(c net.Conn) {
		skipped, err := ForDatagrams(c)
		switch {
		case errors.Is(err, ErrNoSocket):
			debug("no socket", "udp tunnel: no socket to tune")
		case errors.Is(err, errUnsupported):
			debug("platform", "udp tunnel: socket tuning is Linux only")
		case err != nil:
			debug("", "udp tunnel: could not tune the socket", "error", err)
		}
		for name, why := range skipped {
			debug(name, "udp tunnel: the kernel refused a socket option", "option", name, "error", why)
		}
	}
}
