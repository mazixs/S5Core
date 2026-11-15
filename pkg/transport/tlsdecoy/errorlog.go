package tlsdecoy

import (
	"log"
	"log/slog"
	"regexp"
	"strings"
)

const (
	handshakeErrorPrefix = "http: TLS handshake error"
	panicServing         = "http: panic serving"
)

// newServerErrorLog routes net/http's own messages to logger. Without it they
// go through the standard log package, which slog.SetDefault binds to INFO, and
// on a public port every client that rejects the certificate would put its
// address into the INFO log. The observability policy allows no client address
// in the log at any level, and net/http puts one into the messages it writes,
// so serverErrorWriter cuts it out.
func newServerErrorLog(logger *slog.Logger) *log.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return log.New(serverErrorWriter{logger}, "", 0)
}

// serverErrorWriter turns each line of the standard logger into one slog
// record. Handshake failures are routine on a public port and go to DEBUG with
// a fixed message and the cause as an attribute; a handler panic goes to WARN
// without the address of its client; whatever else the server reports (a
// failing Accept) is a fault of this process and goes to WARN as it is.
type serverErrorWriter struct{ logger *slog.Logger }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	switch {
	case strings.HasPrefix(msg, handshakeErrorPrefix):
		if reason, ok := handshakeReason(msg); ok {
			w.logger.Debug("TLS handshake failed", "reason", reason)
		} else {
			w.logger.Debug("TLS handshake failed")
		}
	case strings.HasPrefix(msg, panicServing+" "):
		w.logger.Warn(withoutPanicAddress(msg))
	default:
		w.logger.Warn(msg)
	}
	return len(p), nil
}

// netOpError matches what net.OpError prints for a connection that failed in
// the middle of the handshake: "read tcp <local>-><remote>: <cause>". Neither
// address has a space in it, IPv6 included.
var netOpError = regexp.MustCompile(`^(read|write) \S+ \S+->\S+: (.+)$`)

// handshakeReason returns the cause of a handshake error line without any
// address. Only shapes known to be free of one pass: a TLS alert or error, an
// EOF, and a network error once its addresses are dropped. Anything else
// yields no reason, so a line that does not fit leaks nothing.
func handshakeReason(msg string) (string, bool) {
	rest, ok := strings.CutPrefix(msg, handshakeErrorPrefix+" from ")
	if !ok {
		return "", false
	}
	// "<client address>: <cause>", the address being the first word.
	addr, cause, ok := strings.Cut(rest, " ")
	if !ok || !strings.HasSuffix(addr, ":") {
		return "", false
	}
	if m := netOpError.FindStringSubmatch(cause); m != nil {
		op, reason := m[1], m[2]
		// The cause of a socket error often repeats the operation.
		if strings.HasPrefix(reason, op+": ") {
			return reason, true
		}
		return op + ": " + reason, true
	}
	switch {
	case cause == "EOF", cause == "unexpected EOF",
		strings.HasPrefix(cause, "tls: "),
		strings.HasPrefix(cause, "remote error: tls: "):
		return cause, true
	}
	return "", false
}

// withoutPanicAddress drops the client address from
// "http: panic serving <address>: <panic value and stack>" and keeps the rest.
func withoutPanicAddress(msg string) string {
	rest := strings.TrimPrefix(msg, panicServing+" ")
	addr, tail, ok := strings.Cut(rest, " ")
	if !ok || !strings.HasSuffix(addr, ":") {
		return panicServing
	}
	return panicServing + ": " + tail
}
