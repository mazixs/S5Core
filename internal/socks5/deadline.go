package socks5

import "net"

// A connection passes through regimes with completely different timing
// expectations, and one idle timeout cannot serve all of them:
//
//   - the handshake, where a client that says nothing for seconds is either
//     broken or probing, and should be dropped against an absolute budget;
//   - a TCP relay, where an idle timeout is right, measured in minutes and
//     refreshed by traffic;
//   - the UDP-over-TCP tunnel (command 0x83) and a UDP association, where the
//     carrier connection is deliberately silent whenever the application has
//     nothing to send.
//
// Until plan task Ф6-1 the regime was a plain string forwarded down the
// transport stack (SetDeadlinePolicy). It is now a property of the
// connection's session: this package moves the session between states, and
// the transport asks the session for the deadline of each read and write it
// is about to do (internal/session, pkg/s5server timeoutConn). The string and
// its per-layer forwarding are gone; what remains here is the one helper that
// has nothing to do with deadlines.

// sourceOf names where a connection came from, for rate limiting only. The
// port is dropped: a second attempt from the same client arrives on a
// different port, so keeping it would mean every attempt is its own "source"
// and no limit would ever be reached.
//
// The value is used as a map key and never written to a log; see
// docs/design/observability-policy.md.
func sourceOf(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
