package ws

import "time"

// wsHandshakeTimeout is the maximum time allowed for the WS handshake.
//
// There was a defaultPingInterval next to it, reserved for keepalive. It is
// gone: keepalive lives in pkg/obfs (plan task Ф4-8), because a WebSocket ping
// is a control frame an observer can pick out by opcode and by length whatever
// it carries, and because the plain obfuscated listener has no WebSocket layer
// to put one in while having the same idle timeouts to survive.
const wsHandshakeTimeout = 10 * time.Second

// namedSubprotocols drops empty entries from a subprotocol list and returns
// nil when nothing is left.
//
// An empty string is not "no subprotocol": on the dialer it puts an empty
// Sec-WebSocket-Protocol header on the wire, which no browser and no ordinary
// client ever sends, and on the upgrader it offers to agree to one. A
// transport whose purpose is to look like every other WebSocket connection
// cannot carry a header that only it sends (plan task Ф6-5). The filter lives
// here, at the transport, so that no caller can reintroduce it.
func namedSubprotocols(list []string) []string {
	var out []string
	for _, p := range list {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
