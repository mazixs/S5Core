package relay

import "net"

// Abort closes the original wrapper, while a TCP socket below it gets a
// reset rather than a FIN. Framed transports close without a clean end
// frame, which their reader treats as truncation. Limit unwrapping so an
// embedding application's malformed wrapper cannot spin indefinitely.
func Abort(conn net.Conn) {
	for current, depth := conn, 0; current != nil && depth < 32; depth++ {
		if tcp, ok := current.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
			break
		}
		wrapper, ok := current.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		current = wrapper.NetConn()
	}
	_ = conn.Close()
}
