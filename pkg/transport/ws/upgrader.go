package ws

import (
	"bufio"
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

// UpgraderOpts configures the WebSocket upgrader.
type UpgraderOpts struct {
	// Path is the exact URL path that triggers the WS upgrade (e.g. "/ws").
	Path string
	// Subprotocols allowed. Empty = any.
	Subprotocols []string
	// CheckOrigin controls CORS. If nil, all origins are allowed (safe only
	// when hidden behind TLS + obfs auth).
	CheckOrigin func(r *http.Request) bool
	// ReadLimit bounds one message from the peer. Zero means
	// DefaultReadLimit; a negative value removes the limit. A server sets
	// this only if it knows its clients batch more than the default allows.
	ReadLimit int64
	// WriteBufferSize is the payload gorilla assembles into one socket
	// write; see writeBufferSize.
	WriteBufferSize int
	// EarlyData accepts WebSocket frames that arrive behind the upgrade
	// request, before the 101 has been sent (docs/veil-spec.md, 8.5).
	// Without it gorilla refuses such a connection outright.
	EarlyData bool
}

// writeBufferSize covers the shaper's largest message. A message longer than
// gorilla's buffer leaves as a full buffer and a remainder, so every large
// frame would open with one constant-length TLS record. Zero means
// DefaultMaxFrame; smaller values are raised to it.
func writeBufferSize(maxFrame int) int {
	return max(maxFrame, DefaultMaxFrame)
}

// Upgrader wraps a gorilla websocket.Upgrader and validates the request path.
type Upgrader struct {
	opts UpgraderOpts
	up   websocket.Upgrader
}

// NewUpgrader creates a new WS upgrader.
func NewUpgrader(opts UpgraderOpts) *Upgrader {
	checkOrigin := opts.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = func(r *http.Request) bool { return true }
	}
	return &Upgrader{
		opts: opts,
		up: websocket.Upgrader{
			Subprotocols: namedSubprotocols(opts.Subprotocols),
			CheckOrigin:  checkOrigin,
			// Payload capacity; Gorilla reserves its frame header separately.
			WriteBufferSize: writeBufferSize(opts.WriteBufferSize),
		},
	}
}

// Upgrade inspects the HTTP request and upgrades it to WebSocket if the path
// matches. Returns the upgraded Conn or an error.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if r.URL.Path != u.opts.Path {
		return nil, fmt.Errorf("ws upgrade: path %q does not match %q", r.URL.Path, u.opts.Path)
	}
	if u.opts.EarlyData {
		if h, ok := w.(http.Hijacker); ok {
			w = earlyHijacker{ResponseWriter: w, h: h}
		}
	}
	wsConn, err := u.up.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("ws upgrade: %w", err)
	}
	return WrapWithLimit(wsConn, u.opts.ReadLimit), nil
}

// earlyHijacker hands gorilla a connection whose buffered bytes have been
// moved out of the bufio.Reader and in front of the socket: gorilla refuses
// a non-empty buffer, but reads the same bytes happily from the connection.
type earlyHijacker struct {
	http.ResponseWriter
	h http.Hijacker
}

func (e earlyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := e.h.Hijack()
	if err != nil {
		return c, brw, err
	}
	n := brw.Reader.Buffered()
	if n == 0 {
		return c, brw, nil
	}
	early, _ := brw.Peek(n)
	prefix := append([]byte(nil), early...)
	_, _ = brw.Discard(n)
	return &prefixConn{Conn: c, prefix: prefix}, brw, nil
}

// prefixConn reads prefix before the socket. Reads are serialised by its
// only reader, gorilla's frame reader.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		if len(p.prefix) == 0 {
			p.prefix = nil
		}
		return n, nil
	}
	return p.Conn.Read(b)
}

// NetConn keeps the socket reachable for tcptune and obfs.layerOf.
func (p *prefixConn) NetConn() net.Conn { return p.Conn }
