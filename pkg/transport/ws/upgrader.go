package ws

import (
	"fmt"
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
	wsConn, err := u.up.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("ws upgrade: %w", err)
	}
	return WrapWithLimit(wsConn, u.opts.ReadLimit), nil
}
