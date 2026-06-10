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
			Subprotocols: opts.Subprotocols,
			CheckOrigin:  checkOrigin,
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
	return Wrap(wsConn), nil
}

// IsWSRequest returns true if the request looks like a WebSocket upgrade.
func IsWSRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket" &&
		r.Header.Get("Connection") == "Upgrade"
}
