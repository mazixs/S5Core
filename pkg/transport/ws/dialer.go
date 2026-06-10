package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/mazixs/S5Core/internal/utls"
)

// DialOpts configures the WebSocket dialer.
type DialOpts struct {
	// URL is the WebSocket endpoint (e.g. wss://example.com/ws).
	URL string
	// Host overrides the Host header (optional, for domain fronting).
	Host string
	// Origin sets the Origin header (optional).
	Origin string
	// UserAgent sets the User-Agent header (optional).
	UserAgent string
	// Subprotocols requested via Sec-WebSocket-Protocol.
	Subprotocols []string
	// TLSConfig for the underlying TLS connection.
	TLSConfig *tls.Config
	// TLSFingerprint selects a browser TLS fingerprint (e.g. "chrome", "firefox").
	// If empty, standard crypto/tls is used.
	TLSFingerprint string
}

// Dial connects to a WebSocket endpoint and returns a net.Conn adapter.
func Dial(opts DialOpts) (*Conn, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("ws dial: invalid url: %w", err)
	}

	dialer := websocket.Dialer{
		Subprotocols:     opts.Subprotocols,
		HandshakeTimeout: wsHandshakeTimeout,
	}

	headers := make(http.Header)
	if opts.Host != "" {
		headers.Set("Host", opts.Host)
	}
	if opts.Origin != "" {
		headers.Set("Origin", opts.Origin)
	}
	if opts.UserAgent != "" {
		headers.Set("User-Agent", opts.UserAgent)
	}

	serverName := opts.Host
	if serverName == "" {
		serverName = u.Hostname()
	}

	if opts.TLSFingerprint != "" {
		// Use uTLS to mimic a browser TLS fingerprint.
		// We switch to ws:// so gorilla/websocket does not wrap the
		// connection in a second TLS layer.
		u.Scheme = "ws"
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utls.DialContext(ctx, network, addr, serverName, opts.TLSFingerprint)
		}
	} else {
		dialer.TLSClientConfig = opts.TLSConfig
	}

	wsConn, resp, err := dialer.Dial(u.String(), headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws dial: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	return Wrap(wsConn), nil
}
