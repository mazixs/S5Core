package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/mazixs/S5Core/internal/utls"
	utlslib "github.com/refraction-networking/utls"
)

// DialOpts configures the WebSocket dialer.
type DialOpts struct {
	// URL is the WebSocket endpoint (e.g. wss://example.com/ws).
	URL string
	// Host overrides the Host header (optional, for domain fronting).
	Host string
	// ServerName is the name sent in SNI and verified against the
	// certificate. Empty falls back to Host and then to the host in URL.
	//
	// Host used to decide the SNI on its own, which made one setting do two
	// unrelated things: a deployment that set Host to front a CDN silently
	// moved its SNI with it, and a deployment that wanted only the SNI moved
	// had no way to say so (plan task Ф6-4).
	ServerName string
	// Origin sets the Origin header (optional).
	Origin string
	// UserAgent sets the User-Agent header (optional).
	UserAgent string
	// Subprotocols requested via Sec-WebSocket-Protocol.
	Subprotocols []string
	// TLSConfig for the underlying TLS connection.
	TLSConfig *tls.Config
	// TLSFingerprint selects a browser TLS fingerprint (e.g. "chrome", "firefox").
	// Requires a wss URL. If empty, standard crypto/tls is used.
	TLSFingerprint string
	// RootCAs trusts a private certificate authority in addition to nothing
	// else: it replaces the system roots rather than adding to them, which is
	// what a self-signed deployment wants. Nil keeps the system roots.
	RootCAs *x509.CertPool
	// PinSHA256 pins the server's public key (hex SHA-256 of its SPKI). The
	// chain still has to verify; a pin only narrows what is accepted.
	PinSHA256 []string
	// ReadLimit bounds one message from the server. Zero means
	// DefaultReadLimit; a negative value removes the limit.
	ReadLimit        int64
	utlsSessionCache utlslib.ClientSessionCache
}

// Dial connects to a WebSocket endpoint and returns a net.Conn adapter.
func Dial(opts DialOpts) (*Conn, error) {
	return DialContext(context.Background(), opts)
}

// DialContext bounds DNS, TCP, TLS and HTTP Upgrade with the caller's
// context. The internal handshake limit can only shorten that budget.
func DialContext(ctx context.Context, opts DialOpts) (*Conn, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("ws dial: invalid url: %w", err)
	}

	dialer := websocket.Dialer{
		Subprotocols:     namedSubprotocols(opts.Subprotocols),
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

	serverName := opts.ServerName
	if serverName == "" {
		serverName = opts.Host
	}
	if serverName == "" {
		serverName = u.Hostname()
	}

	pinCheck, err := utls.NewPinChecker(opts.PinSHA256)
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	if opts.TLSFingerprint != "" {
		if u.Scheme != "wss" {
			return nil, fmt.Errorf("ws dial: TLS fingerprint requires a wss URL")
		}
		// Gorilla skips its TLS layer when NetDialTLSContext supplies it.
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utls.DialContext(ctx, network, addr, utls.Options{
				ServerName:   serverName,
				Fingerprint:  opts.TLSFingerprint,
				RootCAs:      opts.RootCAs,
				PinSHA256:    opts.PinSHA256,
				SessionCache: opts.utlsSessionCache,
			})
		}
	} else {
		tlsCfg := opts.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tlsCfg = tlsCfg.Clone()
		}
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = serverName
		}
		if opts.RootCAs != nil {
			tlsCfg.RootCAs = opts.RootCAs
		}
		if pinCheck != nil {
			// On VerifyConnection, so that a connection resumed from a
			// session ticket is pinned like any other (see NewPinChecker),
			// and chained onto whatever the caller already set rather than
			// over it: this is the caller's own tls.Config, and silently
			// dropping a check it installed would be a worse surprise than
			// the one being fixed.
			if prev := tlsCfg.VerifyConnection; prev != nil {
				tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
					if err := prev(cs); err != nil {
						return err
					}
					return pinCheck(cs)
				}
			} else {
				tlsCfg.VerifyConnection = pinCheck
			}
		}
		dialer.TLSClientConfig = tlsCfg
	}

	// Gorilla applies deadlines but does not interrupt an HTTP Upgrade read
	// on cancellation alone. Close the acquired socket until ownership is
	// handed to the caller, and join any cancellation already in progress.
	var stopCancel func() bool
	var canceled chan struct{}
	wrapDial := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(dialCtx, network, addr)
			if err != nil {
				return nil, err
			}
			canceled = make(chan struct{})
			stopCancel = context.AfterFunc(ctx, func() { _ = c.Close(); close(canceled) })
			return c, nil
		}
	}
	if dialer.NetDialTLSContext != nil {
		dialer.NetDialTLSContext = wrapDial(dialer.NetDialTLSContext)
	} else {
		dialer.NetDialContext = wrapDial((&net.Dialer{}).DialContext)
	}
	wsConn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if stopCancel != nil && !stopCancel() {
		<-canceled
	}
	if ctx.Err() != nil {
		if wsConn != nil {
			_ = wsConn.Close()
		}
		err = ctx.Err()
	}
	if resp != nil && resp.Body != nil {
		// Тело ответа на апгрейд не читается ни в одной ветке; без закрытия
		// соединение с неудачным рукопожатием остается в пуле keep-alive.
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws dial: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	return WrapWithLimit(wsConn, opts.ReadLimit), nil
}
