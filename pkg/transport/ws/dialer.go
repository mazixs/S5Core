package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

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
	ReadLimit int64
	// WriteBufferSize is the payload one socket write carries, the shaper's
	// WS_MAX_FRAME. Zero means DefaultMaxFrame; see writeBufferSize.
	WriteBufferSize  int
	utlsSessionCache utlslib.ClientSessionCache
}

// Dialer owns TLS session caches for one immutable endpoint and trust
// configuration. Construct a new Dialer when endpoint, SNI, CA, pin or browser
// fingerprint changes. Each instance has independent crypto/tls and uTLS caches.
//
// Only the crypto/tls path ever resumes. Browser presets carry no resumption
// extension, so with TLS_FINGERPRINT every dial is a full handshake with the
// preset's JA4 and the uTLS cache stays unused. Without a fingerprint
// crypto/tls does not spend a TLS 1.3 ticket: dials that start before a fresh
// ticket arrives offer the same PSK identity in clear text, which links them
// for a passive observer (session_cache_test.go).
type Dialer struct{ opts DialOpts }

// NewDialer snapshots options. Both stacks key sessions by server name, so one
// Dialer holds one live session; the LRU bound of 16 is headroom, not a pool.
// Caller-supplied TLSConfig session caches are replaced to prevent cross-policy
// resumption. Verification callbacks must themselves remain immutable.
func NewDialer(opts DialOpts) *Dialer {
	opts.PinSHA256 = append([]string(nil), opts.PinSHA256...)
	opts.Subprotocols = append([]string(nil), opts.Subprotocols...)
	if opts.RootCAs != nil {
		opts.RootCAs = opts.RootCAs.Clone()
	}
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		opts.TLSConfig = opts.TLSConfig.Clone()
		if opts.TLSConfig.RootCAs != nil {
			opts.TLSConfig.RootCAs = opts.TLSConfig.RootCAs.Clone()
		}
		opts.TLSConfig.NextProtos = append([]string(nil), opts.TLSConfig.NextProtos...)
	}
	opts.TLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(16)
	opts.utlsSessionCache = utlslib.NewLRUClientSessionCache(16)
	return &Dialer{opts: opts}
}

// DialContext opens a new connection, reusing only the TLS session state.
func (d *Dialer) DialContext(ctx context.Context) (*Conn, error) { return DialContext(ctx, d.opts) }

// DialFrames is DialContext for a shaper whose band moved after NewDialer, as
// transport advice does: the write buffer follows maxFrame, the caches stay.
func (d *Dialer) DialFrames(ctx context.Context, maxFrame int) (*Conn, error) {
	opts := d.opts
	opts.WriteBufferSize = maxFrame
	return DialContext(ctx, opts)
}

// wsHandshakeTimeout is the maximum time allowed for the WS handshake.
//
// There was a defaultPingInterval next to it, reserved for keepalive. It is
// gone: keepalive lives in pkg/obfs (plan task Ф4-8), because a WebSocket ping
// is a control frame an observer can pick out by opcode and by length whatever
// it carries, and because the plain obfuscated listener has no WebSocket layer
// to put one in while having the same idle timeouts to survive.
const wsHandshakeTimeout = 10 * time.Second

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
		WriteBufferSize:  writeBufferSize(opts.WriteBufferSize),
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
