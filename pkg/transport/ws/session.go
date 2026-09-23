package ws

import (
	"context"
	"crypto/tls"

	utlslib "github.com/refraction-networking/utls"
)

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
