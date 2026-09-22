package ws

import (
	"context"
	"crypto/tls"

	utlslib "github.com/refraction-networking/utls"
)

// Dialer owns bounded TLS session caches for one immutable endpoint and trust
// configuration. Construct a new Dialer when endpoint, SNI, CA, pin or browser
// fingerprint changes. Each instance has independent crypto/tls and uTLS caches.
// Browser presets without a resumption extension retain their original wire
// fingerprint and perform a full handshake.
type Dialer struct{ opts DialOpts }

// NewDialer snapshots options and keeps at most 16 sessions per TLS stack.
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
