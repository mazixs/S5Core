// Package utls provides a thin wrapper around refraction-networking/utls
// so the WebSocket dialer can perform browser-grade TLS handshakes.
package utls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint presets for JA3 mimicry.
const (
	FPChrome    = "chrome"
	FPFirefox   = "firefox"
	FPSafari    = "safari"
	FPIOS       = "ios"
	FPDefaultGo = "go"
)

// ErrPinMismatch is returned when the server presented a valid certificate
// that is not the one that was pinned.
var ErrPinMismatch = errors.New("utls: server key does not match any pin")

// Options configures certificate verification for a uTLS dial.
//
// The dialer used to hand this job to the caller - InsecureSkipVerify with a
// comment saying the caller should pin the certificate - and no caller ever
// did. A transport built to be indistinguishable from ordinary HTTPS was the
// one connection in the system that accepted any certificate at all, which
// makes a man in the middle not merely possible but undetectable.
//
// Verification is therefore no longer optional. A private deployment with a
// self-signed certificate supplies it through RootCAs; PinSHA256 narrows
// trust further, down to one key.
type Options struct {
	// ServerName is the name verified against the certificate and sent in SNI.
	ServerName string
	// Fingerprint selects the browser ClientHello to imitate.
	Fingerprint string
	// RootCAs replaces the system roots when set. This is how a self-signed
	// server is trusted: by naming it, not by trusting everyone.
	RootCAs *x509.CertPool
	// PinSHA256 holds SHA-256 hashes of the server's SubjectPublicKeyInfo,
	// hex encoded. When non-empty the chain must validate AND the leaf key
	// must match one of the pins.
	PinSHA256 []string
	// SessionCache belongs to one endpoint and immutable trust configuration.
	SessionCache utls.ClientSessionCache
}

// DialContext dials TCP and performs a uTLS handshake using the specified
// browser fingerprint. The returned net.Conn is a *utls.UConn and satisfies
// the standard net.Conn interface.
func DialContext(ctx context.Context, network, addr string, opts Options) (net.Conn, error) {
	pins, err := normalizePins(opts.PinSHA256)
	if err != nil {
		return nil, err
	}

	serverName := opts.ServerName
	if serverName == "" {
		// An empty ServerName with verification on would make every handshake
		// fail with a confusing error, so derive it from the address the way
		// crypto/tls does.
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		serverName = host
	}

	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("utls dial tcp: %w", err)
	}

	config := &utls.Config{
		ServerName:         serverName,
		RootCAs:            opts.RootCAs,
		MinVersion:         utls.VersionTLS13,
		ClientSessionCache: opts.SessionCache,
		// Never add a PSK extension to a named browser fingerprint.
		PreferSkipResumptionOnNilExtension: true,
	}
	if len(pins) > 0 {
		// Runs after the chain has been verified, so a pin is an extra
		// condition and never a replacement for one - and on VerifyConnection
		// rather than VerifyPeerCertificate, for the reason given at
		// NewPinChecker.
		config.VerifyConnection = func(cs utls.ConnectionState) error {
			return pinnedLeaf(pins, cs.PeerCertificates)
		}
	}

	clientHelloID := fingerprintToClientHelloID(opts.Fingerprint)
	uconn := utls.UClient(tcpConn, config, clientHelloID)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return uconn, nil
}

// NewPinChecker builds the VerifyConnection callback for a set of pins, for
// callers that use crypto/tls directly instead of uTLS. An empty list returns
// a nil callback, which is the "chain verification only" case.
//
// VerifyConnection is where a pin belongs. Its neighbour
// VerifyPeerCertificate is not called on a resumed connection - no
// certificate is sent on one, so there is nothing to hand it - while
// VerifyConnection runs on every connection, resumed or not, and gets the
// certificates the session was established with. A pin checked in the other
// place is therefore a pin that a session ticket skips: an application that
// gives this dialer a tls.Config with a ClientSessionCache, which is how TLS
// resumption is turned on in Go, would have its pin enforced on the first
// connection and on none of the ones that resume. Reported by gosec as G123.
func NewPinChecker(pins []string) (func(tls.ConnectionState) error, error) {
	parsed, err := normalizePins(pins)
	if err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return nil, nil
	}
	return func(cs tls.ConnectionState) error {
		return pinnedLeaf(parsed, cs.PeerCertificates)
	}, nil
}

// SPKIPin returns the pin value for a certificate: the hex encoded SHA-256 of
// its SubjectPublicKeyInfo. Pinning the key rather than the certificate means
// a renewal with the same key does not break the client.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// normalizePins accepts pins written with or without colons and in any case.
func normalizePins(pins []string) ([][]byte, error) {
	out := make([][]byte, 0, len(pins))
	for _, p := range pins {
		clean := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		if clean == "" {
			continue
		}
		raw, err := hex.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("utls: pin %q is not hex: %w", p, err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("utls: pin %q is %d bytes, want %d", p, len(raw), sha256.Size)
		}
		out = append(out, raw)
	}
	return out, nil
}

// pinnedLeaf answers whether the certificate the connection was established
// with is one of the pinned keys. The chain has already been verified by the
// time this runs, so a pin only narrows what is accepted.
//
// It takes the parsed chain rather than raw DER because that is what both
// callbacks get on a connection that resumed: the certificates come from the
// stored session, not from the wire.
func pinnedLeaf(pins [][]byte, chain []*x509.Certificate) error {
	if len(chain) == 0 || chain[0] == nil {
		return ErrPinMismatch
	}
	sum := sha256.Sum256(chain[0].RawSubjectPublicKeyInfo)
	for _, pin := range pins {
		if len(pin) == len(sum) && subtleEqual(pin, sum[:]) {
			return nil
		}
	}
	return ErrPinMismatch
}

// subtleEqual compares two hashes. They are public values, so this is about
// being explicit rather than about timing.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// fingerprintToClientHelloID maps friendly names to uTLS ClientHelloIDs.
func fingerprintToClientHelloID(fp string) utls.ClientHelloID {
	switch fp {
	case FPChrome:
		return utls.HelloChrome_Auto
	case FPFirefox:
		return utls.HelloFirefox_Auto
	case FPSafari:
		return utls.HelloSafari_Auto
	case FPIOS:
		return utls.HelloIOS_Auto
	case FPDefaultGo:
		return utls.HelloGolang
	default:
		return utls.HelloChrome_Auto
	}
}
