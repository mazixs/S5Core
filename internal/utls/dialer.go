// Package utls provides a thin wrapper around refraction-networking/utls
// so the WebSocket dialer can perform browser-grade TLS handshakes.
package utls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint presets for JA3 mimicry.
const (
	FPChrome      = "chrome"
	FPFirefox     = "firefox"
	FPSafari      = "safari"
	FPIOS         = "ios"
	FPDefaultGo   = "go"
)

// DialContext dials TCP and performs a uTLS handshake using the specified
// browser fingerprint. The returned net.Conn is a *utls.UConn and satisfies
// the standard net.Conn interface.
func DialContext(ctx context.Context, network, addr string, serverName string, fp string) (net.Conn, error) {
	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("utls dial tcp: %w", err)
	}

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // caller should verify via Pin or proper CA
		MinVersion:         utls.VersionTLS13,
	}

	clientHelloID := fingerprintToClientHelloID(fp)
	uconn := utls.UClient(tcpConn, config, clientHelloID)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return uconn, nil
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

// ToStandardConfig converts a *tls.Config to a *utls.Config.
// This is a shallow copy; most fields are transferred directly.
func ToStandardConfig(cfg *tls.Config) *utls.Config {
	if cfg == nil {
		return nil
	}
	return &utls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             castCertificates(cfg.Certificates),
		RootCAs:                  cfg.RootCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		ServerName:               cfg.ServerName,
		ClientSessionCache:       nil, // not compatible
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsDisabled:   cfg.SessionTicketsDisabled,
	}
}

func castCertificates(certs []tls.Certificate) []utls.Certificate {
	if len(certs) == 0 {
		return nil
	}
	out := make([]utls.Certificate, len(certs))
	for i, c := range certs {
		out[i] = utls.Certificate{
			Certificate:                  c.Certificate,
			PrivateKey:                   c.PrivateKey,
			OCSPStaple:                   c.OCSPStaple,
			SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
			Leaf:                         c.Leaf,
		}
	}
	return out
}
