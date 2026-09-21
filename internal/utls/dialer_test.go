package utls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
)

// tlsServer starts a TLS listener with a freshly generated self-signed
// certificate and returns its address and the pool that trusts it.
func tlsServer(t *testing.T) (addr string, pool *x509.CertPool, leaf *x509.Certificate) {
	t.Helper()

	dir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(dir)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("certificate did not go into the pool")
	}
	leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// Complete the handshake, then wait to be closed.
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = conn.Read(make([]byte, 1))
			}()
		}
	}()

	return ln.Addr().String(), pool, leaf
}

func dial(t *testing.T, addr string, opts Options) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return DialContext(ctx, "tcp", addr, opts)
}

// The dialer used to set InsecureSkipVerify, so this handshake succeeded
// against any certificate anyone cared to present - on the one transport whose
// entire purpose is to be indistinguishable from ordinary HTTPS.
func TestHandshakeRejectsAnUntrustedCertificate(t *testing.T) {
	addr, _, _ := tlsServer(t)

	conn, err := dial(t, addr, Options{Fingerprint: FPChrome})
	if err == nil {
		_ = conn.Close()
		t.Fatal("handshake accepted a certificate signed by nobody")
	}
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if !errors.As(err, &unknown) && !errors.As(err, &hostErr) {
		t.Fatalf("expected a certificate verification error, got %v", err)
	}
}

// Naming the deployment's own CA is how a self-signed server is trusted.
func TestHandshakeAcceptsTheNamedCertificateAuthority(t *testing.T) {
	addr, pool, _ := tlsServer(t)

	conn, err := dial(t, addr, Options{Fingerprint: FPChrome, RootCAs: pool})
	if err != nil {
		t.Fatalf("handshake against the trusted certificate failed: %v", err)
	}
	_ = conn.Close()
}

// A pin is an extra condition on top of a verified chain: the certificate
// below is perfectly valid, it is simply not the one that was pinned. This is
// the substituted-certificate case from the plan.
func TestHandshakeRejectsASubstitutedCertificate(t *testing.T) {
	addr, pool, _ := tlsServer(t)
	_, _, other := tlsServer(t)

	conn, err := dial(t, addr, Options{
		Fingerprint: FPChrome,
		RootCAs:     pool,
		PinSHA256:   []string{SPKIPin(other)},
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("handshake accepted a certificate that does not match the pin")
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("expected a pin mismatch, got %v", err)
	}
}

func TestHandshakeAcceptsTheMatchingPin(t *testing.T) {
	addr, pool, leaf := tlsServer(t)

	// Written the way a human copies a fingerprint: upper case, with colons.
	pin := strings.ToUpper(SPKIPin(leaf))
	var spaced strings.Builder
	for i := 0; i < len(pin); i += 2 {
		if i > 0 {
			spaced.WriteByte(':')
		}
		spaced.WriteString(pin[i : i+2])
	}

	conn, err := dial(t, addr, Options{
		Fingerprint: FPChrome,
		RootCAs:     pool,
		PinSHA256:   []string{spaced.String()},
	})
	if err != nil {
		t.Fatalf("handshake against the pinned certificate failed: %v", err)
	}
	_ = conn.Close()
}

// A pin that cannot be a pin is a configuration error, and it is reported
// before the connection is made rather than silently ignored - a silently
// ignored pin is worse than no pin, because it is believed.
func TestMalformedPinIsRejectedUpFront(t *testing.T) {
	for _, bad := range []string{"not-hex", "abcd"} {
		if _, err := NewPinChecker([]string{bad}); err == nil {
			t.Fatalf("pin %q was accepted", bad)
		}
	}
	check, err := NewPinChecker(nil)
	if err != nil {
		t.Fatalf("empty pin list: %v", err)
	}
	if check != nil {
		t.Fatal("empty pin list produced a checker")
	}
}
