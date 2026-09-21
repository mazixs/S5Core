package ws

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/internal/utls"
)

// A pin is the one check in this dialer that the chain verification cannot
// make for it: it says which key, not merely which authority. TLS resumption
// is where such a check is easiest to lose, because a resumed handshake sends
// no certificate and therefore never reaches VerifyPeerCertificate - the
// callback the pin used to be installed on. Reported by gosec as G123.
//
// Resumption is not something this package turns on; an application that
// embeds the SDK turns it on by handing DialOpts a tls.Config with a
// ClientSessionCache, which is the only way to get it in Go. That is exactly
// what the stand below does.

// wssEcho runs a WebSocket server over TLS 1.3 and counts the handshakes that
// asked it for a certificate. A resumed handshake does not ask, so the
// counter is how a test tells the two apart without reaching inside the
// client's connection.
func wssEcho(t *testing.T) (url string, pool *x509.CertPool, leaf *x509.Certificate, certAsks *atomic.Int64) {
	t.Helper()

	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("test certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("loading the test certificate: %v", err)
	}
	leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the test certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(leaf)

	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()
	})

	certAsks = &atomic.Int64{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certAsks.Add(1)
				return &cert, nil
			},
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	return "wss://" + ln.Addr().String() + "/ws", pool, leaf, certAsks
}

func TestAResumedConnectionIsPinnedLikeAnyOther(t *testing.T) {
	url, pool, leaf, certAsks := wssEcho(t)

	// The application's own TLS configuration, with the session cache that
	// makes resumption possible in the first place. Both dials share it,
	// which is what an application that reuses one tls.Config does.
	cache := tls.NewLRUClientSessionCache(8)
	dial := func(pin string) (*Conn, error) {
		return Dial(DialOpts{
			URL:       url,
			RootCAs:   pool,
			PinSHA256: []string{pin},
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientSessionCache: cache},
		})
	}

	// First connection: a full handshake against the pinned key, and a round
	// trip afterwards so that the session ticket the server sends after the
	// handshake is read and cached.
	first, err := dial(utls.SPKIPin(leaf))
	if err != nil {
		t.Fatalf("the first connection to the pinned server failed: %v", err)
	}
	if _, err := first.Write([]byte("ticket, please")); err != nil {
		t.Fatalf("writing to the server: %v", err)
	}
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len("ticket, please"))
	if _, err := io.ReadFull(first, buf); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	_ = first.Close()
	if got := certAsks.Load(); got != 1 {
		t.Fatalf("the first handshake asked for a certificate %d times, want once", got)
	}

	// Second connection: same cache, a pin the server's key does not match -
	// an application that rotated its pins, or a cache shared with a dial
	// that was never pinned at all. The connection must be refused.
	second, err := dial(utls.SPKIPin(otherLeaf(t)))
	if err == nil {
		_ = second.Close()
		t.Fatal("a connection resumed from a session ticket was accepted against a pin it does not match")
	}
	if !errors.Is(err, utls.ErrPinMismatch) {
		t.Fatalf("the refusal is not a pin mismatch: %v", err)
	}

	// And it was refused on a resumed handshake, not on a full one: had the
	// server been asked for its certificate again, this test would have
	// proved nothing about resumption.
	if got := certAsks.Load(); got != 1 {
		t.Fatalf("the second handshake was a full one (the server was asked for a certificate %d times), "+
			"so the session was not resumed and this test checked nothing", got)
	}
}

// otherLeaf is a certificate from somewhere else, used for a pin that cannot
// match.
func otherLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("second test certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("loading the second test certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the second test certificate: %v", err)
	}
	return leaf
}

// Pinning goes on VerifyConnection, and that field may already hold a check
// the embedding application installed in its own tls.Config. Replacing it
// would silently drop a verification the caller asked for - a worse surprise
// than the one this fix is about - so the two are chained.
func TestTheCallersOwnConnectionCheckSurvivesPinning(t *testing.T) {
	url, pool, leaf, _ := wssEcho(t)

	t.Run("it still runs", func(t *testing.T) {
		var calls atomic.Int64
		conn, err := Dial(DialOpts{
			URL:       url,
			RootCAs:   pool,
			PinSHA256: []string{utls.SPKIPin(leaf)},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				VerifyConnection: func(tls.ConnectionState) error {
					calls.Add(1)
					return nil
				},
			},
		})
		if err != nil {
			t.Fatalf("the pinned dial failed: %v", err)
		}
		_ = conn.Close()
		if got := calls.Load(); got != 1 {
			t.Fatalf("the caller's own check ran %d times, want once", got)
		}
	})

	t.Run("and it can still refuse", func(t *testing.T) {
		conn, err := Dial(DialOpts{
			URL:       url,
			RootCAs:   pool,
			PinSHA256: []string{utls.SPKIPin(leaf)},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				VerifyConnection: func(tls.ConnectionState) error {
					return errors.New("the caller said no")
				},
			},
		})
		if err == nil {
			_ = conn.Close()
			t.Fatal("a connection the caller's own check refused was made anyway")
		}
		if !strings.Contains(err.Error(), "the caller said no") {
			t.Fatalf("the refusal lost the caller's reason: %v", err)
		}
	})
}
