package ws

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDialContextCancelsUpgrade(t *testing.T) {
	for _, fp := range []string{"", "chrome"} {
		t.Run("fingerprint="+fp, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
			defer server.Close()
			defer close(release)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, err := DialContext(ctx, DialOpts{URL: strings.Replace(server.URL, "https:", "wss:", 1), RootCAs: roots, TLSFingerprint: fp})
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("upgrade not reached: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("upgrade not reached")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("wrong cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt Upgrade")
			}
		})
	}
}

func TestDialContextBoundsDNS(t *testing.T) {
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	defer func() { net.DefaultResolver = old }()
	for _, fp := range []string{"", "chrome"} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		c, err := DialContext(ctx, DialOpts{URL: "wss://pending.invalid/ws", TLSFingerprint: fp})
		cancel()
		if c != nil {
			c.Close()
		}
		if err == nil || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("fp=%s elapsed=%v err=%v", fp, time.Since(start), err)
		}
	}
}

func TestDialContextBoundsUpgrade(t *testing.T) {
	for _, fp := range []string{"", "chrome"} {
		t.Run("fingerprint="+fp, func(t *testing.T) {
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
			defer server.Close()
			defer close(release)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			c, err := DialContext(ctx, DialOpts{URL: strings.Replace(server.URL, "https:", "wss:", 1), RootCAs: roots, TLSFingerprint: fp})
			if c != nil {
				c.Close()
			}
			if err == nil || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("elapsed=%v err=%v", time.Since(start), err)
			}
		})
	}
}
