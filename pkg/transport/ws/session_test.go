package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/utls"
	utlslib "github.com/refraction-networking/utls"
)

func echoTicket(t testing.TB, c *Conn) bool {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e := c.Write([]byte("ticket")); e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadFull(c, make([]byte, 6)); e != nil {
		t.Fatal(e)
	}
	switch raw := c.ws.UnderlyingConn().(type) {
	case *tls.Conn:
		return raw.ConnectionState().DidResume
	case *utlslib.UConn:
		return raw.ConnectionState().DidResume
	default:
		t.Fatalf("unexpected TLS stack %T", raw)
	}
	return false
}
func TestDialerResumptionAndTrustIsolation(t *testing.T) {
	for _, fp := range []string{"", "go", "chrome", "firefox", "safari", "ios"} {
		t.Run("fp="+fp, func(t *testing.T) {
			url, roots, leaf, _ := wssEcho(t)
			opts := DialOpts{URL: url, RootCAs: roots, PinSHA256: []string{utls.SPKIPin(leaf)}, TLSFingerprint: fp}
			dialer := NewDialer(opts)
			for i := 0; i < 2; i++ {
				c, e := dialer.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				resumed := echoTicket(t, c)
				if i == 0 && resumed {
					t.Fatal("fresh cache resumed")
				}
				if i == 1 && (fp == "" || fp == "go") && !resumed {
					t.Fatal("second connection did not resume")
				}
			}
			// A new immutable policy must not inherit the previous session's trust.
			for _, change := range []func(*DialOpts){func(o *DialOpts) { o.PinSHA256 = []string{utls.SPKIPin(otherLeaf(t))} }, func(o *DialOpts) { o.RootCAs = x509.NewCertPool() }, func(o *DialOpts) { o.ServerName = "wrong.invalid" }} {
				next := opts
				change(&next)
				c, e := NewDialer(next).DialContext(context.Background())
				if e == nil {
					_ = c.Close()
					t.Fatal("changed trust accepted old session")
				}
			}
			// The original options and pin slice cannot mutate the dialer's snapshot.
			opts.PinSHA256[0] = utls.SPKIPin(otherLeaf(t))
			opts.RootCAs = x509.NewCertPool()
			c, e := dialer.DialContext(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			echoTicket(t, c)
		})
	}
}

func BenchmarkWSSHandshake(b *testing.B) {
	for _, cache := range []bool{false, true} {
		name := "full"
		if cache {
			name = "resumed"
		}
		b.Run(name, func(b *testing.B) {
			url, roots, leaf, _ := wssEcho(b)
			opts := DialOpts{URL: url, RootCAs: roots, PinSHA256: []string{utls.SPKIPin(leaf)}}
			dial := func() (*Conn, error) { return Dial(opts) }
			if cache {
				d := NewDialer(opts)
				dial = func() (*Conn, error) { return d.DialContext(context.Background()) }
			}
			c, e := dial()
			if e != nil {
				b.Fatal(e)
			}
			echoTicket(b, c)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				c, e := dial()
				if e != nil {
					b.Fatal(e)
				}
				if resumed := echoTicket(b, c); resumed != cache {
					b.Fatalf("DidResume=%v, cache=%v", resumed, cache)
				}
			}
		})
	}
}

// Exercise the verification callback even if a caller deliberately reuses the
// underlying uTLS cache against a different pin. NewDialer normally isolates it.
func TestUTLSResumedSessionStillChecksPin(t *testing.T) {
	url, roots, leaf, asks := wssEcho(t)
	dialer := NewDialer(DialOpts{URL: url, RootCAs: roots, PinSHA256: []string{utls.SPKIPin(leaf)}, TLSFingerprint: "go"})
	c, e := dialer.DialContext(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	echoTicket(t, c)
	before := asks.Load()
	dialer.opts.PinSHA256 = []string{utls.SPKIPin(otherLeaf(t))}
	c, e = dialer.DialContext(context.Background())
	if c != nil {
		_ = c.Close()
	}
	if !errors.Is(e, utls.ErrPinMismatch) {
		t.Fatalf("resumed pin check: %v", e)
	}
	if asks.Load() != before {
		t.Fatal("test performed a full handshake instead of resumption")
	}
}
