package ws

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// sniListener accepts one TLS connection and reports the name the client put
// in its ClientHello. It never completes the handshake: a name reaches
// GetCertificate before any certificate is chosen, which is exactly the point
// in the exchange this test is about.
func sniListener(t *testing.T) (addr string, names <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	seen := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn := tls.Server(conn, &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				select {
				case seen <- hello.ServerName:
				default:
				}
				return nil, errors.New("this listener only reads the ClientHello")
			},
		})
		_ = tlsConn.Handshake()
	}()
	return ln.Addr().String(), seen
}

func sniFor(t *testing.T, opts DialOpts) string {
	t.Helper()
	addr, names := sniListener(t)
	opts.URL = "wss://" + addr + "/ws"
	// The dial fails - the listener has no certificate - and the name is
	// already on the wire by then.
	if conn, err := Dial(opts); err == nil {
		_ = conn.Close()
		t.Fatal("the dial succeeded against a listener with no certificate")
	}
	select {
	case name := <-names:
		return name
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello arrived")
		return ""
	}
}

// Plan task Ф6-4: SERVER_NAME was read from the environment and never used,
// while the README said it was the SNI. It now is, on both TLS paths.
func TestServerNameReachesTheWire(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		name := fingerprint
		if name == "" {
			name = "crypto/tls"
		}
		t.Run(name, func(t *testing.T) {
			got := sniFor(t, DialOpts{
				ServerName:     "sni.example",
				TLSFingerprint: fingerprint,
			})
			if got != "sni.example" {
				t.Fatalf("the ClientHello carried %q, want sni.example", got)
			}
		})
	}
}

// Host still decides the SNI when nothing else does - that is the behaviour
// every existing deployment has - but it no longer overrules an explicit
// name. One setting doing two unrelated things is what the task removed.
func TestServerNameOutranksHost(t *testing.T) {
	cases := []struct {
		name string
		opts DialOpts
		want string
	}{
		{
			name: "host alone still moves the SNI",
			opts: DialOpts{Host: "fronted.example"},
			want: "fronted.example",
		},
		{
			name: "an explicit name wins",
			opts: DialOpts{Host: "fronted.example", ServerName: "sni.example"},
			want: "sni.example",
		},
		{
			// An IP literal is not a name, and Go does not put one in SNI.
			// The listener is on 127.0.0.1, so this is what "neither set"
			// looks like.
			name: "neither set falls back to the URL",
			opts: DialOpts{},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := c.opts
			opts.TLSFingerprint = "chrome"
			if got := sniFor(t, opts); got != c.want {
				t.Fatalf("the ClientHello carried %q, want %q", got, c.want)
			}
		})
	}
}
