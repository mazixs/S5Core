package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/mazixs/S5Core/internal/socks5"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeSeparatesHTTPDelayAndTLS(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "h1", true: "h2"}[h2], func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				_, _ = io.WriteString(w, "verified body")
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			tr, err := newTransport("", roots, true, h2, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: time.Second}
			for i := 0; i < 2; i++ {
				got := measure(context.Background(), client, server.URL)
				if got.Error != "" || got.Status != 200 || got.Bytes != 13 || got.SHA256 == "" {
					t.Fatalf("%+v", got)
				}
				if got.FirstResponseMS < 95 || got.TotalMS < got.FirstResponseMS || got.FirstResponseMS < got.TLSMS+90 {
					t.Fatalf("HTTP wait hidden in TLS: %+v", got)
				}
				if got.Reused != (i > 0) {
					t.Fatalf("reuse: %+v", got)
				}
				if i > 0 && (got.TLSMS != 0 || got.SetupMS != 0) {
					t.Fatalf("reused request reports setup: %+v", got)
				}
				if got.ConnectionLocal != "" || got.ConnectionRemote != "" {
					t.Fatalf("addresses reported without -flow-context: %+v", got)
				}
			}
		})
	}
}

func TestProbeFlowContextNamesReusedConnection(t *testing.T) {
	peers := make(chan string, 2)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers <- r.RemoteAddr
		_, _ = io.WriteString(w, "body")
	}))
	defer origin.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if err := run([]string{"-url", origin.URL, "-ca", ca, "-count", "2", "-reuse", "-http2=false", "-flow-context"}, &out, &stderr); err != nil {
		t.Fatal(err, stderr.String())
	}
	var got []measurement
	for dec := json.NewDecoder(&out); dec.More(); {
		var m measurement
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	if len(got) != 2 || !got[1].Reused {
		t.Fatalf("two requests on one connection expected: %+v", got)
	}
	for _, m := range got {
		// The origin sees the probe's end of the connection as its peer.
		if peer := <-peers; m.ConnectionLocal != peer || m.ConnectionRemote != origin.Listener.Addr().String() {
			t.Fatalf("connection %s -> %s, origin saw %s -> %s", m.ConnectionLocal, m.ConnectionRemote, peer, origin.Listener.Addr())
		}
	}
}

func TestProbeThroughSOCKSAndTruncatedBody(t *testing.T) {
	// A loopback phase takes a fraction of a millisecond and can read as 0 on
	// Windows, whose monotonic clock moves in steps of 0.5 to 15.6 ms. Each
	// phase gets a sleep; the lengths differ so that swapped fields differ too.
	const (
		setupDelay = 20 * time.Millisecond
		tlsDelay   = 40 * time.Millisecond
		// The probe reports float64 milliseconds, whose sums and differences
		// round.
		rounding = 1e-6
	)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "partial")
	}))
	// Called once the origin has the ClientHello: inside the probe's handshake.
	origin.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		time.Sleep(tlsDelay)
		return nil, nil
	}}
	origin.StartTLS()
	defer origin.Close()
	server, err := socks5.New(&socks5.Config{
		// The CONNECT reply follows the dial, so the delay is part of setup.
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			time.Sleep(setupDelay)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeContext(ctx, listener) }()
	defer func() { cancel(); listener.Close(); <-done }()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	tr, err := newTransport(listener.Addr().String(), roots, false, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	got := measure(context.Background(), &http.Client{Transport: tr, Timeout: time.Second}, origin.URL)
	if got.Error == "" || got.Bytes != 7 || got.SHA256 != "" || got.Status != 200 {
		t.Fatalf("%+v", got)
	}
	// A span that contains a sleep is not shorter than it on the clock the
	// sleep runs on, however coarse that clock is.
	if got.SetupMS < milliseconds(setupDelay) || got.TLSMS < milliseconds(tlsDelay) {
		t.Fatalf("a delay is missing from its phase: %+v", got)
	}
	// Setup and TLS do not overlap, so what the first byte waited for beyond
	// one of them still holds the delay of the other.
	if got.FirstResponseMS-got.TLSMS < milliseconds(setupDelay)-rounding ||
		got.FirstResponseMS-got.SetupMS < milliseconds(tlsDelay)-rounding {
		t.Fatalf("a delay is counted in the other phase: %+v", got)
	}
}
