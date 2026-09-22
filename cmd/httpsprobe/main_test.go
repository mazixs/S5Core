package main

import (
	"context"
	"crypto/x509"
	"github.com/mazixs/S5Core/internal/socks5"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
			}
		})
	}
}

func TestProbeThroughSOCKSAndTruncatedBody(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "partial")
	}))
	defer origin.Close()
	server, err := socks5.New(&socks5.Config{})
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
	if got.Error == "" || got.Bytes != 7 || got.SHA256 != "" || got.SetupMS <= 0 || got.TLSMS <= 0 || got.Status != 200 {
		t.Fatalf("%+v", got)
	}
}
