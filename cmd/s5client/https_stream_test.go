package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/s5server"
	"golang.org/x/net/proxy"
)

func streamPort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}
func streamPaths(t *testing.T, idle time.Duration) map[string]string {
	t.Helper()
	cert, key, e := testcert.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := s5server.DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.Port = streamPort(t)
	cfg.RequireAuth = false
	cfg.ReadTimeout = idle
	cfg.ObfsEnabled = true
	cfg.ObfsPort = streamPort(t)
	cfg.ObfsPSK = "0123456789abcdef0123456789abcdef"
	cfg.ObfsMaxPadding = 256
	cfg.ObfsMTU = 1400
	cfg.WSEnabled = true
	cfg.WSAddr = "127.0.0.1:" + streamPort(t)
	cfg.WSCertFile = cert
	cfg.WSKeyFile = key
	cfg.WSPath = "/ws"
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, e := s5server.NewServer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	t.Cleanup(func() { cancel(); srv.Stop(); <-done })
	for _, port := range []string{cfg.Port, cfg.ObfsPort} {
		for i := 0; i < 200; i++ {
			c, e := net.DialTimeout("tcp", "127.0.0.1:"+port, 20*time.Millisecond)
			if e == nil {
				c.Close()
				break
			}
			time.Sleep(10 * time.Millisecond)
			if i == 199 {
				t.Fatal(e)
			}
		}
	}
	out := map[string]string{"direct": "", "plain": "127.0.0.1:" + cfg.Port}
	for _, mode := range []string{"obfs", "obfs-keepalive", "obfs-keepalive-risk", "wss"} {
		cp := clientParams{ServerAddr: "127.0.0.1:" + cfg.ObfsPort, PSK: cfg.ObfsPSK, MTU: 1400, MaxPadding: 256, Prologue: "printable", Format: "v1", HandshakeTimeout: 5 * time.Second, DialTimeout: 5 * time.Second, Transport: "obfs"}
		if mode == "wss" {
			cp.Transport = "ws"
			cp.WSUrl = "wss://" + cfg.WSAddr + "/ws"
			cp.WSCAFile = cert
			cp.rootCAs = x509.NewCertPool()
			pemBytes, err := os.ReadFile(cert)
			if err != nil || !cp.rootCAs.AppendCertsFromPEM(pemBytes) {
				t.Fatal("test CA", err)
			}
			cp.WSMinFrame = 256
			cp.WSMaxFrame = 4096
		}
		if mode == "obfs-keepalive-risk" {
			cp.KeepaliveMin = idle * 2 / 3
			cp.KeepaliveMax = idle * 2 / 3
		}
		if mode == "obfs-keepalive" {
			cp.KeepaliveMin = idle / 4
			cp.KeepaliveMax = idle / 3
		}
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		out[mode] = l.Addr().String()
		var wg sync.WaitGroup
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				wg.Add(1)
				go func() { defer wg.Done(); handleClient(c, cp, nil) }()
			}
		}()
		t.Cleanup(func() { l.Close(); <-closed; wg.Wait() })
	}
	return out
}
func streamTransport(t *testing.T, addr string, reuse bool) *http.Transport {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: !reuse, DisableCompression: true, ForceAttemptHTTP2: false}
	if addr != "" {
		d, e := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: 5 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		tr.DialContext = d.(proxy.ContextDialer).DialContext
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

// Real HTTPS bytes pass through the CLI relay and each server transport.
// The application is deliberately silent in one direction for four idle
// intervals. Neither framing nor keepalive is needed to sustain the stream.
func TestHTTPSActiveStreams(t *testing.T) {
	const idle = 500 * time.Millisecond
	paths := streamPaths(t, idle)
	for _, h2 := range []bool{false, true} {
		for _, upload := range []bool{false, true} {
			for _, mode := range []string{"plain", "obfs", "wss", "obfs-keepalive", "obfs-keepalive-risk"} {
				t.Run(fmt.Sprintf("h2=%v/upload=%v/%s", h2, upload, mode), func(t *testing.T) {
					t.Parallel()
					payload := bytes.Repeat([]byte("x"), 1024)
					const rounds = 40
					origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if upload {
							body, err := io.ReadAll(r.Body)
							if err != nil || !bytes.Equal(body, bytes.Repeat(payload, rounds)) {
								http.Error(w, "bad upload", 400)
								return
							}
							_, _ = w.Write([]byte("ok"))
							return
						}
						w.Header().Set("Content-Length", fmt.Sprint(rounds*len(payload)))
						for i := 0; i < rounds; i++ {
							if _, err := w.Write(payload); err != nil {
								return
							}
							w.(http.Flusher).Flush()
							select {
							case <-r.Context().Done():
								return
							case <-time.After(50 * time.Millisecond):
							}
						}
					}))
					origin.EnableHTTP2 = h2
					origin.StartTLS()
					defer origin.Close()
					tr := streamTransport(t, paths[mode], false)
					tr.ForceAttemptHTTP2 = h2
					client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
					var body io.Reader
					var writerDone chan struct{}
					if upload {
						r, w := io.Pipe()
						defer r.Close()
						body = r
						writerDone = make(chan struct{})
						go func() {
							defer close(writerDone)
							defer w.Close()
							for i := 0; i < rounds; i++ {
								if _, err := w.Write(payload); err != nil {
									return
								}
								time.Sleep(50 * time.Millisecond)
							}
						}()
						defer func() { _ = r.Close(); <-writerDone }()
					}
					req, err := http.NewRequest(http.MethodPost, origin.URL, body)
					if err != nil {
						t.Fatal(err)
					}
					start := time.Now()
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					received, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					expected := bytes.Repeat(payload, rounds)
					if upload {
						expected = []byte("ok")
					}
					if err != nil || resp.StatusCode != 200 || !bytes.Equal(received, expected) {
						t.Fatalf("status=%d bytes=%d err=%v", resp.StatusCode, len(received), err)
					}
					if (resp.ProtoMajor == 2) != h2 {
						t.Fatalf("wrong protocol: %s", resp.Proto)
					}
					if time.Since(start) < 3*idle {
						t.Fatal("stream did not cross enough idle intervals")
					}
				})
			}
		}
	}
}

func TestWSSConfiguredDialBudget(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		for _, handshake := range []bool{false, true} {
			t.Run(fmt.Sprintf("fp=%s/handshake=%v", fingerprint, handshake), func(t *testing.T) {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				accepted := make(chan net.Conn, 1)
				go func() {
					if c, e := l.Accept(); e == nil {
						accepted <- c
					}
				}()
				cfg := clientParams{Transport: "ws", WSUrl: "wss://" + l.Addr().String() + "/ws", TLSFingerprint: fingerprint, DialTimeout: 50 * time.Millisecond}
				if handshake {
					cfg.DialTimeout = time.Second
					cfg.HandshakeTimeout = 50 * time.Millisecond
				}
				start := time.Now()
				c, err := dialServer(cfg)
				if c != nil {
					c.Close()
				}
				select {
				case peer := <-accepted:
					defer peer.Close()
				case <-time.After(time.Second):
					t.Fatal("no accepted connection")
				}
				if err == nil || time.Since(start) > 500*time.Millisecond {
					t.Fatalf("elapsed=%v err=%v", time.Since(start), err)
				}
			})
		}
	}
}

func TestHTTPSDefaultReadTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("33-second default idle regression")
	}
	paths := streamPaths(t, 30*time.Second)
	payload := bytes.Repeat([]byte("x"), 1024)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(660*len(payload)))
		for i := 0; i < 660; i++ {
			if _, e := w.Write(payload); e != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-time.After(50 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer server.Close()
	tr := streamTransport(t, paths["plain"], false)
	client := &http.Client{Transport: tr, Timeout: 40 * time.Second}
	start := time.Now()
	r, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r.Body)
	r.Body.Close()
	elapsed := time.Since(start)
	t.Logf("DEFAULT_STREAM bytes=%d expected=%d elapsed=%s err=%v", len(b), 660*len(payload), elapsed, e)
	if e != nil || elapsed < 30*time.Second || !bytes.Equal(b, bytes.Repeat(payload, 660)) {
		t.Fatal("unexpected default-timeout behavior")
	}
}
