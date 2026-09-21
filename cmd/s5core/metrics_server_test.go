package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Plan task Ф6-5: the metrics endpoint used to live on http.DefaultServeMux,
// which any package in the binary can add to. A handler registered there must
// not appear on this port - that is the whole difference between a mux of our
// own and the global one.
func TestTheMetricsPortServesOnlyItsOwnPaths(t *testing.T) {
	http.HandleFunc("/leaked-by-some-other-package", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this should never be reachable on the metrics port"))
	})

	srv := newMetricsServer("")
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.Start()
	t.Cleanup(ts.Close)

	get := func(path string) int {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := get("/health"); code != http.StatusOK {
		t.Errorf("/health answered %d, want 200", code)
	}
	if code := get("/metrics"); code != http.StatusOK {
		t.Errorf("/metrics answered %d, want 200", code)
	}
	if code := get("/leaked-by-some-other-package"); code != http.StatusNotFound {
		t.Fatalf("a handler registered on the default mux answered %d on the metrics port", code)
	}
	// The most likely thing to arrive on the default mux by accident is
	// net/http/pprof, which publishes the heap and the goroutine dump.
	if code := get("/debug/pprof/"); code != http.StatusNotFound {
		t.Fatalf("/debug/pprof answered %d on the metrics port", code)
	}
}

// A connection that opens and sends nothing must be dropped, not held. The
// default http.Server has no header timeout at all, so this used to be a
// goroutine per silent connection for as long as the peer cared to keep it.
func TestASilentClientIsDroppedByTheHeaderTimeout(t *testing.T) {
	if _, ci := os.LookupEnv("CI"); ci && testing.Short() {
		t.Skip("timing test")
	}
	srv := newMetricsServer("")
	if srv.ReadHeaderTimeout == 0 {
		t.Fatal("the metrics server has no ReadHeaderTimeout")
	}
	// The default is seconds, which is right in production and too long for a
	// test: what is being checked is that the timeout exists and closes the
	// connection, not its value.
	srv.ReadHeaderTimeout = 150 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Say the first word of a request and then go quiet, which is what a
	// Slowloris does.
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	buf := make([]byte, 512)
	start := time.Now()
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the server held a silent connection open")
			}
			break // EOF or reset: the server dropped it, which is the point
		}
		if n > 0 && time.Since(start) > 4*time.Second {
			t.Fatal("the server kept answering a request that never finished")
		}
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the silent connection was held for %v", elapsed)
	}
}

func TestTheMetricsServerHasEveryTimeoutSet(t *testing.T) {
	srv := newMetricsServer("127.0.0.1:0")
	for _, c := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout},
		{"IdleTimeout", srv.IdleTimeout},
	} {
		if c.got <= 0 {
			t.Errorf("%s is not set", c.name)
		}
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is not set")
	}
	if srv.Handler == nil {
		t.Fatal("the server has no handler of its own, so it falls back to the default mux")
	}
}
