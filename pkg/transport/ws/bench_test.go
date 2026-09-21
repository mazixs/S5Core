package ws

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func benchmarkShapedThroughput(b *testing.B, shaped bool) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	serverConnCh := make(chan *Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		serverConnCh <- c
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	clientConn, err := Dial(DialOpts{URL: wsURL})
	if err != nil {
		b.Fatal(err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Minute))
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Minute))

	var wr io.Writer = serverConn
	var rd io.Reader = clientConn
	if shaped {
		wr = NewShapedConn(serverConn, DefaultMinFrame, DefaultMaxFrame, 0)
		rd = NewShapedConn(clientConn, DefaultMinFrame, DefaultMaxFrame, 0)
	}

	// Loopback WS only (no TLS). Count delivery, not just buffered writes.
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, rd, int64(b.N)*(1024*1024))
		done <- err
	}()

	payload := make([]byte, 1024*1024) // 1 MB
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := wr.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
}

func BenchmarkThroughput_PlainWS(b *testing.B) {
	benchmarkShapedThroughput(b, false)
}

func BenchmarkThroughput_ShapedWS(b *testing.B) {
	benchmarkShapedThroughput(b, true)
}

// The shaping budget in the plan is stated in bandwidth and latency, so the
// second pair of benchmarks measures a single interactive write - one
// obfuscated frame at the default MTU - rather than a megabyte at a time.
// What the histogram of the resulting frame lengths looks like is a question
// about the result rather than the speed, and it is asked in shaping_test.go.
func benchmarkWriteLatency(b *testing.B, shaped bool) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	serverConnCh := make(chan *Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		serverConnCh <- c
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	clientConn, err := Dial(DialOpts{URL: wsURL})
	if err != nil {
		b.Fatal(err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Minute))
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Minute))

	var wr io.Writer = clientConn
	if shaped {
		wr = NewShapedConn(clientConn, DefaultMinFrame, DefaultMaxFrame, 0)
	}

	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, serverConn, int64(b.N)*1422)
		done <- err
	}()

	// One obfuscated frame carrying a full MTU of payload.
	payload := make([]byte, 1422)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := wr.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	// This benchmark explicitly measures local Write latency. Delivery is
	// still checked before closing, but is outside that measurement.
	if err := <-done; err != nil {
		b.Fatal(err)
	}
}

func BenchmarkWriteLatency_PlainWS(b *testing.B) {
	benchmarkWriteLatency(b, false)
}

func BenchmarkWriteLatency_ShapedWS(b *testing.B) {
	benchmarkWriteLatency(b, true)
}
