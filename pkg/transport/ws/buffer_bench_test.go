package ws

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func benchmarkPerfServerWrite(b *testing.B, size int) {
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

	wr := NewShapedConn(serverConn, DefaultMinFrame, DefaultMaxFrame, 0)
	rd := NewShapedConn(clientConn, DefaultMinFrame, DefaultMaxFrame, 0)

	// Loopback WS only (no TLS). Count delivery, not just buffered writes.
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, rd, int64(b.N)*int64(size))
		done <- err
	}()

	payload := make([]byte, size)
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

func BenchmarkPerfServerWrite(b *testing.B) {
	for _, size := range []int{1422, 22752, 1048576} {
		b.Run(fmt.Sprint(size), func(b *testing.B) { benchmarkPerfServerWrite(b, size) })
	}
}

func BenchmarkPerfUpgrade(b *testing.B) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	accepted := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := up.Upgrade(w, r)
		if e == nil {
			accepted <- c
		}
	}))
	defer srv.Close()
	url := strings.Replace(srv.URL, "http:", "ws:", 1) + "/ws"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, e := Dial(DialOpts{URL: url})
		if e != nil {
			b.Fatal(e)
		}
		s := <-accepted
		_ = c.Close()
		_ = s.Close()
	}
}
