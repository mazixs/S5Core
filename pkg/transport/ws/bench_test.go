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

	var wr io.Writer = serverConn
	var rd io.Reader = clientConn
	if shaped {
		wr = NewShapedConn(serverConn, 512, 4096, 0)
		rd = NewShapedConn(clientConn, 512, 4096, 0)
	}

	// Drain reader
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			_, err := rd.Read(buf)
			if err != nil {
				return
			}
		}
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
	b.StopTimer()

	clientConn.Close()
	<-done
}

func BenchmarkThroughput_PlainWS(b *testing.B) {
	benchmarkShapedThroughput(b, false)
}

func BenchmarkThroughput_ShapedWS(b *testing.B) {
	benchmarkShapedThroughput(b, true)
}

func BenchmarkShapedWriteSizes(b *testing.B) {
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

	shaped := NewShapedConn(clientConn, 512, 4096, 0)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	payload := make([]byte, 32*1024)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := shaped.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}
