package ws

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestShapedConn_Echo(t *testing.T) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	serverConnCh := make(chan *Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		serverConnCh <- c
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	clientConn, err := Dial(DialOpts{URL: wsURL})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	defer serverConn.Close()

	shapedClient := NewShapedConn(clientConn, 512, 2048, 2*time.Millisecond)
	shapedServer := NewShapedConn(serverConn, 512, 2048, 2*time.Millisecond)

	// Echo goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := shapedServer.Read(buf)
			if err != nil {
				return
			}
			if _, err := shapedServer.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	want := make([]byte, 16384)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if _, err := shapedClient.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(want))
	off := 0
	for off < len(got) {
		n, err := shapedClient.Read(got[off:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		off += n
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch")
	}

	shapedClient.Close()
	<-done
}
