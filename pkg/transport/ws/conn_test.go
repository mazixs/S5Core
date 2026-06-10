package ws

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestConn_Echo(t *testing.T) {
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Test decoy endpoint
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("decoy get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decoy status: %d", resp.StatusCode)
	}

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	clientConn, err := Dial(DialOpts{URL: wsURL})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	defer serverConn.Close()

	// Echo goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			if _, err := serverConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Send random payload
	want := make([]byte, 8192)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read exact echo back
	got := make([]byte, len(want))
	off := 0
	for off < len(got) {
		n, err := clientConn.Read(got[off:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		off += n
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch")
	}

	clientConn.Close()
	wg.Wait()
}

func TestConn_PathMismatch(t *testing.T) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.Close()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/wrong"
	_, err := Dial(DialOpts{URL: wsURL})
	if err == nil {
		t.Fatal("expected error for wrong path")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "bad handshake") {
		t.Fatalf("unexpected error: %v", err)
	}
}

