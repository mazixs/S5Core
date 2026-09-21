package ws

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Plan task Ф4-6. The decision made in pkg/obfs - serialise a connection with
// a mutex per direction rather than with a writer goroutine and a queue - has
// to hold for this layer too, and the plan is explicit that it is one decision
// for both. It already did here: Conn.Write and ShapedConn.Write each hold a
// mutex, which is why gorilla/websocket, a library that takes one writer at a
// time, is safe underneath and does not need replacing. These tests pin that
// rather than leaving it to be read out of the code, and they are the ones the
// keepalive work (Ф4-8) will lean on when it starts writing ping frames from a
// timer goroutine.

func wsPair(t *testing.T) (client, server *Conn) {
	t.Helper()

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
	t.Cleanup(srv.Close)

	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"
	client, err := Dial(DialOpts{URL: wsURL})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server = <-serverConnCh
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// writeConcurrently sends tagged messages from several goroutines and checks
// that the stream on the other side is a sequence of whole messages: a frame
// assembled from two writers at once would show up as a chunk carrying two
// tags. Run under -race, it also covers the library's own writer state.
func writeConcurrently(t *testing.T, w io.Writer, r io.Reader, writers, messages, msgLen int) {
	t.Helper()

	want := make(map[byte][]byte, writers)
	for i := 0; i < writers; i++ {
		tag := byte('A' + i)
		want[tag] = bytes.Repeat([]byte{tag}, msgLen)
	}

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, writers*messages*msgLen)
		n, _ := io.ReadFull(r, buf)
		received <- buf[:n]
	}()

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(tag byte) {
			defer wg.Done()
			for j := 0; j < messages; j++ {
				if _, err := w.Write(want[tag]); err != nil {
					t.Errorf("writer %c: %v", tag, err)
					return
				}
			}
		}(byte('A' + i))
	}
	wg.Wait()

	stream := <-received
	if len(stream) != writers*messages*msgLen {
		t.Fatalf("the reader got %d bytes, want %d", len(stream), writers*messages*msgLen)
	}

	counts := make(map[byte]int)
	for off := 0; off < len(stream); off += msgLen {
		chunk := stream[off : off+msgLen]
		expected, ok := want[chunk[0]]
		if !ok {
			t.Fatalf("the message at offset %d starts with %q, which no writer sent", off, chunk[0])
		}
		if !bytes.Equal(chunk, expected) {
			t.Fatalf("the message at offset %d mixes %q with another writer's bytes", off, chunk[0])
		}
		counts[chunk[0]]++
	}
	for tag, n := range counts {
		if n != messages {
			t.Fatalf("writer %c has %d messages in the stream, want %d", tag, n, messages)
		}
	}
}

func TestTwoGoroutinesCanWriteToOneWebSocket(t *testing.T) {
	client, server := wsPair(t)
	writeConcurrently(t, client, server, 4, 50, 2000)
}

// The shaper is the layer that will carry keepalive traffic beside payload
// traffic, and it splits one write into several frames, so an unserialised
// writer would interleave halves of two messages rather than whole ones.
func TestTwoGoroutinesCanWriteThroughTheShaper(t *testing.T) {
	client, server := wsPair(t)
	shaped := NewShapedConn(client, 512, 1024, 0)
	writeConcurrently(t, shaped, server, 4, 50, 4000)
}
