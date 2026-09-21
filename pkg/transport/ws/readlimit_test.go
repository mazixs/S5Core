package ws

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// F05 in docs/reports/code-quality-audit-2026-09-20.md: the adapter used to
// read a whole WebSocket message into memory before returning any of it, and
// parked whatever did not fit in the caller's buffer for later. Nothing above
// this layer has authenticated the peer at that point, so the peer chose how
// much memory the server allocated. These tests are about the two halves of
// the fix: a read holds no more than the caller asked for, and a message
// larger than this protocol ever sends is refused rather than assembled.

// wsPairLimited is wsPair with a message limit on each end, in the form the
// options take it: zero means the default, negative means none.
func wsPairLimited(t *testing.T, serverLimit, clientLimit int64) (client, server *Conn) {
	t.Helper()

	up := NewUpgrader(UpgraderOpts{Path: "/ws", ReadLimit: serverLimit})
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
	client, err := Dial(DialOpts{URL: wsURL, ReadLimit: clientLimit})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server = <-serverConnCh
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// heapHeld is the live heap after two collections, which is as close as the
// runtime lets a test get to "how much is still referenced".
func heapHeld() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// A reader that asks for one byte gets one byte and owes nothing for the
// rest of the message. The number this test watches is memory, because that
// is what the defect was: reading the message ahead of the caller is only
// visible as the bytes it leaves behind.
func TestAReaderDoesNotHoldAMessageItHasNotBeenAskedFor(t *testing.T) {
	const (
		conns   = 24
		message = 512 * 1024
		// Buffering every message would hold conns*message = 12 MiB. Not
		// buffering holds gorilla's own read buffer per connection, some
		// kilobytes. The threshold sits between the two orders of magnitude
		// rather than close to either, so that the test fails on the defect
		// and not on an allocator's mood.
		budget = 2 << 20
	)

	payload := make([]byte, message)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload: %v", err)
	}

	base := heapHeld()

	clients := make([]*Conn, 0, conns)
	for i := 0; i < conns; i++ {
		client, server := wsPairLimited(t, 0, 0)
		go func() {
			// The far end may never drain this; the write fails at cleanup
			// and that is the point of the test.
			_, _ = server.Write(payload)
		}()

		one := make([]byte, 1)
		if _, err := client.Read(one); err != nil {
			t.Fatalf("connection %d: read one byte: %v", i, err)
		}
		if one[0] != payload[0] {
			t.Fatalf("connection %d: read %#x, want %#x", i, one[0], payload[0])
		}
		clients = append(clients, client)
	}

	held := heapHeld() - base
	runtime.KeepAlive(clients)

	if held > budget {
		t.Fatalf("%d connections that read one byte each hold %d KiB; "+
			"one byte of a %d KiB message should leave the rest on the wire, "+
			"so anything near %d KiB means the message was assembled in memory",
			conns, held/1024, message/1024, conns*message/1024)
	}
}

// The rest of the message is still there afterwards, and in order: streaming
// is not an excuse to lose bytes at a message boundary.
func TestReadingAMessageInPiecesYieldsTheWholeMessage(t *testing.T) {
	client, server := wsPairLimited(t, 0, 0)

	messages := [][]byte{
		bytes.Repeat([]byte{'a'}, 1),
		bytes.Repeat([]byte{'b'}, 17),
		bytes.Repeat([]byte{'c'}, 64*1024),
		bytes.Repeat([]byte{'d'}, 3),
	}
	var want []byte
	for _, m := range messages {
		want = append(want, m...)
	}

	go func() {
		for _, m := range messages {
			if _, err := server.Write(m); err != nil {
				return
			}
		}
	}()

	got := make([]byte, 0, len(want))
	buf := make([]byte, 7)
	for len(got) < len(want) {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read after %d of %d bytes: %v", len(got), len(want), err)
		}
		if n > len(buf) {
			t.Fatalf("read returned %d bytes into a buffer of %d", n, len(buf))
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream differs from what was written (%d bytes read)", len(got))
	}
}

// A message of zero bytes is a message, not the end of the connection. The
// old Read skipped it explicitly; the streaming one has to skip it too,
// because a reader that returned (0, nil) forever would spin and one that
// returned io.EOF would close a live tunnel.
func TestAnEmptyMessageDoesNotEndTheStream(t *testing.T) {
	client, server := wsPairLimited(t, 0, 0)

	go func() {
		if _, err := server.Write(nil); err != nil {
			return
		}
		_, _ = server.Write([]byte("after the empty one"))
	}()

	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read after an empty message: %v", err)
	}
	if got := string(buf[:n]); got != "after the empty one" {
		t.Fatalf("read %q, want the message that followed the empty one", got)
	}
}

// Only binary messages carry the tunnel. A text message from a peer that
// found the endpoint is skipped, not delivered as payload and not fatal.
func TestATextMessageIsNotPayload(t *testing.T) {
	client, server := wsPairLimited(t, 0, 0)

	go func() {
		if err := server.ws.WriteMessage(websocket.TextMessage, []byte("not payload")); err != nil {
			return
		}
		_, _ = server.Write([]byte("payload"))
	}()

	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read after a text message: %v", err)
	}
	if got := string(buf[:n]); got != "payload" {
		t.Fatalf("read %q, want the binary message", got)
	}
}

// The largest write this transport is asked to carry is one batch of
// obfuscated frames. pkg/obfs caps a batch at 32 KiB, and at a jumbo MTU the
// floor of its write buffer is two frames, some 128 KiB. This test writes
// twice that in one message, unshaped, and expects the default limit to pass
// it: a limit that refused our own traffic would be a denial of service we
// wrote ourselves.
func TestTheDefaultLimitPassesTheLargestBatchWeSend(t *testing.T) {
	const batch = 256 * 1024
	if batch >= DefaultReadLimit {
		t.Fatalf("the default limit %d no longer clears a %d byte batch", DefaultReadLimit, batch)
	}

	client, server := wsPairLimited(t, 0, 0)

	want := make([]byte, batch)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("payload: %v", err)
	}
	go func() { _, _ = server.Write(want) }()

	got := make([]byte, 0, batch)
	buf := make([]byte, 16*1024)
	for len(got) < batch {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read after %d of %d bytes: %v", len(got), batch, err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("a %d byte batch came back changed", batch)
	}
}

// Past the limit the reader fails instead of allocating. The peer here is
// unauthenticated as far as this layer knows, so the test states the
// property that matters: the refusal costs the reader nothing.
func TestAMessageOverTheLimitIsRefusedAndNotAssembled(t *testing.T) {
	const (
		limit   = 64 * 1024
		message = 8 * limit
		budget  = 2 * limit
	)

	client, server := wsPairLimited(t, 0, limit)

	go func() { _, _ = server.Write(make([]byte, message)) }()

	// Without a limit the message is merely large, and the read after it
	// blocks forever. The deadline turns that into this test's own failure
	// rather than the package timeout's.
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}

	base := heapHeld()
	buf := make([]byte, 4096)
	var err error
	for err == nil {
		_, err = client.Read(buf)
	}
	held := heapHeld()

	if !errors.Is(err, websocket.ErrReadLimit) {
		t.Fatalf("read of a %d byte message under a %d byte limit failed with %v, want %v",
			message, limit, err, websocket.ErrReadLimit)
	}
	if held > base+budget {
		t.Fatalf("refusing a %d byte message grew the heap by %d KiB; the limit "+
			"exists so the message is never assembled", message, (held-base)/1024)
	}
	runtime.KeepAlive(buf)
}

// The limit is the deployment's to set: a server whose clients batch more
// than the default can raise it, and one that trusts its peer can remove it.
// Both ends read the same option in the same way.
func TestTheMessageLimitIsAnOption(t *testing.T) {
	const message = 3 * DefaultReadLimit

	t.Run("a raised limit passes what the default would refuse", func(t *testing.T) {
		client, server := wsPairLimited(t, 0, 4*DefaultReadLimit)
		assertCarries(t, client, server, message)
	})

	t.Run("a negative limit removes it", func(t *testing.T) {
		client, server := wsPairLimited(t, 0, -1)
		assertCarries(t, client, server, message)
	})

	t.Run("the server end reads the same option", func(t *testing.T) {
		client, server := wsPairLimited(t, 1024, 0)
		go func() { _, _ = client.Write(make([]byte, 64*1024)) }()

		if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("read deadline: %v", err)
		}
		buf := make([]byte, 4096)
		var err error
		for err == nil {
			_, err = server.Read(buf)
		}
		if !errors.Is(err, websocket.ErrReadLimit) {
			t.Fatalf("server with a 1 KiB limit read a 64 KiB message with %v, want %v",
				err, websocket.ErrReadLimit)
		}
	})
}

// assertCarries writes n bytes one way and insists every one of them arrives.
func assertCarries(t *testing.T, dst, src *Conn, n int) {
	t.Helper()

	_ = dst.SetReadDeadline(time.Now().Add(30 * time.Second))
	go func() { _, _ = src.Write(make([]byte, n)) }()

	buf := make([]byte, 32*1024)
	read := 0
	for read < n {
		got, err := dst.Read(buf)
		if err != nil {
			t.Errorf("read after %d of %d bytes: %v", read, n, err)
			return
		}
		read += got
	}
}
