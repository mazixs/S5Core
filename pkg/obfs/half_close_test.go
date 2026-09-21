package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Plan task Ф4-9. The half-close has to mean the same thing on every
// transport this layer can sit on, which is why it is a frame and not a
// syscall: TCP underneath could carry a real FIN, a WebSocket could not, and
// a tunnel that ends a stream one way on one transport and another way on the
// other ends it correctly on neither.

func halfClosePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	return obfsPair(t, Config{PSK: bytes.Repeat([]byte("k"), 32), MTU: DefaultMTU})
}

func closeWrite(t *testing.T, c net.Conn) {
	t.Helper()
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("an obfuscated connection does not offer CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

func TestClosingOneHalfEndsTheOtherSidesRead(t *testing.T) {
	client, server := halfClosePair(t)

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	closeWrite(t, client)

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != "request" {
		t.Fatalf("server read %q, want %q", got, "request")
	}
}

func TestTheOtherDirectionSurvivesAHalfClose(t *testing.T) {
	client, server := halfClosePair(t)

	if _, err := client.Write([]byte("question")); err != nil {
		t.Fatalf("write: %v", err)
	}
	closeWrite(t, client)

	// The server drains to the end of the stream, exactly as a protocol that
	// answers only once the request is complete would, and then answers.
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := io.ReadAll(server); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if _, err := server.Write([]byte("answer")); err != nil {
		t.Fatalf("server write after the client's half-close: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, len("answer"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "answer" {
		t.Fatalf("client read %q, want %q", buf, "answer")
	}
}

func TestWritingAfterAHalfCloseIsRefused(t *testing.T) {
	client, _ := halfClosePair(t)

	closeWrite(t, client)

	if _, err := client.Write([]byte("late")); !errors.Is(err, errWriteClosed) {
		t.Fatalf("Write after CloseWrite = %v, want %v", err, errWriteClosed)
	}
	// Closing the same half twice is what a relay does when both directions
	// end at once, and it is not an error.
	closeWrite(t, client)
}

func TestAHalfCloseIsTheSizeOfARealFrame(t *testing.T) {
	// A FIN that went out as a short frame would be a marker an observer
	// could find without decrypting anything: the last frame of every stream,
	// always the same length.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_, _ = io.Copy(io.Discard, raw)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	log := &writeLog{Conn: raw}
	c, err := NewClientConn(log, Config{PSK: bytes.Repeat([]byte("k"), 32), MTU: DefaultMTU})
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}

	if _, err := c.Write(bytes.Repeat([]byte("x"), 1200)); err != nil {
		t.Fatalf("write: %v", err)
	}
	beforeSizes, _ := log.snapshot()
	closeWrite(t, c)

	after, _ := log.snapshot()
	if len(after) != len(beforeSizes)+1 {
		t.Fatalf("CloseWrite produced %d writes, want 1", len(after)-len(beforeSizes))
	}
	fin := after[len(after)-1]
	data := beforeSizes[len(beforeSizes)-1]
	if fin < data/2 {
		t.Fatalf("the FIN frame is %d bytes against a data frame of %d: it stands out by length", fin, data)
	}
	t.Logf("FIN frame %d bytes, data frame %d bytes", fin, data)
}

func TestAClientThatNeverWroteStillSendsItsSalt(t *testing.T) {
	// The salt rides in front of the first frame. A client that closes its
	// write half without having written anything still has to send it, or the
	// peer has no keys to open the FIN with and reads a stream that never
	// starts.
	client, server := halfClosePair(t)

	closeWrite(t, client)

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, err := server.Read(make([]byte, 16))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("server read = %d, %v; want 0, EOF", n, err)
	}
}
