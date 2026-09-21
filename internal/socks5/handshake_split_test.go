package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Механика бага из боевого отчета: клиент отправляет приветствие SOCKS5 и
// CONNECT одним Write. Сервер, читающий поток буферизованно и теряющий хвост
// буфера между стадиями, в этот момент замолкает навсегда - соединение висит
// до таймаута, в логе ничего нет.
//
// Тесты ниже фиксируют, что разбиение потока на пакеты не влияет на результат:
// поток байтов есть поток байтов, и ни одна стадия рукопожатия не имеет права
// считать, что пакет заканчивается ровно на ее границе.

const (
	splitUser = "foo"
	splitPass = "bar"
)

// handshakeStream builds the whole client side of a session as one byte slice:
// greeting, credentials, CONNECT and the first payload byte.
func handshakeStream(port uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{Socks5Version, 2, NoAuth, UserPassAuth})
	b.Write([]byte{userAuthVersion, byte(len(splitUser))})
	b.WriteString(splitUser)
	b.Write([]byte{byte(len(splitPass))})
	b.WriteString(splitPass)
	b.Write([]byte{Socks5Version, ConnectCommand, 0, 1, 127, 0, 0, 1})
	b.Write(binary.BigEndian.AppendUint16(nil, port))
	b.WriteString("ping")
	return b.Bytes()
}

// splitTestServer builds a server whose destination is an in-memory echo, so
// the test needs no network at all.
func splitTestServer(t testing.TB) *Server {
	t.Helper()
	srv, err := New(&Config{
		AuthMethods: []Authenticator{UserPassAuthenticator{Credentials: StaticCredentials{splitUser: splitPass}}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			near, far := halfClosablePipe()
			go func() {
				defer func() { _ = far.Close() }()
				_, _ = io.Copy(far, far)
			}()
			return near, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// halfClosablePipe returns a connected pair that supports CloseWrite, unlike
// net.Pipe. Without it the relay never learns that one side finished and the
// test hangs - which is real behaviour worth knowing about (see the half-close
// counter, plan task Ф1-5), but it is not what these tests are measuring.
func halfClosablePipe() (a, b net.Conn) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return &pipeConn{r: ar, w: aw}, &pipeConn{r: br, w: bw}
}

type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *pipeConn) CloseWrite() error           { return c.w.Close() }

func (c *pipeConn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}

func (c *pipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// runHandshake feeds the stream to the server in the given chunks and returns
// what the server answered, or an error if it went quiet.
func runHandshake(t *testing.T, srv *Server, chunks [][]byte) ([]byte, error) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.ServeConnContext(context.Background(), serverEnd)
	}()

	// Писать и читать нужно одновременно: net.Pipe не буферизует, а сервер
	// отвечает на приветствие раньше, чем дочитает CONNECT.
	writeErr := make(chan error, 1)
	go func() {
		for _, chunk := range chunks {
			if _, err := clientEnd.Write(chunk); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	_ = clientEnd.SetDeadline(time.Now().Add(2 * time.Second))

	// [5 auth] [1 status] [10 reply] [4 echo]
	reply := make([]byte, 2+2+10+4)
	_, readErr := io.ReadFull(clientEnd, reply)

	_ = clientEnd.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after the client closed: the relay is stuck")
	}
	if err := <-writeErr; err != nil && readErr == nil {
		return reply, err
	}
	return reply, readErr
}

func assertHandshakeSucceeded(t *testing.T, reply []byte, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: server went quiet: %v", what, err)
	}
	if reply[0] != Socks5Version || reply[1] != UserPassAuth {
		t.Fatalf("%s: bad method selection %v", what, reply[:2])
	}
	if reply[2] != userAuthVersion || reply[3] != authSuccess {
		t.Fatalf("%s: auth rejected %v", what, reply[2:4])
	}
	if reply[4] != Socks5Version || reply[5] != successReply {
		t.Fatalf("%s: CONNECT rejected %v", what, reply[4:14])
	}
	if got := string(reply[14:]); got != "ping" {
		t.Fatalf("%s: payload came back as %q, want %q", what, got, "ping")
	}
}

// TestHandshake_CoalescedInOneWrite is the exact shape of the field report:
// everything in a single write, which is what a client does when it pipelines
// CONNECT behind the greeting to save a round trip.
func TestHandshake_CoalescedInOneWrite(t *testing.T) {
	srv := splitTestServer(t)
	stream := handshakeStream(12345)

	reply, err := runHandshake(t, srv, [][]byte{stream})
	assertHandshakeSucceeded(t, reply, err, "coalesced handshake")
}

// TestHandshake_EveryFragmentation walks every single split point of the same
// stream. Any stage that assumes a read ends on its own boundary fails here,
// and the failure names the offset.
func TestHandshake_EveryFragmentation(t *testing.T) {
	srv := splitTestServer(t)
	stream := handshakeStream(12345)

	for at := 1; at < len(stream); at++ {
		chunks := [][]byte{stream[:at], stream[at:]}
		reply, err := runHandshake(t, srv, chunks)
		if err != nil {
			t.Fatalf("split after byte %d of %d: server went quiet: %v", at, len(stream), err)
		}
		assertHandshakeSucceeded(t, reply, nil, "split after byte "+itoa(at))
	}
}

// TestHandshake_ByteAtATime is the extreme case of the same property: one byte
// per write, which is what a hostile or badly written client looks like.
func TestHandshake_ByteAtATime(t *testing.T) {
	srv := splitTestServer(t)
	stream := handshakeStream(12345)

	chunks := make([][]byte, 0, len(stream))
	for i := range stream {
		chunks = append(chunks, stream[i:i+1])
	}

	reply, err := runHandshake(t, srv, chunks)
	assertHandshakeSucceeded(t, reply, err, "one byte per write")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// FuzzHandshakeParsing throws arbitrary bytes at the handshake parser. It does
// not assert on the reply - a malformed stream is supposed to be rejected. It
// asserts that the server neither panics nor hangs: a parser that blocks
// forever on a crafted length byte is a denial of service that no amount of
// timeout tuning fixes.
func FuzzHandshakeParsing(f *testing.F) {
	f.Add(handshakeStream(12345))
	f.Add([]byte{Socks5Version, 1, NoAuth})
	f.Add([]byte{Socks5Version, 1, UserPassAuth, userAuthVersion, 255})
	f.Add([]byte{Socks5Version, ConnectCommand, 0, 3, 255})
	f.Add([]byte{4, 1, 0, 1})
	f.Add([]byte{})

	srv := splitTestServer(f)

	f.Fuzz(func(t *testing.T, stream []byte) {
		clientEnd, serverEnd := net.Pipe()

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = srv.ServeConnContext(context.Background(), serverEnd)
		}()

		go func() {
			_ = clientEnd.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = clientEnd.Write(stream)
			// Дочитать все, что сервер успел ответить, иначе он заблокируется
			// на записи в непрочитанный net.Pipe и тест зависнет не из-за
			// разбора, а из-за самого теста.
			_, _ = io.Copy(io.Discard, clientEnd)
			_ = clientEnd.Close()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("handshake parser hung on %d bytes: %x", len(stream), stream)
		}
	})
}
