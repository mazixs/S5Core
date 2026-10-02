package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// heldConn collects writes until release, then hands them to the peer in one
// write. The obfuscation reader takes everything the transport has in one
// read, so this is how a test makes the reply, the target's bytes and the FIN
// arrive as one batch - the shape that used to be read as data plus io.EOF.
type heldConn struct {
	net.Conn
	mu   sync.Mutex
	held bytes.Buffer
}

func (c *heldConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held.Write(p)
}

func (c *heldConn) release() error {
	c.mu.Lock()
	b := bytes.Clone(c.held.Bytes())
	c.held.Reset()
	c.mu.Unlock()
	_, err := c.Conn.Write(b)
	return err
}

var successReply = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

// A target that answers and closes at once must reach the application as a
// success, its bytes and the end of the stream (docs/plan/draft.md, Ч-22): the reply
// was read with one Read, which returns data together with io.EOF when the FIN
// is in the same batch, and any error was taken for a failed setup - so the
// application got 0x01 and the banner was lost.
func TestATargetThatAnswersAndClosesReachesTheApplication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  []byte
		banner string
	}{
		{"closes at once", successReply, ""},
		{"writes a banner and closes", successReply, "421 too many connections\r\n"},
		{"refuses and closes", []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := testClientParams()
				logs := captureLogs(t)

				original := dialServer
				t.Cleanup(func() { dialServer = original })

				serverSide := make(chan *heldConn, 1)
				dialServer = func(clientParams) (net.Conn, error) {
					local, remote := net.Pipe()
					t.Cleanup(func() {
						_ = local.Close()
						_ = remote.Close()
					})
					serverSide <- &heldConn{Conn: remote}
					return local, nil
				}

				app, client := net.Pipe()
				defer func() { _ = app.Close() }()

				done := make(chan struct{})
				go func() {
					defer close(done)
					handleClient(client, cfg, nil)
				}()

				writeErr := make(chan error, 1)
				go func() {
					_, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...))
					writeErr <- err
				}()
				var greetResp [2]byte
				if _, err := io.ReadFull(app, greetResp[:]); err != nil {
					t.Fatalf("greeting response: %v", err)
				}
				if err := <-writeErr; err != nil {
					t.Fatalf("application write: %v", err)
				}

				held := <-serverSide
				server := obfsServerSide(t, held, cfg)
				if _, err := io.ReadFull(server, make([]byte, 3+len(connectRequest()))); err != nil {
					t.Fatalf("server read of greeting and CONNECT: %v", err)
				}

				reply := tc.reply
				if _, err := server.Write(append([]byte{0x05, 0x00}, reply...)); err != nil {
					t.Fatalf("server greeting and CONNECT reply: %v", err)
				}
				if tc.banner != "" {
					if _, err := server.Write([]byte(tc.banner)); err != nil {
						t.Fatalf("server banner: %v", err)
					}
				}
				if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatalf("server FIN: %v", err)
				}
				go func() { _ = held.release() }()

				got := make([]byte, len(reply))
				if _, err := io.ReadFull(app, got); err != nil {
					t.Fatalf("the application got no reply: %v", err)
				}
				if !bytes.Equal(got, reply) {
					t.Fatalf("the application got %v, want the reply %v", got, reply)
				}
				rest, err := io.ReadAll(app)
				if err != nil {
					t.Fatalf("reading to the end of the stream: %v", err)
				}
				if string(rest) != tc.banner {
					t.Fatalf("the application got %q after the reply, want %q", rest, tc.banner)
				}

				_ = server.Close()
				_ = app.Close()
				<-done
				if want := fmt.Sprintf("down=%d", len(tc.banner)); !strings.Contains(logs.String(), want) {
					t.Fatalf("the log does not say %s, the bytes after the reply:\n%s", want, logs.String())
				}
			})
		})
	}
}

// The reply may arrive a byte at a time and is still one reply.
func TestAReplyInPiecesIsOneReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testClientParams()
		logs := captureLogs(t)

		original := dialServer
		t.Cleanup(func() { dialServer = original })

		serverSide := make(chan net.Conn, 1)
		dialServer = func(clientParams) (net.Conn, error) {
			local, remote := net.Pipe()
			t.Cleanup(func() {
				_ = local.Close()
				_ = remote.Close()
			})
			serverSide <- remote
			return local, nil
		}

		app, client := net.Pipe()
		defer func() { _ = app.Close() }()

		done := make(chan struct{})
		go func() {
			defer close(done)
			handleClient(client, cfg, nil)
		}()

		writeErr := make(chan error, 1)
		go func() {
			_, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...))
			writeErr <- err
		}()
		var greetResp [2]byte
		if _, err := io.ReadFull(app, greetResp[:]); err != nil {
			t.Fatalf("greeting response: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("application write: %v", err)
		}

		server := obfsServerSide(t, <-serverSide, cfg)
		if _, err := io.ReadFull(server, make([]byte, 3+len(connectRequest()))); err != nil {
			t.Fatalf("server read of greeting and CONNECT: %v", err)
		}
		reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		go func() {
			for _, b := range append([]byte{0x05, 0x00}, reply...) {
				if _, err := server.Write([]byte{b}); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
			_, _ = server.Write([]byte("payload"))
		}()

		got := make([]byte, len(reply)+len("payload"))
		if _, err := io.ReadFull(app, got); err != nil {
			t.Fatalf("the application got no reply: %v", err)
		}
		if !bytes.Equal(got, append(reply, "payload"...)) {
			t.Fatalf("the application got %q", got)
		}

		_ = server.Close()
		_ = app.Close()
		<-done
		if want := fmt.Sprintf("down=%d", len("payload")); !strings.Contains(logs.String(), want) {
			t.Fatalf("the log does not say %s: the reply was counted as payload\n%s", want, logs.String())
		}
	})
}
