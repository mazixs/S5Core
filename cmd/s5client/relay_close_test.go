package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// endWrite is what keeps a relay from outliving the traffic it carries. The
// bug it fixes was found while measuring the keepalive matrix (Ф4-8): the
// client ignored SIGTERM once any tunnel had been opened, because handleClient
// waited on two copies and only one of them ever ended.
//
// The application closing its side ends the copy that reads from it. The other
// copy sits reading the tunnel, and the far end has no reason to close it -
// the target is still connected, and to the server nothing has happened. So
// handleClient never returned, its deferred Close never ran, the tunnel stayed
// open, and the WaitGroup a shutdown waits on never reached zero.

// relayPair runs the same two-copy relay handleClient does, and reports
// whether it finished.
func relayPair(t *testing.T, app, tunnel net.Conn) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(tunnel, app) //nolint:errcheck
		endWrite(tunnel)
	}()
	go func() {
		defer wg.Done()
		io.Copy(app, tunnel) //nolint:errcheck
		endWrite(app)
	}()
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// peerThatFollows stands in for the other end of the tunnel - our own server,
// or the application - each of which passes an end-of-stream on rather than
// sitting on it. It reads until EOF and then closes, which is what makes a
// half-close enough to unwind the whole chain.
func peerThatFollows(c net.Conn) {
	go func() {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
}

func TestARelayEndsWhenTheApplicationCloses(t *testing.T) {
	appSide, appRelay := tcpPair(t)
	tunnelRelay, tunnelFar := tcpPair(t)

	done := relayPair(t, appRelay, tunnelRelay)

	if _, err := appSide.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(tunnelFar, buf); err != nil {
		t.Fatalf("the relay did not forward the request: %v", err)
	}
	if !bytes.Equal(buf, []byte("request")) {
		t.Fatalf("the relay forwarded %q", buf)
	}
	peerThatFollows(tunnelFar)

	// The application is done sending and closes. Without endWrite the server
	// was never told, so it kept the tunnel open and the relay never returned.
	appSide.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay is still running after the application closed its connection")
	}
}

func TestARelayEndsWhenTheTunnelCloses(t *testing.T) {
	appSide, appRelay := tcpPair(t)
	tunnelRelay, tunnelFar := tcpPair(t)

	done := relayPair(t, appRelay, tunnelRelay)

	if _, err := tunnelFar.Write([]byte("reply")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(appSide, buf); err != nil {
		t.Fatalf("the relay did not forward the reply: %v", err)
	}
	if !bytes.Equal(buf, []byte("reply")) {
		t.Fatalf("the relay forwarded %q", buf)
	}
	peerThatFollows(appSide)

	tunnelFar.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay is still running after the tunnel closed")
	}
}

// What endWrite sends has to be a half-close and not a close, or a request
// that ends before its answer does would lose the answer.
func TestEndWriteLeavesTheOtherDirectionOpen(t *testing.T) {
	near, far := tcpPair(t)

	endWrite(near)

	if _, err := io.ReadFull(far, make([]byte, 1)); err != io.EOF {
		t.Fatalf("the far end read %v after the half-close, want EOF", err)
	}
	if _, err := far.Write([]byte("answer")); err != nil {
		t.Fatalf("the far end could not answer after the half-close: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(near, buf); err != nil {
		t.Fatalf("the answer did not arrive: %v", err)
	}
	if !bytes.Equal(buf, []byte("answer")) {
		t.Fatalf("the answer arrived as %q", buf)
	}
}

// A transport that cannot half-close - a WebSocket, here stood in for by a
// connection whose CloseWrite always fails - must still end the relay.
type noHalfClose struct {
	net.Conn
}

func (noHalfClose) CloseWrite() error { return errNoHalfClose }

var errNoHalfClose = &net.OpError{Op: "closewrite", Err: io.ErrUnexpectedEOF}

func TestARelayEndsOnATransportThatCannotHalfClose(t *testing.T) {
	appSide, appRelay := tcpPair(t)
	tunnelRelay, tunnelFar := tcpPair(t)

	done := relayPair(t, appRelay, noHalfClose{tunnelRelay})

	if _, err := appSide.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(tunnelFar, make([]byte, 1)); err != nil {
		t.Fatalf("forward: %v", err)
	}
	appSide.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay is still running on a transport without half-close")
	}
}

func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = got.c.Close()
	})
	return dialed, got.c
}
