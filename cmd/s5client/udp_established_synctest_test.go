package main

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// "UDP Tunnel established" and "UDP Tunnel closed" are each written from one
// place in associateUDP, by the goroutine that runs the handler, so the second
// cannot come first. These tests pin that and what the pair means: a setup
// that fails writes neither, and a setup that ends writes each once, whenever
// the application leaves or the tunnel dies. They run on net.Pipe inside a
// synctest bubble: nothing waits for a clock, and the interleavings that
// matter are held open with channels rather than raced.

const (
	establishedMsg = "UDP Tunnel established"
	closedMsg      = "UDP Tunnel closed"
)

// pipeAssociation runs the handler on pipes: app is the application's SOCKS5
// connection and server the far end of the tunnel. wrap may put a layer on
// the client's end of the tunnel.
func pipeAssociation(t *testing.T, optimistic bool, wrap func(net.Conn) net.Conn) (app, server net.Conn, done chan struct{}) {
	t.Helper()
	app, clientSide := net.Pipe()
	server, tunnel := net.Pipe()
	t.Cleanup(func() {
		_ = app.Close()
		_ = server.Close()
	})
	if wrap != nil {
		tunnel = wrap(tunnel)
	}
	done = runUDPAssociate(t, clientSide, "example.com", clientParams{OptimisticConnect: optimistic}, nil, dialled(tunnel))
	return app, server, done
}

// serverWrites sends to the client from its own goroutine, since a pipe write
// returns only once the client has read it. The channel closes when it has.
func serverWrites(server net.Conn, b []byte) <-chan struct{} {
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = server.Write(b)
	}()
	return written
}

// wantPair checks that every established line has a closing line, that there
// is at most one of each, and that the closing line is the later. It returns
// the number of pairs.
func wantPair(t *testing.T, logs *syncBuffer) int {
	t.Helper()
	s := logs.String()
	opened, closed := len(linesOf(s, establishedMsg)), len(linesOf(s, closedMsg))
	if opened != closed || opened > 1 {
		t.Fatalf("%d established and %d closing lines, want one of each or none:\n%s", opened, closed, s)
	}
	if opened == 1 && strings.Index(s, `msg="`+establishedMsg+`"`) > strings.Index(s, `msg="`+closedMsg+`"`) {
		t.Fatalf("the closing line came before established:\n%s", s)
	}
	return opened
}

func wantEstablished(t *testing.T, logs *syncBuffer, established bool) {
	t.Helper()
	if got := wantPair(t, logs) == 1; got != established {
		t.Fatalf("established is %v, want %v:\n%s", got, established, logs)
	}
}

// gatedTunnel holds the handler where it clears the setup deadline, the first
// thing it does once it has read the server's reply, until the test opens the
// gate. closed says the setup closed the tunnel: the application had left.
type gatedTunnel struct {
	net.Conn
	gate   chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (c *gatedTunnel) SetDeadline(t time.Time) error {
	<-c.gate
	return c.Conn.SetDeadline(t)
}

func (c *gatedTunnel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestTheClosingLineNeverPrecedesEstablished(t *testing.T) {
	for _, tc := range []struct {
		name       string
		optimistic bool
		end        func(app, server net.Conn)
	}{
		{"the application leaves", false, func(app, _ net.Conn) { _ = app.Close() }},
		{"the tunnel ends", false, func(_, server net.Conn) { _ = server.Close() }},
		{"the application leaves, optimistic", true, func(app, _ net.Conn) { _ = app.Close() }},
		{"the tunnel ends, optimistic", true, func(_, server net.Conn) { _ = server.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				app, server, done := pipeAssociation(t, tc.optimistic, nil)
				written := serverWrites(server, udpTunnelReply)
				readAppReply(t, app)
				<-written

				tc.end(app, server)
				waitHandler(t, done)
				wantEstablished(t, logs, true)
			})
		})
	}

	// The application leaves after the server has answered and before the
	// setup is over, which closes the tunnel under the handler: the end is
	// already waiting when established is written. Whether the pair is written
	// at all is not what this checks, only that the closing line is not first.
	t.Run("the application leaves while the setup ends", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logs := captureLogs(t)
			var gated *gatedTunnel
			app, server, done := pipeAssociation(t, true, func(c net.Conn) net.Conn {
				gated = &gatedTunnel{Conn: c, gate: make(chan struct{}), closed: make(chan struct{})}
				return gated
			})
			readAppReply(t, app)
			<-serverWrites(server, udpTunnelReply)

			_ = app.Close()
			<-gated.closed
			close(gated.gate)
			waitHandler(t, done)
			wantPair(t, logs)
		})
	})
}

func TestNoEstablishedLineForASetupThatFails(t *testing.T) {
	refusal := []byte{socks5Ver, 0x02, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	for _, optimistic := range []bool{false, true} {
		mode := "waiting"
		if optimistic {
			mode = "optimistic"
		}
		for _, tc := range []struct {
			name string
			// act drives the setup to its failure; the handler must end.
			act func(app, server net.Conn)
		}{
			{"the server refuses", func(_, server net.Conn) { _, _ = server.Write(refusal) }},
			{"the reply stops short", func(_, server net.Conn) {
				_, _ = server.Write(udpTunnelReply[:1])
				_ = server.Close()
			}},
			{"the tunnel closes before it answers", func(_, server net.Conn) { _ = server.Close() }},
			{"the application leaves before the server answers", func(app, _ net.Conn) { _ = app.Close() }},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					logs := captureLogs(t)
					app, server, done := pipeAssociation(t, optimistic, nil)
					// The application is answered once or refused, and a pipe
					// holds the handler until that is read.
					go func() { _, _ = io.Copy(io.Discard, app) }()
					tc.act(app, server)
					waitHandler(t, done)
					wantEstablished(t, logs, false)
				})
			})
		}
	}

	// A refused dial is the one failure that has no tunnel at all.
	t.Run("the dial fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logs := captureLogs(t)
			app, clientSide := net.Pipe()
			t.Cleanup(func() { _ = app.Close() })
			dial := func(cfg clientParams, _ []byte) (net.Conn, clientParams, error) {
				return nil, cfg, &tunnelError{phase: phaseDial, err: io.ErrClosedPipe}
			}
			done := runUDPAssociate(t, clientSide, "example.com", clientParams{OptimisticConnect: true}, nil, dial)
			readAppReply(t, app)
			waitHandler(t, done)
			wantEstablished(t, logs, false)
		})
	})

	// Answered once the server has accepted: an application that left in the
	// meantime is told nothing, and the association never starts.
	t.Run("the application leaves before it is answered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logs := captureLogs(t)
			app, server, done := pipeAssociation(t, false, nil)
			<-serverWrites(server, udpTunnelReply)
			_ = app.Close()
			waitHandler(t, done)
			wantEstablished(t, logs, false)
		})
	})
}
