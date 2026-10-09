package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// The edges of an optimistic setup (docs/plan/v2.4-rc4.md, decision 1): what
// happens between the early success and the server's reply.

// With PROXY_USER the dial still waits for the greeting and the
// authentication; the early bytes must follow the authentication and CONNECT,
// never precede them.
func TestEarlyBytesFollowThePasswordAndTheRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := optimisticParams()
		cfg.ProxyUser, cfg.ProxyPass = "user", "secret"
		side := pipeServer(t)

		app, done := openApp(t, cfg)
		readReply(t, app)
		go func() { _, _ = app.Write([]byte("hello")) }()

		server := obfsServerSide(t, <-side, cfg)
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(server, greeting); err != nil {
			t.Fatalf("server read of the greeting: %v", err)
		}
		if want := []byte{0x05, 0x02, 0x00, 0x02}; !bytes.Equal(greeting, want) {
			t.Fatalf("the greeting is %v, want %v", greeting, want)
		}
		if _, err := server.Write([]byte{0x05, 0x02}); err != nil {
			t.Fatalf("server chooses the password: %v", err)
		}
		want := append(buildUserPassAuthPacket("user", "secret"), connectRequest()...)
		got := make([]byte, len(want))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("server read of the password and CONNECT: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("after the greeting the server got %v, want %v", got, want)
		}
		if _, err := server.Write([]byte{0x01, 0x00}); err != nil {
			t.Fatalf("server accepts the password: %v", err)
		}
		early := make([]byte, len("hello"))
		if _, err := io.ReadFull(server, early); err != nil || string(early) != "hello" {
			t.Fatalf("the early bytes came as %q, err %v", early, err)
		}

		if _, err := server.Write(append(append([]byte(nil), successReply...), "world"...)); err != nil {
			t.Fatalf("server replies: %v", err)
		}
		back := make([]byte, len("world"))
		if _, err := io.ReadFull(app, back); err != nil || string(back) != "world" {
			t.Fatalf("the application got %q, err %v", back, err)
		}
		_ = server.Close()
		_ = app.Close()
		<-done
	})
}

// restingPolicy gives cfg a policy with a second transport to rest on.
func restingPolicy(t *testing.T, cfg clientParams) (clientParams, *clientPolicy, *fakeClock) {
	t.Helper()
	cfg.WSUrl = "wss://cdn.example/ws"
	cfg.TransportCooldown = 5 * time.Minute
	p, clock := policyFor(t, cfg)
	cfg.policy = p
	return cfg, p, clock
}

// A server that asks for a password the client does not have answers the
// greeting the dial no longer reads. Like the same answer read by the dial,
// it is a refusal: the policy neither rests the transport nor takes it for a
// success.
func TestAPasswordDemandAfterAnOptimisticSuccessIsARefusal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		side := pipeServer(t)
		cfg, p, clock := restingPolicy(t, optimisticParams())
		first := cfg.attempt().transport
		// A failure past its cooldown: a success would erase it.
		old := clock.now().Add(-2 * cfg.TransportCooldown)
		p.failedAt[first] = old

		app, done := openApp(t, cfg)
		readReply(t, app)
		server := serverReadsRequest(t, <-side, cfg)
		if _, err := server.Write([]byte{0x05, 0x02}); err != nil {
			t.Fatalf("server demands a password: %v", err)
		}
		n, err := app.Read(make([]byte, 16))
		<-done
		if n != 0 || err == nil {
			t.Fatalf("the application read %d bytes, err %v; want the connection closed", n, err)
		}
		out := logs.String()
		for _, want := range []string{"server requires auth but PROXY_USER not set", "phase=" + string(phaseAuthRejected)} {
			if !strings.Contains(out, want) {
				t.Fatalf("the log does not say %s:\n%s", want, out)
			}
		}
		p.mu.Lock()
		got, ok := p.failedAt[first]
		p.mu.Unlock()
		if !ok || !got.Equal(old) {
			t.Fatalf("the policy moved: failedAt[%s] = %v, %v; want %v", first, got, ok, old)
		}
	})
}

// halfDuplex is a connection that can end its writes and keep reading, which
// net.Pipe cannot.
type halfDuplex struct {
	net.Conn          // reads, and everything else
	w        net.Conn // writes
}

func (c *halfDuplex) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *halfDuplex) CloseWrite() error           { return c.w.Close() }
func (c *halfDuplex) Close() error {
	_ = c.w.Close()
	return c.Conn.Close()
}

// An application that sends its request and ends its writes before the server
// has said anything: the FIN follows the early bytes into the tunnel, and the
// answer still comes back.
func TestAnApplicationFINBeforeTheReplyStillGetsTheAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := optimisticParams()
		side := pipeServer(t)

		appIn, clientOut := net.Pipe()
		clientIn, appOut := net.Pipe()
		app := &halfDuplex{Conn: appIn, w: appOut}
		client := &halfDuplex{Conn: clientIn, w: clientOut}
		t.Cleanup(func() { _ = app.Close() })
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleClient(client, cfg, nil)
		}()
		go func() { _, _ = app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...)) }()
		if _, err := io.ReadFull(app, make([]byte, 2)); err != nil {
			t.Fatalf("greeting response: %v", err)
		}
		readReply(t, app)
		go func() {
			_, _ = app.Write([]byte("request"))
			_ = app.CloseWrite()
		}()

		server := serverReadsRequest(t, <-side, cfg)
		up, err := io.ReadAll(server)
		if err != nil || string(up) != "request" {
			t.Fatalf("before its reply the server got %q, err %v; want the request and the end", up, err)
		}
		if _, err := server.Write(append(append([]byte{0x05, 0x00}, successReply...), "answer"...)); err != nil {
			t.Fatalf("server replies: %v", err)
		}
		_ = server.Close()
		back, err := io.ReadAll(app)
		if err != nil || string(back) != "answer" {
			t.Fatalf("the application got %q, err %v; want the whole answer", back, err)
		}
		<-done
	})
}

// A server that drops the connection during the setup while the application
// is still sending: the application is reset, the setup is logged as failed
// in the phase that went unanswered, and the transport rests as it does
// without OPTIMISTIC_CONNECT.
func TestAServerDropDuringAnOptimisticSetupIsAFailedSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		side := pipeServer(t)
		cfg, _, _ := restingPolicy(t, optimisticParams())
		first := cfg.attempt().transport
		failedBefore := minutes.failed.Load()

		app, done := openApp(t, cfg)
		readReply(t, app)
		go func() {
			for {
				if _, err := app.Write([]byte("more")); err != nil {
					return
				}
			}
		}()
		raw := <-side
		server := serverReadsRequest(t, raw, cfg)
		if _, err := io.ReadFull(server, make([]byte, 8)); err != nil {
			t.Fatalf("server read of the early bytes: %v", err)
		}
		_ = raw.Close()
		<-done

		out := logs.String()
		for _, want := range []string{"Tunnel setup failed", "phase=" + string(phaseGreeting)} {
			if !strings.Contains(out, want) {
				t.Fatalf("the log does not say %s:\n%s", want, out)
			}
		}
		if strings.Contains(out, "TCP Tunnel closed") {
			t.Fatalf("a failed setup was logged as a closed tunnel:\n%s", out)
		}
		if got := minutes.failed.Load() - failedBefore; got != 1 {
			t.Fatalf("the minute counted %d failed setups, want 1", got)
		}
		if next := cfg.attempt().transport; next == first {
			t.Fatalf("a dropped setup left the next connection on %s", next)
		}
	})
}

// writesFailAfterFirst lets the opening through and fails every later write,
// as a socket does once the peer has reset it, while what already arrived
// stays readable.
type writesFailAfterFirst struct {
	net.Conn
	writes atomic.Int32
}

func (c *writesFailAfterFirst) Write(b []byte) (int, error) {
	if c.writes.Add(1) > 1 {
		return 0, errors.New("connection reset by peer")
	}
	return c.Conn.Write(b)
}

// failingWritesServer is pipeServer over writesFailAfterFirst.
func failingWritesServer(t *testing.T) <-chan net.Conn {
	t.Helper()
	original := dialServer
	t.Cleanup(func() { dialServer = original })
	side := make(chan net.Conn, 1)
	dialServer = func(clientParams) (net.Conn, error) {
		local, remote := net.Pipe()
		t.Cleanup(func() {
			_ = local.Close()
			_ = remote.Close()
		})
		side <- remote
		return &writesFailAfterFirst{Conn: local}, nil
	}
	return side
}

// A success that arrives after a failed write has nowhere to go: the
// application is already reset. The relay ends there instead of copying
// into it, without the setup deadline, until the server closes.
func TestASuccessAfterAFailedEarlyWriteEndsTheRelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		cfg := optimisticParams()
		side := failingWritesServer(t)

		app, done := openApp(t, cfg)
		readReply(t, app)
		server := serverReadsRequest(t, <-side, cfg)
		if _, err := app.Write([]byte("hello")); err != nil {
			t.Fatalf("application write: %v", err)
		}
		synctest.Wait()

		if _, err := server.Write(append([]byte{0x05, 0x00}, successReply...)); err != nil {
			t.Fatalf("server replies: %v", err)
		}
		select {
		case <-done:
		case <-time.After(time.Hour):
			t.Fatal("the relay outlived the application it could no longer write to")
		}
		_ = server.Close()

		out := logs.String()
		if !strings.Contains(out, "closed_by=tunnel") {
			t.Fatalf("the log does not blame the tunnel:\n%s", out)
		}
		if strings.Contains(out, "Tunnel setup failed") {
			t.Fatalf("an answered setup was logged as failed:\n%s", out)
		}
	})
}

// A server that refuses closes with the early bytes unread, and the reset can
// fail the upstream's next write before the refusal is read. The failed write
// must not close the tunnel under the reader: the refusal is the answer and
// is logged as one, not as a failed setup.
func TestAFailedEarlyWriteDoesNotHideTheRefusal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		cfg := optimisticParams()
		side := failingWritesServer(t)
		closedBefore := minutes.closed[1].Load()
		failedBefore := minutes.failed.Load()

		app, done := openApp(t, cfg)
		readReply(t, app)
		server := serverReadsRequest(t, <-side, cfg)
		if _, err := app.Write([]byte("hello")); err != nil {
			t.Fatalf("application write: %v", err)
		}
		synctest.Wait()

		refusal := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if _, err := server.Write(append([]byte{0x05, 0x00}, refusal...)); err != nil {
			t.Fatalf("the refusal did not reach the client: %v", err)
		}
		<-done
		_ = server.Close()

		out := logs.String()
		for _, want := range []string{"closed_by=server", "reply=5"} {
			if !strings.Contains(out, want) {
				t.Fatalf("the log does not say %s:\n%s", want, out)
			}
		}
		if strings.Contains(out, "Tunnel setup failed") {
			t.Fatalf("a refusal was logged as a failed setup:\n%s", out)
		}
		if got := minutes.closed[1].Load() - closedBefore; got != 1 {
			t.Fatalf("the minute counted %d connections closed by the server, want 1", got)
		}
		if got := minutes.failed.Load() - failedBefore; got != 0 {
			t.Fatalf("a refusal was counted as %d failed setups", got)
		}
	})
}

// Two connections choose a transport together. One fails at the greeting and
// rests it; the other finishes its dial later, before any answer. That dial
// proves nothing about the path, so it must not undo the rest: only an
// answered greeting is a success.
func TestALateDialDoesNotUndoAFailedGreeting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		captureLogs(t)
		cfg, _, _ := restingPolicy(t, optimisticParams())
		first := cfg.attempt().transport

		original := dialServer
		t.Cleanup(func() { dialServer = original })
		turn := make(chan struct{})
		side := make(chan net.Conn, 2)
		dialServer = func(clientParams) (net.Conn, error) {
			<-turn
			local, remote := net.Pipe()
			t.Cleanup(func() {
				_ = local.Close()
				_ = remote.Close()
			})
			side <- remote
			return local, nil
		}

		appA, doneA := openApp(t, cfg)
		readReply(t, appA)
		appB, doneB := openApp(t, cfg)
		readReply(t, appB)
		synctest.Wait()

		turn <- struct{}{}
		rawA := <-side
		serverReadsRequest(t, rawA, cfg)
		_ = rawA.Close()
		synctest.Wait()
		next := cfg.attempt().transport
		if next == first {
			t.Fatalf("the failed greeting did not rest %s", first)
		}

		turn <- struct{}{}
		rawB := <-side
		serverReadsRequest(t, rawB, cfg)
		synctest.Wait()
		if got := cfg.attempt().transport; got != next {
			t.Fatalf("a dial without an answer moved the next connection back to %s", got)
		}

		_ = rawB.Close()
		_ = appA.Close()
		_ = appB.Close()
		<-doneA
		<-doneB
	})
}
