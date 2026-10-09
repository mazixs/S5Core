package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// A dead spare under an optimistic CONNECT or a UDP association: the
// application has heard success already, so the setup is repeated on a fresh
// dial where it can be, and nothing of the spare reaches the application or
// the transport policy.

// readAllOnceAndHangUp takes the first write of a tunnel whole, so that the
// setup returns, and closes: the failure comes where the greeting is read.
func readAllOnceAndHangUp(remote net.Conn) {
	_, _ = remote.Read(make([]byte, 64<<10))
	_ = remote.Close()
}

// readWritesAndHangUp takes n writes of a tunnel whole and closes: the
// setup and what the application sent behind it, so that no write of the
// client meets the close and the failure is the end of the stream.
func readWritesAndHangUp(n int) func(net.Conn) {
	return func(remote net.Conn) {
		buf := make([]byte, 64<<10)
		for range n {
			_, _ = remote.Read(buf)
		}
		_ = remote.Close()
	}
}

// readAndHangUp drains n bytes of the tunnel and closes it.
func readAndHangUp(n int64) func(net.Conn) {
	return func(remote net.Conn) {
		_, _ = io.CopyN(io.Discard, remote, n)
		_ = remote.Close()
	}
}

// answersAndEchoes plays a server that takes the greeting, the request and
// the application's early bytes, accepts, sends back and closes.
func answersAndEchoes(cfg clientParams, early, back string) func(net.Conn) {
	return func(remote net.Conn) {
		conn, err := newObfsConnForTest(remote, cfg)
		if err != nil {
			return
		}
		got := make([]byte, 3+len(connectRequest())+len(early))
		if _, err := io.ReadFull(conn, got); err != nil {
			return
		}
		if !bytes.HasSuffix(got, []byte(early)) {
			return
		}
		reply := append([]byte{socks5Ver, socks5NoAuth}, successReply...)
		_, _ = conn.Write(append(reply, back...))
		_ = conn.Close()
	}
}

// readsRequest plays a server up to the greeting and the request, quietly:
// the next spare the tunnel orders is served by it too and only closed.
func readsRequest(remote net.Conn, cfg clientParams) (net.Conn, bool) {
	conn, err := newObfsConnForTest(remote, cfg)
	if err != nil {
		return nil, false
	}
	_, err = io.ReadFull(conn, make([]byte, 3+len(connectRequest())))
	return conn, err == nil
}

func optimisticPolicyParams(t *testing.T) clientParams {
	t.Helper()
	cfg := policyParams(t)
	cfg.OptimisticConnect = true
	return cfg
}

func TestADeadSpareUnderAnOptimisticConnectIsInvisibleToTheApplication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := optimisticPolicyParams(t)
		dead := spareFrom(t, server, cfg, readWritesAndHangUp(2))
		used, wasted := minutes.prewarmUsed.Load(), minutes.prewarmWasted.Load()

		server.setServe(answersAndEchoes(cfg, "hello", "world"))
		before := server.count()
		app, done := openApp(t, cfg)
		readReply(t, app)
		if _, err := app.Write([]byte("hello")); err != nil {
			t.Fatalf("application write: %v", err)
		}
		back := make([]byte, len("world"))
		if _, err := io.ReadFull(app, back); err != nil || string(back) != "world" {
			t.Fatalf("the application got %q, err %v; want the answer through a fresh dial", back, err)
		}
		_ = app.Close()
		<-done
		synctest.Wait()

		if !isClosed(dead) {
			t.Fatal("the dead spare is still open")
		}
		// The fresh dial and the next spare.
		if got := server.count() - before; got != 2 {
			t.Fatalf("%d dials, want the fresh one and the next spare", got)
		}
		if n := restedTransports(cfg.policy); n != 0 {
			t.Fatalf("a dead spare rested %d transports", n)
		}
		if got := minutes.prewarmUsed.Load() - used; got != 0 {
			t.Fatalf("a dead spare counted as used %d times", got)
		}
		if got := minutes.prewarmWasted.Load() - wasted; got != 1 {
			t.Fatalf("a dead spare counted as wasted %d times, want 1", got)
		}
	})
}

func TestADeadSpareWithMoreThanTheBufferResetsWithoutRestingTheTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := optimisticPolicyParams(t)
		const sent = 100 << 10
		spareFrom(t, server, cfg, readAndHangUp(80<<10))
		used, wasted := minutes.prewarmUsed.Load(), minutes.prewarmWasted.Load()

		before := server.count()
		app, done := openApp(t, cfg)
		readReply(t, app)
		go func() { _, _ = app.Write(make([]byte, sent)) }()
		n, err := app.Read(make([]byte, 16))
		<-done
		if n != 0 || err == nil {
			t.Fatalf("the application read %d bytes, err %v; want its connection reset", n, err)
		}
		time.Sleep(prewarmRTT)
		synctest.Wait()
		// Only the next spare: nothing could be sent again.
		if got := server.count() - before; got != 1 {
			t.Fatalf("%d dials, want only the next spare", got)
		}
		if n := restedTransports(cfg.policy); n != 0 {
			t.Fatalf("a dead spare rested %d transports", n)
		}
		if got := minutes.prewarmUsed.Load() - used; got != 0 {
			t.Fatalf("a dead spare counted as used %d times", got)
		}
		if got := minutes.prewarmWasted.Load() - wasted; got != 1 {
			t.Fatalf("a dead spare counted as wasted %d times, want 1", got)
		}
	})
}

var earlyDatagram = []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 53, 'q'}

// A datagram the application sent before the server answered goes behind
// the request to a spare that turns out dead, and again behind the request on
// the fresh dial.
func TestAnEarlyDatagramFollowsTheRequestToTheFreshDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := policyParams(t)
		// Takes the request and the datagram behind it, and ends unanswered.
		spareFrom(t, server, cfg, readWritesAndHangUp(2))
		got := make(chan []byte, 1)
		server.setServe(func(remote net.Conn) {
			conn, ok := readsRequest(remote, cfg)
			if !ok {
				return // the next spare
			}
			d := make([]byte, 2+len(earlyDatagram))
			_, _ = io.ReadFull(conn, d)
			got <- d[2:]
			_, _ = conn.Write([]byte{socks5Ver, socks5NoAuth})
		})

		setup := &udpSetup{}
		setup.add(earlyDatagram)
		cfg.requestSent = setup.attach
		cfg.setup = setup
		conn, _, err := dialAttempt(cfg, connectRequest())
		if err != nil {
			t.Fatalf("the association failed instead of dialing again: %v", err)
		}
		defer func() { _ = conn.Close() }()
		if d := <-got; !bytes.Equal(d, earlyDatagram) {
			t.Fatalf("the fresh dial got %x behind the request, want the early datagram", d)
		}
		early := setup.close()
		if early.writeErr != nil || early.lost != 0 {
			t.Fatalf("the retry left %+v, want nothing lost and no failed write", early)
		}
		if n := restedTransports(cfg.policy); n != 0 {
			t.Fatalf("a dead spare rested %d transports", n)
		}
	})
}

// A write behind the request that failed on the spare is not the failure of
// the attempt set up again after it.
func TestAFailedEarlyWriteOnASpareDoesNotOutliveARestart(t *testing.T) {
	setup := &udpSetup{}
	setup.spare()
	setup.add(earlyDatagram)
	dead, peer := net.Pipe()
	_ = peer.Close()
	setup.attach(dead)

	setup.restart()
	fresh, server := net.Pipe()
	defer func() { _ = server.Close() }()
	got := make(chan []byte, 1)
	go func() {
		d := make([]byte, 2+len(earlyDatagram))
		_, _ = io.ReadFull(server, d)
		got <- d[2:]
	}()
	setup.attach(fresh)
	select {
	case d := <-got:
		if !bytes.Equal(d, earlyDatagram) {
			t.Fatalf("the fresh tunnel got %x, want the early datagram again", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fresh tunnel got nothing; the early datagram was dropped")
	}
	if early := setup.close(); early.writeErr != nil {
		t.Fatalf("the write to the spare outlived the restart: %v", early.writeErr)
	}
}

// A datagram that came after the request went out on a spare is held as well:
// the spare may still turn out dead, and the datagram goes again behind the
// request on the fresh dial.
func TestADatagramAfterTheRequestOnASpareFollowsTheRetry(t *testing.T) {
	setup := &udpSetup{}
	setup.spare()
	first, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	setup.attach(first)
	setup.add(earlyDatagram)

	setup.restart()
	fresh, server := net.Pipe()
	defer func() { _ = server.Close() }()
	got := make(chan []byte, 1)
	go func() {
		d := make([]byte, 2+len(earlyDatagram))
		_, _ = io.ReadFull(server, d)
		got <- d[2:]
	}()
	setup.attach(fresh)
	select {
	case d := <-got:
		if !bytes.Equal(d, earlyDatagram) {
			t.Fatalf("the fresh tunnel got %x, want the datagram again", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fresh tunnel got nothing; the datagram went with the spare")
	}
	_ = setup.close()
}

// What a failure on a spare may be repeated after, without a kernel to ask
// (a pipe, or not Linux): only what proves the server did not get the
// request.
func TestWhatAFailureOnASpareMayRepeat(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		retried   bool
		countsFor bool // counts against the path
	}{
		{"failed before the request", tunnelFail(phaseDial, "failed to create obfs conn: %w", io.ErrClosedPipe), true, false},
		{"ended without an answer", tunnelFail(phaseGreeting, "failed to read server greeting: %w", io.EOF), true, false},
		{"ended inside a frame", tunnelFail(phaseGreeting, "failed to read server greeting: %w", io.ErrUnexpectedEOF), true, false},
		{"a write that failed", tunnelFail(phaseGreeting, "failed to send greeting: %w", io.ErrClosedPipe), false, false},
		{"closed by this client", tunnelFail(phaseGreeting, "failed to read server greeting: %w", net.ErrClosed), false, true},
		{"a timeout", tunnelFail(phaseGreeting, "failed to read server greeting: %w", os.ErrDeadlineExceeded), false, true},
		{"after the answer", tunnelFail(phaseConnectReply, "failed to read reply: %w", io.EOF), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markSpareFailure(tc.err, endedUnanswered(tc.err), nil)
			if got := mayRetry(tc.err); got != tc.retried {
				t.Fatalf("retried %v, want %v", got, tc.retried)
			}
			if got := countsAgainstThePath(tc.err); got != tc.countsFor {
				t.Fatalf("counts against the path %v, want %v", got, tc.countsFor)
			}
		})
	}
}

// The application's end of its stream before the reply follows its bytes to
// the fresh tunnel: a server that answers only after the end hears it at
// once, not when the handshake budget runs out.
func TestADeadSpareRetryCarriesTheApplicationsFIN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := optimisticPolicyParams(t)
		// Takes the setup, and closes while the application's bytes wait on
		// the pipe.
		spareFrom(t, server, cfg, func(remote net.Conn) {
			_, _ = remote.Read(make([]byte, 64<<10))
			time.Sleep(time.Millisecond)
			_ = remote.Close()
		})

		ended := make(chan time.Duration, 1)
		var start time.Time
		server.setServe(func(remote net.Conn) {
			conn, ok := readsRequest(remote, cfg)
			if !ok {
				return // the next spare
			}
			up, err := io.ReadAll(conn)
			if err != nil || string(up) != "hello" {
				t.Errorf("the fresh tunnel got %q, err %v; want the bytes and the end", up, err)
			}
			ended <- time.Since(start)
			_, _ = conn.Write(append(append([]byte{socks5Ver, socks5NoAuth}, successReply...), "world"...))
			_ = conn.Close()
		})

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
		start = time.Now()
		go func() {
			_, _ = app.Write([]byte("hello"))
			_ = app.CloseWrite()
		}()

		if took := <-ended; took >= time.Second {
			t.Fatalf("the end of the application's stream reached the fresh tunnel after %v", took)
		}
		back, err := io.ReadAll(app)
		if err != nil || string(back) != "world" {
			t.Fatalf("the application got %q, err %v; want the answer", back, err)
		}
		<-done
	})
}

// A timeout on a spare under an optimistic CONNECT is not repeated and rests
// the transport, as on a fresh dial.
func TestATimeoutOnASpareUnderAnOptimisticConnectRestsTheTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := optimisticPolicyParams(t)
		spareFrom(t, server, cfg, drain)
		wasted := minutes.prewarmWasted.Load()

		before := server.count()
		app, done := openApp(t, cfg)
		readReply(t, app)
		<-done
		synctest.Wait()
		// Only the next spare.
		if got := server.count() - before; got != 1 {
			t.Fatalf("%d dials, want only the next spare", got)
		}
		if n := restedTransports(cfg.policy); n != 1 {
			t.Fatalf("a timeout on a spare rested %d transports, want 1", n)
		}
		// The spare under the tunnel, and the next one, which reached its
		// age within the budget.
		if got := minutes.prewarmWasted.Load() - wasted; got != 2 {
			t.Fatalf("prewarm_wasted grew by %d, want 2", got)
		}
	})
}

// An application that leaves while its association is set up on a spare:
// the setup closes the spare itself, and that is no reason to dial again.
func TestAnApplicationLeavingDuringSetupOnASpareDialsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := policyParams(t)
		spareFrom(t, server, cfg, drain)

		setup := &udpSetup{}
		cfg.requestSent = setup.attach
		cfg.setup = setup
		before := server.count()
		failed := make(chan error, 1)
		go func() {
			_, _, err := dialAttempt(cfg, connectRequest())
			failed <- err
		}()
		synctest.Wait()
		setup.abandon()
		if err := <-failed; err == nil {
			t.Fatal("a setup the application left succeeded")
		}
		time.Sleep(prewarmRTT)
		synctest.Wait()
		// Only the next spare.
		if got := server.count() - before; got != 1 {
			t.Fatalf("%d dials, want only the next spare", got)
		}
		if n := restedTransports(cfg.policy); n != 0 {
			t.Fatalf("an application that left rested %d transports", n)
		}
	})
}
