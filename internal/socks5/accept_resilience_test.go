package socks5

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// A listener whose Accept answers from a script, which is the only way to
// make it fail the way a kernel does. Once the script runs out it blocks
// until Close, like a real listener with nobody calling.
type scriptedListener struct {
	mu      sync.Mutex
	steps   []acceptStep
	next    int
	calls   []time.Duration
	started time.Time

	done      chan struct{}
	closeOnce sync.Once
}

type acceptStep struct {
	conn net.Conn
	err  error
	// wait holds the step until the test releases it, so that a step can be
	// ordered against what the test does with the connection before it.
	wait <-chan struct{}
}

func newScriptedListener(steps ...acceptStep) *scriptedListener {
	return &scriptedListener{steps: steps, started: time.Now(), done: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls = append(l.calls, time.Since(l.started))
	if l.next >= len(l.steps) {
		l.mu.Unlock()
		<-l.done
		return nil, net.ErrClosed
	}
	step := l.steps[l.next]
	l.next++
	l.mu.Unlock()
	if step.wait != nil {
		<-step.wait
	}
	return step.conn, step.err
}

func (l *scriptedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return scriptedAddr{} }

// callTimes returns when each Accept happened, measured from the listener's
// creation.
func (l *scriptedListener) callTimes() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Duration(nil), l.calls...)
}

type scriptedAddr struct{}

func (scriptedAddr) Network() string { return "scripted" }
func (scriptedAddr) String() string  { return "scripted" }

func serverForAcceptTests(t *testing.T) *Server {
	t.Helper()
	// The retry writes a line per failure, and these tests cause a dozen.
	server, err := New(&Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

// A process that runs out of file descriptors gets EMFILE from accept(2).
// The condition is momentary - it clears as soon as some connection ends -
// but returning from Accept ends the listener, and nothing restarts it. The
// port stayed shut long after the burst that closed it, so a load spike
// turned into an outage that needed a restart.
func TestALoadFailureDoesNotCloseThePort(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ln := newScriptedListener(
		acceptStep{err: syscall.EMFILE},
		acceptStep{conn: server},
	)
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() { served <- serverForAcceptTests(t).ServeContext(context.Background(), ln) }()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	greet(t, client)

	select {
	case err := <-served:
		t.Fatalf("the listener gave up after a temporary failure: %v", err)
	default:
	}
}

// The errors that are worth retrying are the ones about this moment rather
// than about the socket. Each of them used to be fatal to the listener.
func TestEveryMomentaryKernelErrorIsRetried(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS,
		syscall.ENOMEM, syscall.ECONNABORTED, syscall.EINTR, syscall.EAGAIN,
	} {
		if !recoverableAcceptError(errno) {
			t.Errorf("%v (%d) ends the listener, but the next accept can succeed", errno, uint(errno))
		}
		if !recoverableAcceptError(&net.OpError{Op: "accept", Err: errno}) {
			t.Errorf("%v wrapped in net.OpError - the form Accept actually returns - is not recognised", errno)
		}
	}

	// The opposite: a closed listener never comes back, and retrying it is
	// a spin at full speed.
	if recoverableAcceptError(net.ErrClosed) {
		t.Error("a closed listener is treated as retryable, which spins the accept loop")
	}
	if recoverableAcceptError(&net.OpError{Op: "accept", Err: net.ErrClosed}) {
		t.Error("a closed listener wrapped in net.OpError is treated as retryable")
	}
	if recoverableAcceptError(errors.New("some other failure")) {
		t.Error("an unknown failure is retried, so a permanent one loops forever")
	}
}

// A failure to accept says nothing about the connections already being
// served. The loop used to close every one of them on any Accept error, so
// one EMFILE dropped every established session on the node.
func TestAnAcceptFailureLeavesEstablishedConnectionsAlone(t *testing.T) {
	firstClient, firstServer := net.Pipe()
	secondClient, secondServer := net.Pipe()
	defer func() { _ = firstClient.Close() }()
	defer func() { _ = secondClient.Close() }()

	ln := newScriptedListener(
		acceptStep{conn: firstServer},
		acceptStep{err: syscall.ENOBUFS},
		acceptStep{conn: secondServer},
	)
	defer func() { _ = ln.Close() }()

	go func() { _ = serverForAcceptTests(t).ServeContext(context.Background(), ln) }()

	_ = firstClient.SetDeadline(time.Now().Add(5 * time.Second))
	_ = secondClient.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, firstClient)
	// The second connection is only accepted after the failure, so its
	// greeting is proof that the loop got past it.
	greet(t, secondClient)

	// And the first connection is still the same session: it is mid
	// handshake, waiting for a request, rather than closed underneath the
	// client.
	echo := echoTarget(t)
	if err := relayEcho(firstClient, echo); err != nil {
		t.Fatalf("the established connection did not survive the accept failure: %v", err)
	}
}

// The other half of the rule: an error that is not about this moment ends
// the loop, and ending the loop ends the connections it produced. Without
// this the retry would apply to a closed listener and spin a core.
func TestAClosedListenerEndsTheLoopAndItsConnections(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	// The close comes after the greeting, not racing it: the point of the
	// test is what happens to a connection that is already being served.
	greeted := make(chan struct{})
	ln := newScriptedListener(
		acceptStep{conn: server},
		acceptStep{err: net.ErrClosed, wait: greeted},
	)
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() { served <- serverForAcceptTests(t).ServeContext(context.Background(), ln) }()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	greet(t, client)
	close(greeted)

	select {
	case err := <-served:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ServeContext returned %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeContext is still running on a closed listener")
	}

	// Sessions here can last hours; a shutdown that waits for them is not a
	// shutdown, so the loop closes them itself.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived the listener that produced it")
	}
}

// What the retry costs while the condition lasts. The schedule is asserted
// exactly, in a bubble where waiting is free: a loop that retried without a
// pause would spin through the backlog at full speed, and one that paused
// too long would leave the port idle after the cause had passed.
func TestTheRetryScheduleBacksOffToACeiling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()

		steps := make([]acceptStep, 0, 10)
		for i := 0; i < 9; i++ {
			steps = append(steps, acceptStep{err: syscall.EMFILE})
		}
		steps = append(steps, acceptStep{conn: server})

		ln := newScriptedListener(steps...)
		served := make(chan error, 1)
		go func() { served <- serverForAcceptTests(t).ServeContext(context.Background(), ln) }()

		greet(t, client)

		// 5ms, doubling, capped at a second: the ninth pause is the cap and
		// the tenth would be too.
		want := []time.Duration{
			0,
			5 * time.Millisecond,
			15 * time.Millisecond,
			35 * time.Millisecond,
			75 * time.Millisecond,
			155 * time.Millisecond,
			315 * time.Millisecond,
			635 * time.Millisecond,
			1275 * time.Millisecond,
			2275 * time.Millisecond,
		}
		// The call after the successful accept is the loop waiting for the
		// next client, and it carries no delay of its own.
		got := ln.callTimes()
		if len(got) < len(want) {
			t.Fatalf("accept was called %d times, want at least %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("accept %d at %v, want %v", i+1, got[i], want[i])
			}
		}

		_ = ln.Close()
		<-served
		_ = server.Close()
	})
}

// echoTarget is a plain TCP destination that echoes what it is sent, so
// a relay through it can be observed end to end.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// connectThrough issues a CONNECT for addr on an already greeted connection
// and checks that bytes make the round trip.
func relayEcho(c net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return errors.New("target is not an IPv4 address")
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}

	req := []byte{Socks5Version, ConnectCommand, 0, ipv4Address}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[1] != successReply {
		return errors.New("connect was refused")
	}

	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(c, echo); err != nil {
		return err
	}
	if string(echo) != "ping" {
		return errors.New("the relay returned " + string(echo))
	}
	return nil
}
