package s5server

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// Timeout behaviour used to be the part nobody tested: observing a 30-second
// read timeout costs 30 seconds of wall clock, so the tests were never
// written and the timeouts were never verified. testing/synctest runs these
// in a bubble with a fake clock, where waiting is free. That buys precision
// as well as speed - the assertion is "at exactly 30s", not "somewhere after
// 29s", so a future off-by-one in deadline arithmetic cannot hide in jitter.
//
// net.Pipe is the fake network the bubble needs: its deadlines are built on
// time.AfterFunc, so they follow the bubble clock. A real TCP socket would
// not - the kernel's timers know nothing about the fake clock.

const (
	testReadTimeout      = 30 * time.Second
	testWriteTimeout     = 10 * time.Second
	testHandshakeTimeout = 15 * time.Second
)

// timeoutPair returns a timeoutConn and the peer end of the pipe it wraps.
// The deadlines belong to the session the wrapper asks, so the pair carries
// one in the state a freshly accepted connection is in.
func timeoutPair(t *testing.T, read, write time.Duration) (*timeoutConn, net.Conn) {
	t.Helper()
	return sessionPair(t, session.SLA{ReadIdle: read, WriteIdle: write})
}

// handshakePair returns a connection whose session also has a handshake
// budget, in the state a freshly accepted connection is in.
func handshakePair(t *testing.T, read, write, handshake time.Duration) (*timeoutConn, net.Conn) {
	t.Helper()
	return sessionPair(t, session.SLA{ReadIdle: read, WriteIdle: write, Handshake: handshake})
}

func sessionPair(t *testing.T, sla session.SLA) (*timeoutConn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	sess := session.NewRegistry(nil).Open(TransportPlain, false, sla)
	return &timeoutConn{Conn: local, sess: sess}, peer
}

// enterRelay walks the session to Relay the way the SOCKS5 core does, so the
// test exercises the same transitions production takes rather than reaching
// into the state directly.
func enterRelay(t *testing.T, conn *timeoutConn, k session.Kind) {
	t.Helper()
	conn.sess.Become(k)
	if !conn.sess.Enter(session.Handshake) || !conn.sess.Enter(session.Relay) {
		t.Fatalf("the session refused the move to relay, it is in %s", conn.sess.Protocol())
	}
}

func requireDeadlineExceeded(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a deadline error, got none")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a deadline error, got %v", err)
	}
}

func requireElapsed(t *testing.T, start time.Time, want time.Duration, what string) {
	t.Helper()
	if got := time.Since(start); got != want {
		t.Fatalf("%s took %v, want exactly %v", what, got, want)
	}
}

func TestReadTimeoutFiresWhenThePeerGoesSilent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, _ := timeoutPair(t, testReadTimeout, testWriteTimeout)

		start := time.Now()
		_, err := conn.Read(make([]byte, 16))
		requireDeadlineExceeded(t, err)
		requireElapsed(t, start, testReadTimeout, "silent read")
	})
}

func TestWriteTimeoutFiresWhenThePeerStopsReading(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, _ := timeoutPair(t, testReadTimeout, testWriteTimeout)

		start := time.Now()
		_, err := conn.Write([]byte("nobody is reading this"))
		requireDeadlineExceeded(t, err)
		requireElapsed(t, start, testWriteTimeout, "unread write")
	})
}

// ReadTimeout is an idle timeout, not a cap on how long a connection may
// live: timeoutConn refreshes the deadline before every Read. A long download
// is therefore safe, and a long silence is not. That distinction is the whole
// reason keepalive (Ф4-8) will be needed for tunnels that legitimately go
// quiet.
func TestReadDeadlineSlidesWithEveryByte(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 20 * time.Second // under the timeout, so traffic keeps it alive
		const rounds = 20                 // 400s in total, far past the 30s timeout

		conn, peer := timeoutPair(t, testReadTimeout, testWriteTimeout)

		go func() {
			for i := 0; i < rounds; i++ {
				time.Sleep(interval)
				if _, err := peer.Write([]byte{byte(i)}); err != nil {
					return
				}
			}
		}()

		start := time.Now()
		buf := make([]byte, 1)
		for i := 0; i < rounds; i++ {
			if _, err := conn.Read(buf); err != nil {
				t.Fatalf("round %d: connection died while traffic was flowing: %v", i, err)
			}
		}
		if alive := time.Since(start); alive <= testReadTimeout {
			t.Fatalf("connection only lived %v, the test proves nothing", alive)
		}

		lastByte := time.Now()
		_, err := conn.Read(buf)
		requireDeadlineExceeded(t, err)
		requireElapsed(t, lastByte, testReadTimeout, "read after the traffic stopped")
	})
}

func TestZeroTimeoutsLeaveTheConnectionOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := timeoutPair(t, 0, 0)

		done := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			done <- err
		}()

		// A full day of silence. With no deadline set, nothing wakes the read.
		time.Sleep(24 * time.Hour)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("read returned after a day of silence: %v", err)
		default:
		}

		// The reader is still there, so a very late byte still gets through.
		if _, err := peer.Write([]byte{7}); err != nil {
			t.Fatalf("peer write: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("read after a day: %v", err)
		}
	})
}

// pipeListener hands out the local ends of net.Pipe pairs. A TCP listener
// cannot be driven inside a bubble, this can.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	// Buffered: dial offers a connection before Accept asks for one, which is
	// how a real listener behaves and what keeps the test linear.
	return &pipeListener{conns: make(chan net.Conn, 8), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// dial creates a connection pair and offers the local end to Accept.
func (l *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	select {
	case l.conns <- local:
	case <-l.closed:
		t.Fatal("listener closed")
	}
	return peer
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// UpdateTimeouts is documented as working "on the fly". On the fly means the
// next connection, not the ones already running: the deadline values are
// copied into timeoutConn at Accept time. Checking both halves of that
// sentence would cost 35 seconds of wall clock without a fake clock, which is
// why nothing checked it before.
func TestUpdateTimeoutsAppliesFromTheNextAcceptOnward(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const newTimeout = 5 * time.Second

		pl := newPipeListener()
		t.Cleanup(func() { _ = pl.Close() })
		l := &listenerPipeline{
			Listener:     pl,
			readTimeout:  testReadTimeout,
			writeTimeout: testWriteTimeout,
			transport:    TransportPlain,
		}

		pl.dial(t)
		before, err := l.Accept()
		if err != nil {
			t.Fatalf("accept before: %v", err)
		}

		l.setTimeouts(newTimeout, newTimeout)

		pl.dial(t)
		after, err := l.Accept()
		if err != nil {
			t.Fatalf("accept after: %v", err)
		}

		type reading struct {
			name    string
			conn    net.Conn
			want    time.Duration
			elapsed time.Duration
			err     error
		}
		readings := []*reading{
			{name: "connection accepted before the update", conn: before, want: testReadTimeout},
			{name: "connection accepted after the update", conn: after, want: newTimeout},
		}

		var wg sync.WaitGroup
		start := time.Now()
		for _, r := range readings {
			wg.Add(1)
			go func(r *reading) {
				defer wg.Done()
				_, err := r.conn.Read(make([]byte, 1))
				r.elapsed = time.Since(start)
				r.err = err
			}(r)
		}
		wg.Wait()

		for _, r := range readings {
			requireDeadlineExceeded(t, r.err)
			if r.elapsed != r.want {
				t.Fatalf("%s timed out after %v, want exactly %v", r.name, r.elapsed, r.want)
			}
		}
	})
}

// A client that sends one byte every few seconds keeps an idle timeout alive
// forever: every byte pushes the deadline out again. That is the classic
// slow-handshake attack, and it is the reason the setup phase needs an
// absolute budget rather than another idle timeout.
func TestHandshakeBudgetCutsOffADribblingClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const dribble = 5 * time.Second // well under the 30s idle timeout

		conn, peer := handshakePair(t, testReadTimeout, testWriteTimeout, testHandshakeTimeout)

		stop := make(chan struct{})
		dribbling := make(chan struct{})
		go func() {
			defer close(dribbling)
			for {
				select {
				case <-stop:
					return
				case <-time.After(dribble):
				}
				if _, err := peer.Write([]byte{0}); err != nil {
					return
				}
			}
		}()

		start := time.Now()
		buf := make([]byte, 1)
		var err error
		for err == nil {
			_, err = conn.Read(buf)
		}
		requireDeadlineExceeded(t, err)
		requireElapsed(t, start, testHandshakeTimeout, "dribbled handshake")

		// A goroutine still running when the bubble ends is a deadlock, not a
		// leftover: stop the writer and wait for it.
		close(stop)
		_ = peer.Close()
		<-dribbling
	})
}

// Once the handshake is over the budget must go with it: a download that
// takes ten minutes is not a stalled handshake. What remains is the relay
// idle timeout, refreshed by traffic.
func TestRelayRegimeDropsTheHandshakeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 20 * time.Second // under the idle timeout, past the budget
		const rounds = 6                  // 120s in total, eight times the budget

		conn, peer := handshakePair(t, testReadTimeout, testWriteTimeout, testHandshakeTimeout)
		enterRelay(t, conn, session.Stream)

		go func() {
			for i := 0; i < rounds; i++ {
				time.Sleep(interval)
				if _, err := peer.Write([]byte{byte(i)}); err != nil {
					return
				}
			}
		}()

		buf := make([]byte, 1)
		for i := 0; i < rounds; i++ {
			if _, err := conn.Read(buf); err != nil {
				t.Fatalf("round %d: relay died %v after the handshake ended: %v",
					i, time.Duration(i+1)*interval, err)
			}
		}

		// The idle timeout is still in force, and it is the relay one.
		lastByte := time.Now()
		_, err := conn.Read(buf)
		requireDeadlineExceeded(t, err)
		requireElapsed(t, lastByte, testReadTimeout, "idle relay")
	})
}

// The 0x83 tunnel is silent whenever the application has nothing to send, so
// no idle timeout may apply to it. Ten minutes is the number from the plan;
// the bubble makes it free to wait.
func TestTunnelRegimeSurvivesTenMinutesOfSilence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := handshakePair(t, testReadTimeout, testWriteTimeout, testHandshakeTimeout)
		enterRelay(t, conn, session.Tunnel)

		done := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			done <- err
		}()

		time.Sleep(10 * time.Minute)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("tunnel died after ten minutes of silence: %v", err)
		default:
		}

		// And the packet that finally arrives still gets through.
		if _, err := peer.Write([]byte{1}); err != nil {
			t.Fatalf("peer write: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("read after ten quiet minutes: %v", err)
		}
	})
}

// The write side follows the same three regimes: a tunnel that cannot write
// after a quiet stretch is just as broken as one that cannot read.
func TestTunnelRegimeAlsoLiftsTheWriteTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := handshakePair(t, testReadTimeout, testWriteTimeout, testHandshakeTimeout)
		enterRelay(t, conn, session.Tunnel)

		written := make(chan error, 1)
		go func() {
			_, err := conn.Write([]byte{9})
			written <- err
		}()

		// Nobody reads for far longer than the write timeout.
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		select {
		case err := <-written:
			t.Fatalf("write gave up after ten minutes: %v", err)
		default:
		}

		buf := make([]byte, 1)
		if _, err := peer.Read(buf); err != nil {
			t.Fatalf("peer read: %v", err)
		}
		if err := <-written; err != nil {
			t.Fatalf("write after ten quiet minutes: %v", err)
		}
	})
}
