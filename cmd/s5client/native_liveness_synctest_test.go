package main

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/veil"
)

// The liveness of the native path, in a testing/synctest bubble so that the
// assertions can be exact. The path is in memory: the client's end is a
// datagramConn, and the server's end answers every probe it receives. Jitter
// is zero, so an active association is probed every 400 ms exactly.

type memPath struct {
	server   *nativeudp.Session
	toClient chan []byte
	errs     chan error
	closed   chan struct{}
	dropUp   atomic.Bool
	dropDown atomic.Bool
	lose     func(probe int64) bool
	probes   atomic.Int64
	data     atomic.Int64
	mu       sync.Mutex
	heard    []time.Duration // when a probe said the client hears the server
	bare     []time.Duration // when a probe did not
	start    time.Time
}

func (p *memPath) Write(b []byte) (int, error) {
	if p.dropUp.Load() {
		return len(b), nil
	}
	// The server drops what it cannot open, and the sender never learns.
	if pk, err := p.server.Open(b); err == nil {
		switch pk.Kind {
		case nativeudp.KindProbe:
			p.mu.Lock()
			at := time.Since(p.start)
			if len(pk.Data) == 1 && pk.Data[0] == nativeudp.ProbeHeard {
				p.heard = append(p.heard, at)
			} else {
				p.bare = append(p.bare, at)
			}
			p.mu.Unlock()
			if i := p.probes.Add(1); p.lose == nil || !p.lose(i) {
				p.answer(nativeudp.KindProbeAck, nil)
			}
		case nativeudp.KindData:
			p.data.Add(1)
		}
	}
	return len(b), nil
}

func (p *memPath) answer(kind byte, d []byte) {
	if p.dropDown.Load() {
		return
	}
	wire, err := p.server.Seal(nil, kind, d)
	if err != nil {
		panic(err)
	}
	p.toClient <- wire
}

func (p *memPath) Read(b []byte) (int, error) {
	select {
	case err := <-p.errs:
		return 0, err
	case w := <-p.toClient:
		return copy(b, w), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

// memServer is where the probes of a memPath go.
var memServer = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}

func (p *memPath) RemoteAddr() net.Addr { return memServer }

// logged counts the lines of logs that contain every one of parts.
func logged(logs *syncBuffer, parts ...string) int {
	n := 0
lines:
	for _, line := range strings.Split(logs.String(), "\n") {
		for _, part := range parts {
			if !strings.Contains(line, part) {
				continue lines
			}
		}
		n++
	}
	return n
}

type liveness struct {
	t       *testing.T
	start   time.Time
	path    *memPath
	client  *nativeClient
	signals chan time.Time
}

// startLiveness must run inside the bubble.
func startLiveness(t *testing.T, lose func(int64) bool) *liveness {
	t.Helper()
	return startLivenessWith(t, lose, 0)
}

// startLivenessWith draws every probe interval at the given point of its
// jitter range.
func startLivenessWith(t *testing.T, lose func(int64) bool, jitter float64) *liveness {
	t.Helper()
	return startLivenessSignalling(t, lose, jitter, nil)
}

// startLivenessSignalling tells the server through signal, or through the
// signals channel when signal is nil.
func startLivenessSignalling(t *testing.T, lose func(int64) bool, jitter float64, signal func()) *liveness {
	t.Helper()
	psk, secret := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 40)
	ck, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	p := &memPath{server: nativeudp.NewSession(sk), toClient: make(chan []byte, 4096), errs: make(chan error, 16), closed: make(chan struct{}), lose: lose, start: time.Now()}
	l := &liveness{t: t, start: p.start, path: p, signals: make(chan time.Time, 64)}
	if signal == nil {
		signal = func() { l.signals <- time.Now() }
	}
	l.client = newNativeClient(p, nativeudp.NewSession(ck), signal)
	l.client.jitter = func() float64 { return jitter }
	t.Cleanup(func() { close(p.closed); synctest.Wait() })
	go l.client.run(func([]byte) {})
	return l
}

// at sleeps until the given offset from the start of the association.
func (l *liveness) at(d time.Duration) {
	time.Sleep(time.Until(l.start.Add(d)))
	synctest.Wait()
}

// stream has the server send state every 10 ms, as a game server does to a
// client that only listens, until stop is closed.
func (l *liveness) stream(stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				l.path.answer(nativeudp.KindData, []byte("state"))
			}
		}
	}()
}

// input has the application send a datagram every 10 ms until stop is closed.
func (l *liveness) input(stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				l.client.carry([]byte("input"))
			}
		}
	}()
}

func (l *liveness) signalled() []time.Duration {
	var at []time.Duration
	for {
		select {
		case s := <-l.signals:
			at = append(at, s.Sub(l.start))
		default:
			return at
		}
	}
}

// Probes at 0.4 and 0.8 s are answered; the break at 1.0 s loses the ones at
// 1.2, 1.6 and 2.0 s, and at 2.4 s three are unanswered, the first of them
// 1.2 s ago. The server is told then and again with the first retry, which
// finds the break healed and verifies the path. Where the server's datagrams
// stop, it is told at 2.0 s as well: the client has not heard it for a
// second, and the answers go by TCP from there rather than from the verdict.
func TestThePathIsDownExactlyThreeProbesAfterItBreaks(t *testing.T) {
	told := map[string][]time.Duration{
		"server to client": {2 * time.Second, 2400 * time.Millisecond},
		"client to server": {2400 * time.Millisecond},
	}
	for _, direction := range []string{"server to client", "client to server"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := startLiveness(t, nil)
				stop := make(chan struct{})
				defer close(stop)
				l.stream(stop)
				cut := &l.path.dropDown
				if direction == "client to server" {
					cut = &l.path.dropUp
				}
				l.at(time.Second)
				if !l.client.up.Load() {
					t.Fatal("the path was not verified")
				}
				cut.Store(true)
				l.at(2400*time.Millisecond - time.Nanosecond)
				if !l.client.up.Load() {
					t.Fatal("down before the third unanswered probe")
				}
				l.at(2400 * time.Millisecond)
				if got := l.signalled(); !slices.Equal(got, told[direction]) {
					t.Fatalf("the server was told at %v, want %v", got, told[direction])
				}
				if l.client.up.Load() {
					t.Fatal("the path is still up")
				}
				if l.client.carry([]byte("input")) {
					t.Fatal("a datagram went native on a path that is down")
				}
				// The retry after the break is at 3.4 s.
				cut.Store(false)
				l.at(3400*time.Millisecond - time.Nanosecond)
				if l.client.up.Load() {
					t.Fatal("up before the retry")
				}
				l.at(3400 * time.Millisecond)
				if !l.client.up.Load() {
					t.Fatal("the retry did not verify the path")
				}
				if got := l.signalled(); len(got) != 1 || got[0] != 3400*time.Millisecond {
					t.Fatalf("the server was told at %v, want once more at 3.4s", got)
				}
			})
		})
	}
}

// A native datagram sent just before the loss can reach the server after the
// signal and turn its answers back to native, and an application that only
// listens then hears nothing until the path is verified again. So every retry
// of a lost path tells the server again: with the verdict at 2.4 s, with the
// retries at 3.4, 5.4, 9.4 and 17.4 s, and with the one at 27.4 s that finds
// the path healed. The first signal is at 2.0 s, a second after the server
// was last heard. From there on the path is up and the server is told
// nothing.
func TestEveryRetryOfALostPathTellsTheServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.at(time.Second)
		l.path.dropDown.Store(true)
		l.at(20 * time.Second)
		l.path.dropDown.Store(false)
		l.at(27400*time.Millisecond - time.Nanosecond)
		if l.client.up.Load() {
			t.Fatal("up before the retry")
		}
		l.at(27400 * time.Millisecond)
		if !l.client.up.Load() {
			t.Fatal("the retry did not verify the path")
		}
		l.at(time.Minute)
		want := []time.Duration{2 * time.Second, 2400 * time.Millisecond, 3400 * time.Millisecond, 5400 * time.Millisecond,
			9400 * time.Millisecond, 17400 * time.Millisecond, 27400 * time.Millisecond}
		if got := l.signalled(); !slices.Equal(got, want) {
			t.Fatalf("the server was told at %v, want %v", got, want)
		}
	})
}

// A path whose probes are never answered, as behind a front on another host,
// meets the rule of a lost path at 7 s: the probes at 0, 1 and 3 s are
// unanswered, the first of them 7 s ago. The client says so once, naming
// where the probes go, and tells the server nothing: no datagram went native.
func TestAPathThatNeverAnswersIsReportedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		l := startLiveness(t, func(int64) bool { return true })
		line := []string{`msg="Native UDP not answering; association using 0x83"`, "addr=" + memServer.String()}
		l.at(7*time.Second - time.Nanosecond)
		if n := logged(logs, line...); n != 0 {
			t.Fatalf("reported before the rule was met:\n%s", logs)
		}
		l.at(7 * time.Second)
		if n := logged(logs, line...); n != 1 {
			t.Fatalf("%d reports at 7 s, want 1:\n%s", n, logs)
		}
		l.at(time.Minute)
		if n := logged(logs, line...); n != 1 {
			t.Fatalf("%d reports in a minute, want 1:\n%s", n, logs)
		}
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
	})
}

// A path that was verified is not reported as never answering: not when its
// first two probes are lost and the third, at 3 s, is answered, and not when
// it is lost later, where the warning says so and its retries meet the rule
// again at 9.4 s.
func TestAVerifiedPathIsNotReportedAsNeverAnswering(t *testing.T) {
	for name, lose := range map[string]func(int64) bool{
		"verified by the third probe": func(i int64) bool { return i <= 2 },
		"lost after it was verified":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logs := captureLogs(t)
				l := startLiveness(t, lose)
				stop := make(chan struct{})
				defer close(stop)
				l.stream(stop)
				if lose == nil {
					l.at(time.Second)
					l.path.dropDown.Store(true)
				}
				l.at(30 * time.Second)
				if n := logged(logs, "Native UDP not answering"); n != 0 {
					t.Fatalf("a verified path was reported as never answering:\n%s", logs)
				}
				if lost := logged(logs, "Native UDP path lost"); (lose == nil) != (lost == 1) {
					t.Fatalf("%d losses logged:\n%s", lost, logs)
				}
			})
		})
	}
}

// The same break under the application's own traffic, with probes every
// 500 ms. From 2.1 s every datagram finds the path stale and pokes the
// watcher, and a poke probes 400 ms after the last probe, before the timer
// would: the probes at 1.5 and 2.0 s are lost, the poke at 2.4 s sends the
// third, and the one at 2.8 s finds three unanswered. The rule was checked
// only when the timer fired, and under traffic it never did. The first of
// those datagrams, at 2.1 s, tells the server too: its answers go by TCP from
// the moment the client stops hearing it, as its own datagrams do.
func TestAPathThatBreaksUnderTrafficIsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLivenessWith(t, nil, 0.5)
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.input(stop)
		l.at(1100 * time.Millisecond)
		l.path.dropDown.Store(true)
		l.at(2800*time.Millisecond - time.Nanosecond)
		if !l.client.up.Load() {
			t.Fatal("down before the third unanswered probe")
		}
		l.at(2800 * time.Millisecond)
		if got, want := l.signalled(), []time.Duration{2100 * time.Millisecond, 2800 * time.Millisecond}; !slices.Equal(got, want) {
			t.Fatalf("the server was told at %v, want %v", got, want)
		}
		// The retry probe went with the verdict, and the next is 1 s later.
		l.at(3 * time.Second)
		l.path.dropDown.Store(false)
		l.at(3800*time.Millisecond - time.Nanosecond)
		if l.client.up.Load() {
			t.Fatal("up before the retry")
		}
		l.at(3800 * time.Millisecond)
		if !l.client.up.Load() || !l.client.carry([]byte("input")) {
			t.Fatal("the retry did not bring native back")
		}
	})
}

// Two probes lost out of every three, on an active association for a minute:
// never three in a row, so never down. The first two are lost before the path
// is verified (at 0 and 1 s), the third verifies it at 3 s and is followed at
// once by the probe that says the client hears the server, and from there a
// probe goes every 400 ms: 4 + 142 by the end of the minute.
func TestLostProbesAreNotALostPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, func(i int64) bool { return i%3 != 0 })
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.at(time.Minute)
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("down at %v", got)
		}
		if !l.client.up.Load() {
			t.Fatal("the path is not up")
		}
		if n := l.path.probes.Load(); n != 146 {
			t.Fatalf("%d probes in a minute of traffic, want 146", n)
		}
	})
}

// An idle association sends one probe every 10 s for the NAT and nothing
// else, past the one that follows the first answer and brings the server's
// answers native.
func TestAnIdleAssociationOnlyKeepsTheNATOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(35 * time.Second)
		if n := l.path.probes.Load(); n != 5 {
			t.Fatalf("%d probes in 35 s of idle, want 5 (two at 0, then 10, 20 and 30 s)", n)
		}
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("an idle association told the server at %v", got)
		}
		if !l.client.up.Load() {
			t.Fatal("the path is not up")
		}
	})
}

// The first datagram after a pause probes at once. The watcher had the idle
// keepalive due at 10 s, and a path that broke under the traffic that
// followed went unnoticed until then.
func TestTrafficAfterAPauseIsProbedAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(5 * time.Second)
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		// The stream's first datagram lands at 5.01 s and is probed at once;
		// the break at 5.1 s loses the probes at 5.41, 5.81 and 6.21 s. The
		// last of them is 1.11 s after the server was last heard.
		l.at(5100 * time.Millisecond)
		l.path.dropDown.Store(true)
		l.at(6610 * time.Millisecond)
		if got, want := l.signalled(), []time.Duration{6210 * time.Millisecond, 6610 * time.Millisecond}; !slices.Equal(got, want) {
			t.Fatalf("the server was told at %v, want %v", got, want)
		}
	})
}

// A flow that speaks every 1.5 s stays native: while it is active the probes
// keep the path fresh between its datagrams.
func TestASparseFlowIsCarriedNatively(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		for i := 0; i < 6; i++ {
			l.at(100*time.Millisecond + time.Duration(i)*1500*time.Millisecond)
			if !l.client.carry([]byte("input")) {
				t.Fatalf("datagram %d went by 0x83", i)
			}
		}
		synctest.Wait()
		if n := l.path.data.Load(); n != 6 {
			t.Fatalf("%d datagrams reached the server natively, want 6", n)
		}
	})
}

// An ICMP error on the socket, or several in a row, does not stop the reader,
// and with it the probes.
func TestAnErrorOnTheSocketIsNotTheEndOfIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, func(i int64) bool { return i == 1 })
		for i := 0; i < 5; i++ {
			l.path.errs <- &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
		}
		l.at(time.Second)
		if !l.client.up.Load() {
			t.Fatal("the retry at 1 s was not heard after the errors")
		}
	})
}

// A probe says the client hears the server only while it does: the server
// takes the answers back to native on it, and a probe of a path the client
// no longer hears arrives right after the signal that took them off. The
// probe at 0 s verifies the path and is followed at once by one that hears;
// those at 0.4-1.6 s hear the stream, which stops at 1.0 s; from 2.0 s the
// client has not heard the server for a second. The retry at 3.4 s finds the
// break healed and is followed at once by one that hears.
func TestAProbeSaysWhenTheClientHearsTheServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.at(time.Second)
		l.path.dropDown.Store(true)
		l.at(3 * time.Second)
		l.path.dropDown.Store(false)
		l.at(3400 * time.Millisecond)
		ms := func(v ...int) []time.Duration {
			d := make([]time.Duration, len(v))
			for i, m := range v {
				d[i] = time.Duration(m) * time.Millisecond
			}
			return d
		}
		l.path.mu.Lock()
		heard, bare := slices.Clone(l.path.heard), slices.Clone(l.path.bare)
		l.path.mu.Unlock()
		if want := ms(0, 400, 800, 1200, 1600, 3400); !slices.Equal(heard, want) {
			t.Fatalf("probes that hear at %v, want %v", heard, want)
		}
		if want := ms(0, 2000, 2400, 3400); !slices.Equal(bare, want) {
			t.Fatalf("bare probes at %v, want %v", bare, want)
		}
	})
}

// A datagram too big for native goes by 0x83 and says nothing to the server:
// the path is fine, and the answers stay where they are.
func TestADatagramTooBigForNativeTellsTheServerNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.at(100 * time.Millisecond)
		if l.client.carry(make([]byte, l.client.session.MaxPayload()+1)) {
			t.Fatal("a datagram too big for native went native")
		}
		if !l.client.carry([]byte("input")) {
			t.Fatal("the next datagram did not go native")
		}
		l.at(time.Second)
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
	})
}

// A signal the tunnel cannot take, as behind a full send buffer, does not hold
// the probes: the path breaks at 1.0 s, the signal at 2.0 s never returns, and
// the retry at 3.4 s still finds the break healed. The watcher used to write
// the signal itself and stopped there until the stream drained (finding 5 of
// the third review).
func TestAStuckSignalDoesNotStopTheProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var tries atomic.Int32
		l := startLivenessSignalling(t, nil, 0, func() { tries.Add(1); <-release })
		t.Cleanup(func() { close(release) })
		stop := make(chan struct{})
		defer close(stop)
		l.stream(stop)
		l.at(time.Second)
		l.path.dropDown.Store(true)
		l.at(3 * time.Second)
		if l.client.up.Load() {
			t.Fatal("the path is still up")
		}
		l.path.dropDown.Store(false)
		l.at(3400 * time.Millisecond)
		if !l.client.up.Load() {
			t.Fatal("the retry did not verify the path while a signal was stuck")
		}
		if n := tries.Load(); n != 1 {
			t.Fatalf("%d signals were written, want the one that is stuck", n)
		}
	})
}
