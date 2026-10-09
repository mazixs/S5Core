package main

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caarlos0/env/v11"
)

// Plan task R4-8. The tests run in a synctest bubble with a dial that costs
// one 40 ms round trip, so what prewarm saves and when it acts are exact.

const prewarmRTT = 40 * time.Millisecond

type dialed struct {
	local  net.Conn
	closed chan struct{} // closed when the client end goes away
}

// countingServer replaces dialServer with a pipe per dial and records them.
// serve runs on the server end of each new dial; by default it drains it.
type countingServer struct {
	mu    sync.Mutex
	dials []*dialed
	serve func(remote net.Conn)
}

func drain(remote net.Conn) { _, _ = io.Copy(io.Discard, remote) }

func newCountingServer(t *testing.T) *countingServer {
	t.Helper()
	s := &countingServer{serve: drain}
	original := dialServer
	t.Cleanup(func() {
		dialServer = original
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, d := range s.dials {
			_ = d.local.Close()
		}
	})
	dialServer = func(clientParams) (net.Conn, error) {
		time.Sleep(prewarmRTT)
		local, remote := net.Pipe()
		d := &dialed{local: local, closed: make(chan struct{})}
		s.mu.Lock()
		s.dials = append(s.dials, d)
		serve := s.serve
		s.mu.Unlock()
		go func() {
			serve(remote)
			_, _ = io.Copy(io.Discard, remote)
			_ = remote.Close()
			close(d.closed)
		}()
		return local, nil
	}
	return s
}

func (s *countingServer) setServe(serve func(net.Conn)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serve = serve
}

func (s *countingServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dials)
}

func (s *countingServer) dialOf(c net.Conn) *dialed {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dials {
		if d.local == c {
			return d
		}
	}
	return nil
}

func isClosed(d *dialed) bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func prewarmParams(on bool) clientParams {
	cfg := testClientParams()
	cfg.Prewarm = on
	return cfg
}

// startPool turns a pool on for the test and off at its end.
func startPool(t *testing.T, p *prewarmPool, cfg clientParams) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p.start(ctx, cfg)
	t.Cleanup(func() {
		cancel()
		synctest.Wait()
	})
	return cancel
}

// tunnel opens and closes one tunnel's transport.
func tunnel(t *testing.T, p *prewarmPool, cfg clientParams) (net.Conn, bool) {
	t.Helper()
	c, spare, err := p.take(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	return c, spare
}

// spareOf returns the pool's spare once its dial is done.
func spareOf(t *testing.T, p *prewarmPool) *spareConn {
	t.Helper()
	time.Sleep(prewarmRTT)
	synctest.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spare == nil {
		t.Fatal("no spare")
	}
	return p.spare
}

func noSpare(t *testing.T, p *prewarmPool) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spare != nil || p.dialing {
		t.Fatalf("the pool holds a spare (%v) or is dialing one (%v)", p.spare != nil, p.dialing)
	}
}

func TestALoneTunnelOrdersNoSpare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		time.Sleep(5 * time.Minute)
		tunnel(t, &p, cfg)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := server.count(); got != 1 {
			t.Fatalf("one tunnel after a quiet spell and five quiet minutes cost %d dials, want 1", got)
		}
	})
}

func TestAPollOnceAMinuteOpensNoSpare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		for range 5 {
			tunnel(t, &p, cfg)
			time.Sleep(time.Minute)
		}
		synctest.Wait()
		if got := server.count(); got != 5 {
			t.Fatalf("five polls a minute apart cost %d dials, want 5", got)
		}
	})
}

func TestASpareSavesTheDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		tunnel(t, &p, cfg)
		tunnel(t, &p, cfg) // the second within 30 s orders a spare
		spare := spareOf(t, &p)
		if server.count() != 3 {
			t.Fatalf("%d dials, want two tunnels and one spare", server.count())
		}

		start := time.Now()
		c, onSpare, err := p.take(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took != 0 {
			t.Fatalf("taking the spare took %v, want no round trip", took)
		}
		if !onSpare || c != spare.conn {
			t.Fatal("the third tunnel did not get the spare")
		}
		_ = c.Close()
		spareOf(t, &p) // and ordered the next one
		if server.count() != 4 {
			t.Fatalf("%d dials, want the next spare ordered by the tunnel that took one", server.count())
		}
	})
}

func TestASpareIsClosedAtItsAgeAndNotReplaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)
		wasted := minutes.prewarmWasted.Load()

		tunnel(t, &p, cfg)
		ordered := time.Now()
		tunnel(t, &p, cfg)
		spare := spareOf(t, &p)
		d := server.dialOf(spare.conn)
		if spare.maxAge < prewarmAgeMin || spare.maxAge >= prewarmAgeMax {
			t.Fatalf("a spare's age is %v, want [%v, %v)", spare.maxAge, prewarmAgeMin, prewarmAgeMax)
		}

		time.Sleep(time.Until(ordered.Add(spare.maxAge - time.Nanosecond)))
		synctest.Wait()
		if isClosed(d) {
			t.Fatal("the spare was closed before its age")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if !isClosed(d) {
			t.Fatalf("the spare is still open at %v", spare.maxAge)
		}
		if got := minutes.prewarmWasted.Load() - wasted; got != 1 {
			t.Fatalf("prewarm_wasted grew by %d, want 1", got)
		}

		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if server.count() != 3 {
			t.Fatalf("%d dials, want no spare after the expired one", server.count())
		}
		c, onSpare := tunnel(t, &p, cfg)
		if onSpare || c == spare.conn {
			t.Fatal("a spare past its age was handed to a tunnel")
		}
	})
}

// The age has no single value an observer could learn as the client's.
func TestTheAgeOfASpareIsDrawnFromItsBand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		ages := map[time.Duration]bool{}
		for range 50 {
			tunnel(t, &p, cfg)
			tunnel(t, &p, cfg)
			s := spareOf(t, &p)
			if s.maxAge < prewarmAgeMin || s.maxAge >= prewarmAgeMax {
				t.Fatalf("a spare's age is %v, want [%v, %v)", s.maxAge, prewarmAgeMin, prewarmAgeMax)
			}
			ages[s.maxAge] = true
			time.Sleep(time.Minute)
		}
		if len(ages) < 40 {
			t.Fatalf("50 spares had %d distinct ages", len(ages))
		}
	})
}

func TestABurstWastesAtMostOneSpare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)
		wasted := minutes.prewarmWasted.Load()

		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				c, _, err := p.take(cfg)
				if err == nil {
					_ = c.Close()
				}
			})
		}
		wg.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := server.count(); got != 11 {
			t.Fatalf("a burst of 10 tunnels cost %d dials, want 10 and one spare", got)
		}
		if got := minutes.prewarmWasted.Load() - wasted; got != 1 {
			t.Fatalf("prewarm_wasted grew by %d after a burst, want 1", got)
		}
	})
}

func TestWithoutPrewarmEveryTunnelDialsAndNothingElse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(false)
		startPool(t, &p, cfg)

		for range 3 {
			start := time.Now()
			if _, onSpare := tunnel(t, &p, cfg); onSpare {
				t.Fatal("a spare with PREWARM=false")
			}
			if took := time.Since(start); took != prewarmRTT {
				t.Fatalf("a tunnel took %v to dial, want %v", took, prewarmRTT)
			}
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if server.count() != 3 {
			t.Fatalf("%d dials for three tunnels with PREWARM=false", server.count())
		}
	})
}

func TestASpareIsTakenOnlyByTheTransportItWasDialedFor(t *testing.T) {
	wsCfg := func() clientParams {
		cfg := prewarmParams(true)
		cfg.WSUrl = "wss://198.51.100.3/ws"
		cfg.WSMinFrame, cfg.WSMaxFrame, cfg.WSMaxJitterMs = 256, 4096, 0
		return cfg
	}
	for name, change := range map[string]func(*clientParams){
		"another node":        func(c *clientParams) { c.WSUrl = "wss://198.51.100.4/ws" },
		"another frame shape": func(c *clientParams) { c.WSMaxFrame = 8192 },
		"another jitter":      func(c *clientParams) { c.WSMaxJitterMs = 5 },
		"obfs instead":        func(c *clientParams) { c.WSUrl = "" },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newCountingServer(t)
				var p prewarmPool
				cfg := wsCfg()
				startPool(t, &p, cfg)

				tunnel(t, &p, cfg)
				tunnel(t, &p, cfg)
				d := server.dialOf(spareOf(t, &p).conn)

				other := wsCfg()
				change(&other)
				if c, onSpare := tunnel(t, &p, other); onSpare || c == d.local {
					t.Fatal("a spare was handed to a tunnel it was not dialed for")
				}
				synctest.Wait()
				if !isClosed(d) {
					t.Fatal("the spare that did not fit is still open")
				}
			})
		})
	}
}

func TestASpareDialedAfterStopIsClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		stop := startPool(t, &p, cfg)

		tunnel(t, &p, cfg)
		tunnel(t, &p, cfg) // orders a spare, still dialing
		stop()
		time.Sleep(prewarmRTT)
		synctest.Wait()
		noSpare(t, &p)
		if server.count() != 3 {
			t.Fatalf("%d dials, want the spare's dial to have finished", server.count())
		}
		for i := range 3 {
			server.mu.Lock()
			d := server.dials[i]
			server.mu.Unlock()
			if !isClosed(d) {
				t.Fatalf("dial %d is open after the client stopped", i)
			}
		}
	})
}

func TestASpareForTheNodeTheClientLeftIsClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		tunnel(t, &p, cfg)
		go func() { // orders a spare for the first node
			if c, _, err := p.take(cfg); err == nil {
				_ = c.Close()
			}
		}()
		synctest.Wait()
		moved := cfg
		moved.ServerAddr = "198.51.100.2:1443"
		tunnel(t, &p, moved) // while it is dialed, the client moves on
		synctest.Wait()
		noSpare(t, &p)
		server.mu.Lock()
		defer server.mu.Unlock()
		for i, d := range server.dials {
			if !isClosed(d) {
				t.Fatalf("dial %d is still open", i)
			}
		}
	})
}

// A stop between two tunnels forgets the first: the tunnel after a restart
// is a lone one and orders nothing. Each synctest bubble starts its clock at
// the same instant, so a pool that kept the moment of its last tunnel saw
// one in the future and took the first tunnel of the next test for a busy
// client.
func TestARestartedPoolForgetsItsLastTunnel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		stop := startPool(t, &p, cfg)

		tunnel(t, &p, cfg)
		stop()
		synctest.Wait()
		startPool(t, &p, cfg)
		tunnel(t, &p, cfg)
		time.Sleep(prewarmRTT)
		synctest.Wait()
		noSpare(t, &p)
		if got := server.count(); got != 2 {
			t.Fatalf("%d dials, want the two tunnels only", got)
		}
	})
}

// A stop and a start while a spare is dialed: the spare belongs to the pool
// that ordered it, and the restarted one closes it even when the client is
// back on the same node by the time the dial is done.
func TestASpareOrderedBeforeARestartIsClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var p prewarmPool
		cfg := prewarmParams(true)
		startPool(t, &p, cfg)

		tunnel(t, &p, cfg)
		go func() { // the second tunnel orders a spare
			if c, _, err := p.take(cfg); err == nil {
				_ = c.Close()
			}
		}()
		synctest.Wait()
		p.stop()
		startPool(t, &p, cfg)
		go func() { // the same node again, before the spare's dial is done
			if c, _, err := p.take(cfg); err == nil {
				_ = c.Close()
			}
		}()
		synctest.Wait()
		time.Sleep(prewarmRTT)
		synctest.Wait()
		noSpare(t, &p)
		server.mu.Lock()
		defer server.mu.Unlock()
		if len(server.dials) != 4 {
			t.Fatalf("%d dials, want three tunnels and one spare", len(server.dials))
		}
		for i, d := range server.dials {
			if !isClosed(d) {
				t.Fatalf("dial %d is still open", i)
			}
		}
	})
}

// A laptop that slept: the monotonic clock stood still, the wall clock did
// not. A spare older by the wall clock than its age is not handed out, and a
// sleep longer than the activity window leaves the client a quiet one.
func TestASpareThatCrossedASleepIsNotTaken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sleep   time.Duration
		ordered int // spares ordered by the tunnel after the sleep
	}{
		{"past the age of a spare", prewarmAgeMax + time.Second, 1},
		{"past the activity window", prewarmActivity + time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newCountingServer(t)
				var slept atomic.Int64
				p := prewarmPool{now: func() time.Time { return time.Now().Add(time.Duration(slept.Load())) }}
				cfg := prewarmParams(true)
				startPool(t, &p, cfg)

				tunnel(t, &p, cfg)
				tunnel(t, &p, cfg)
				spare := spareOf(t, &p)
				slept.Store(int64(tc.sleep))

				before := server.count()
				c, onSpare := tunnel(t, &p, cfg)
				if onSpare || c == spare.conn {
					t.Fatalf("a spare %v old by the wall clock was handed out", tc.sleep)
				}
				time.Sleep(prewarmRTT)
				synctest.Wait()
				if got := server.count() - before; got != 1+tc.ordered {
					t.Fatalf("%d dials after the sleep, want the tunnel's and %d spares", got, tc.ordered)
				}
			})
		})
	}
}

// The timer and a tunnel reach an expiring spare at the same instant: either
// may win, the spare is closed once and not handed out.
func TestASpareAtItsAgeIsClosedOnceWhoeverComesFirst(t *testing.T) {
	for range 20 {
		synctest.Test(t, func(t *testing.T) {
			newCountingServer(t)
			var p prewarmPool
			cfg := prewarmParams(true)
			startPool(t, &p, cfg)

			tunnel(t, &p, cfg)
			ordered := time.Now()
			tunnel(t, &p, cfg)
			spare := spareOf(t, &p)
			wasted := minutes.prewarmWasted.Load()

			time.Sleep(time.Until(ordered.Add(spare.maxAge)))
			c, onSpare, err := p.take(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			if onSpare || c == spare.conn {
				t.Fatal("a spare at its age was handed out")
			}
			synctest.Wait()
			if got := minutes.prewarmWasted.Load() - wasted; got != 1 {
				t.Fatalf("the expiring spare was counted as wasted %d times", got)
			}
		})
	}
}

// answer plays a server that accepts the greeting of a no-auth client.
func answer(t *testing.T, cfg clientParams) func(net.Conn) {
	return func(remote net.Conn) {
		conn, err := newObfsConnForTest(remote, cfg)
		if err != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte{socks5Ver, socks5NoAuth})
	}
}

func hangUp(remote net.Conn) { _ = remote.Close() }

// spareFrom puts a spare in the global pool, its server end served by serve.
func spareFrom(t *testing.T, server *countingServer, cfg clientParams, serve func(net.Conn)) *dialed {
	t.Helper()
	startPool(t, &spares, cfg)
	tunnel(t, &spares, cfg)
	server.setServe(serve)
	tunnel(t, &spares, cfg)
	d := server.dialOf(spareOf(t, &spares).conn)
	server.setServe(drain)
	return d
}

func policyParams(t *testing.T) clientParams {
	t.Helper()
	cfg := prewarmParams(true)
	cfg.WSUrl = "wss://198.51.100.3/ws"
	cfg.TransportCooldown = 5 * time.Minute
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy
	return cfg.attempt()
}

func restedTransports(p *clientPolicy) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.failedAt)
}

// readOneAndHangUp is a server that closes a spare under a tunnel that is
// writing to it, so that the write fails: on a pipe there is no kernel to say
// whether the server got anything.
func readOneAndHangUp(remote net.Conn) {
	_, _ = remote.Read(make([]byte, 1))
	_ = remote.Close()
}

// A spare the server closed before it was taken - a laptop that slept, a
// network that changed, a platform without hungUp - costs the transport
// nothing. The tunnel is set up again on a fresh dial where the server is
// proven not to have got the request: the setup failed before the request
// was written, or the stream ended without an answer to the greeting. A
// failed write without TCP_INFO proves nothing, and the tunnel fails.
func TestADeadSpareIsRetriedOnAFreshDialAndDoesNotRestTheTransport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		serve   func(net.Conn)
		phase   tunnelPhase
		retried bool
	}{
		{"closed before the dial", hangUp, phaseDial, true},
		{"ended without an answer", readAllOnceAndHangUp, phaseGreeting, true},
		{"closed under a write", readOneAndHangUp, phaseGreeting, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newCountingServer(t)
				cfg := policyParams(t)
				dead := spareFrom(t, server, cfg, tc.serve)
				used, wasted := minutes.prewarmUsed.Load(), minutes.prewarmWasted.Load()
				logs := captureLogs(t)

				server.setServe(answer(t, cfg))
				before := server.count()
				conn, _, err := dialAttempt(cfg, connectRequest())
				switch {
				case tc.retried && err != nil:
					t.Fatalf("a tunnel on a dead spare failed instead of dialing again: %v", err)
				case tc.retried:
					_ = conn.Close()
					if !strings.Contains(logs.String(), `error="`+string(tc.phase)+": ") {
						t.Fatalf("the spare did not fail in the %s:\n%s", tc.phase, logs.String())
					}
				case err == nil:
					_ = conn.Close()
					t.Fatal("a write the server may have got was repeated on a fresh dial")
				case tunnelPhaseOf(err) != tc.phase:
					t.Fatalf("the spare failed with %v, want the %s", err, tc.phase)
				}
				// The fill of the next spare may finish after the tunnel.
				time.Sleep(prewarmRTT)
				synctest.Wait()
				want := 1 // the next spare the tunnel ordered
				if tc.retried {
					want++
				}
				if got := server.count() - before; got != want {
					t.Fatalf("%d dials after a dead spare, want %d", got, want)
				}
				if !isClosed(dead) {
					t.Fatal("the dead spare is still open")
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
		})
	}
}

func TestATunnelOnASpareCountsAsUsed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := policyParams(t)
		spareFrom(t, server, cfg, answer(t, prewarmParams(true)))
		used := minutes.prewarmUsed.Load()

		before := server.count()
		start := time.Now()
		conn, _, err := dialAttempt(cfg, connectRequest())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if got := time.Since(start); got != 0 {
			t.Fatalf("a tunnel on a spare took %v to set up against an instant server", got)
		}
		time.Sleep(prewarmRTT)
		synctest.Wait()
		if got := server.count() - before; got != 1 {
			t.Fatalf("%d dials, want only the next spare", got)
		}
		if got := minutes.prewarmUsed.Load() - used; got != 1 {
			t.Fatalf("prewarm_used grew by %d, want 1", got)
		}
	})
}

// The handshake deadline belongs to the tunnel, not to the transport under
// it: a spare taken 5.9 s after it was dialed still gets the whole budget. A
// timeout on a spare is not retried and rests the transport as on a fresh
// dial: the budget ran from the take, so it says the same of the path.
func TestTheHandshakeDeadlineStartsWhenTheSpareIsTaken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		cfg := policyParams(t)
		spare := spareFrom(t, server, cfg, drain)

		// Just short of the youngest age a spare can be closed at.
		time.Sleep(prewarmAgeMin - 100*time.Millisecond - prewarmRTT)
		before := server.count()
		start := time.Now()
		_, _, err := dialAttempt(cfg, connectRequest())
		if err == nil {
			t.Fatal("a silent server completed the handshake")
		}
		if tunnelPhaseOf(err) != phaseGreeting {
			t.Fatalf("failed in phase %q, want %q: %v", tunnelPhaseOf(err), phaseGreeting, err)
		}
		if waited := time.Since(start); waited != cfg.HandshakeTimeout {
			t.Fatalf("the tunnel on a 5.9 s old spare gave up after %v, want %v from the moment it was taken", waited, cfg.HandshakeTimeout)
		}
		synctest.Wait()
		if !isClosed(spare) {
			t.Fatal("the tunnel did not run on the spare")
		}
		// The only dial is the next spare the tunnel ordered.
		if got := server.count() - before; got != 1 {
			t.Fatalf("%d dials after a timeout on a spare, want only the next spare", got)
		}
		if n := restedTransports(cfg.policy); n != 1 {
			t.Fatalf("a timeout on a spare rested %d transports, want 1", n)
		}
	})
}

// The control: the same silent server on a fresh dial does rest the
// transport, as before prewarm.
func TestATimeoutOnAFreshDialStillRestsTheTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newCountingServer(t)
		cfg := policyParams(t)
		cfg.Prewarm = false
		startPool(t, &spares, cfg)

		if _, _, err := dialAttempt(cfg, connectRequest()); err == nil {
			t.Fatal("a silent server completed the handshake")
		}
		if n := restedTransports(cfg.policy); n != 1 {
			t.Fatalf("a timeout on a fresh dial rested %d transports, want 1", n)
		}
	})
}

func TestTheMinuteSummaryReportsPrewarm(t *testing.T) {
	logs := captureLogs(t)
	var m minuteCounts
	m.prewarmUsed.Add(3)
	m.prewarmWasted.Add(1)
	m.emit("boot")
	if line := logs.String(); !strings.Contains(line, "prewarm_used=3 prewarm_wasted=1") {
		t.Fatalf("the minute summary lacks prewarm: %s", line)
	}

	logs = captureLogs(t)
	m.udp.Add(1)
	m.emit("boot")
	if line := logs.String(); strings.Contains(line, "prewarm_") {
		t.Fatalf("a minute without prewarm reports it: %s", line)
	}
}

func TestPrewarmIsOnByDefault(t *testing.T) {
	var cfg clientParams
	if err := env.ParseWithOptions(&cfg, env.Options{Environment: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if !cfg.Prewarm {
		t.Fatal("PREWARM defaults to false")
	}
}
