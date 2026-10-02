package main

import (
	"encoding/binary"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
)

// The findings of docs/reports/v2.3-rc1-audit-2026-09-26.md on the client, in
// the bubble of native_liveness_synctest_test.go. The audit's reproductions
// asserted the defects; these assert their absence.

// routeModel is where the server sends its answers, by the rule of
// answerPath in internal/socks5: a heard probe or native datagram with a
// counter below the last loss signal's is stale, and so is a loss signal
// whose counter is not above the highest heard.
type routeModel struct {
	mu                sync.Mutex
	native            bool
	heard, lost       uint64
	hasHeard, hasLost bool
}

func (r *routeModel) Heard(c uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasLost && c < r.lost {
		return
	}
	r.heard, r.hasHeard = max(r.heard, c), true
	r.native = true
}

func (r *routeModel) Lost(next uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lost, r.hasLost = max(r.lost, next), true
	if r.hasHeard && next <= r.heard {
		return
	}
	r.native = false
}

func (r *routeModel) Native() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.native
}

// serve has the server answer every 10 ms by the route, as a game server
// does to a client that only listens, until stop is closed. An answer by TCP
// reaches the client as goroutine B of the association hands it over.
func (l *liveness) serve(route *routeModel, stop <-chan struct{}) (native, tcp *atomic.Int64) {
	native, tcp = new(atomic.Int64), new(atomic.Int64)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				if route.Native() {
					native.Add(1)
					l.path.answer(nativeudp.KindData, []byte("state"))
				} else {
					tcp.Add(1)
					l.client.tcpAnswer(len("state"))
				}
			}
		}
	}()
	return native, tcp
}

// Two heard probes lost in a row, on an association that only listens: the
// server keeps answering by TCP until a probe reaches it. The next probe
// hears the server (one lost answer does not make the client deaf), and
// the answers by TCP keep the association active, so it goes within one
// active interval. It used to take the idle keepalive, whose probe was bare
// by then, and the answers stayed on TCP for good (finding F2).
func TestTwoLostHeardProbesDoNotStrandTheAnswersOnTCP(t *testing.T) {
	for _, c := range []struct {
		name   string
		jitter float64
		back   time.Duration
	}{{"probes every 400 ms", 0, 800 * time.Millisecond}, {"probes every 580 ms", 0.9, 1160 * time.Millisecond}} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var route routeModel
				// The first two heard probes are lost with their answers.
				var heard atomic.Int32
				var losing atomic.Bool
				l := startLivenessOn(t, func(int64) bool { return losing.Swap(false) }, c.jitter, nil, func(counter uint64) {
					if heard.Add(1) <= 2 {
						losing.Store(true)
						return
					}
					route.Heard(counter)
				})
				stop := make(chan struct{})
				defer close(stop)
				native, _ := l.serve(&route, stop)
				l.at(c.back - time.Nanosecond)
				if route.Native() {
					t.Fatal("native before the third heard probe")
				}
				l.at(c.back)
				if !route.Native() {
					t.Fatalf("the answers were not native at %v", c.back)
				}
				l.at(60 * time.Second)
				if !route.Native() || native.Load() < 5800 {
					t.Fatalf("native %v with %d native answers in a minute", route.Native(), native.Load())
				}
			})
		})
	}
}

// A signal decided before the path came back, and written only after it, does
// not take the answers back to TCP: it carries the counter of its decision,
// which the heard probe after the recovery outranks. The audit held the
// signal from 2.0 to 6 s and the answers stayed on TCP for the minute after
// (finding F2).
func TestALateSignalDoesNotTakeTheAnswersBackToTCP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var route routeModel
		var pending atomic.Bool
		l := startLivenessOn(t, nil, 0, func() { pending.Store(true) }, route.Heard)
		stop := make(chan struct{})
		defer close(stop)
		native, tcp := l.serve(&route, stop)
		l.at(time.Second)
		l.path.dropDown.Store(true)
		l.at(3 * time.Second)
		l.path.dropDown.Store(false)
		l.at(3400 * time.Millisecond)
		if !l.client.up.Load() || !route.Native() {
			t.Fatal("the path did not recover")
		}
		if !pending.Load() {
			t.Fatal("the client never decided to tell")
		}
		// The stream writes the signal now, as TunnelWriter would: built
		// when it is written, from the counter of the last decision.
		l.at(6 * time.Second)
		route.Lost(binary.BigEndian.Uint64(l.client.signalFrame()[2:]))
		before := tcp.Load()
		l.at(66 * time.Second)
		if !route.Native() || tcp.Load() != before || native.Load() < 5900 {
			t.Fatalf("after the late signal: native %v, %d answers by TCP, %d native",
				route.Native(), tcp.Load()-before, native.Load())
		}
	})
}

// The signal carries the counter of the client's next datagram when it
// decided, not when the frame is written: what it sealed in between says
// the opposite and is newer. A later decision carries its own.
func TestTheSignalCarriesTheCounterOfItsDecision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(100 * time.Millisecond)
		next := func() uint64 { return binary.BigEndian.Uint64(l.client.signalFrame()[2:]) }
		decided := l.client.session.Next()
		l.client.tell(true)
		for range 3 {
			if err := l.client.send(nativeudp.KindData, []byte("input")); err != nil {
				t.Fatal(err)
			}
		}
		if got := next(); got != decided {
			t.Fatalf("the signal carries %d, want %d of its decision", got, decided)
		}
		later := l.client.session.Next()
		l.client.tell(true)
		if got := next(); got != later {
			t.Fatalf("the signal carries %d, want %d of the later decision", got, later)
		}
	})
}

// One lost probe answer diverts no datagram, whether or not the server's
// data keeps coming: the client stops hearing only once two probes in a row
// are overdue. It used to divert every datagram from a second after the last
// packet until the next answer (finding F3).
func TestOneLostProbeKeepsTheDatagramsNative(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "the client only sends"
		if streaming {
			name = "the server sends too"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := startLivenessWith(t, func(i int64) bool { return i == 4 }, 0.9)
				stop := make(chan struct{})
				defer close(stop)
				if streaming {
					l.stream(stop)
				}
				for tick := 1; tick <= 200; tick++ {
					l.at(time.Duration(tick) * 10 * time.Millisecond)
					if l.client.carry([]byte("input")) != byNative {
						t.Fatalf("the datagram at %v went by 0x83", time.Duration(tick)*10*time.Millisecond)
					}
				}
				if got := l.signalled(); len(got) != 0 {
					t.Fatalf("the server was told at %v", got)
				}
			})
		})
	}
}

// The same at a probe RTT of 50 ms, where the lost answer leaves the client
// without a packet for longer.
func TestOneLostProbeAtALongerRTTKeepsTheDatagramsNative(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var l *liveness
		ready := make(chan struct{})
		l = startLivenessWith(t, func(i int64) bool {
			<-ready
			if i != 4 {
				go func() { time.Sleep(50 * time.Millisecond); l.path.answer(nativeudp.KindProbeAck, nil) }()
			}
			return true
		}, 0.9)
		close(ready)
		l.at(100 * time.Millisecond)
		for tick := 1; tick <= 200; tick++ {
			l.at(100*time.Millisecond + time.Duration(tick)*10*time.Millisecond)
			if l.client.carry([]byte("input")) != byNative {
				t.Fatalf("the datagram at %v went by 0x83", time.Since(l.start))
			}
		}
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
	})
}

// The first datagram after a pause goes native: the probes of the idle
// association were answered, so nothing says the path is gone. It used to go
// by 0x83, a second after the last packet being all the client asked
// (finding F3).
func TestTheFirstDatagramAfterAPauseGoesNative(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(5 * time.Second)
		if l.client.carry([]byte("first")) != byNative {
			t.Fatal("the first datagram after the pause went by 0x83")
		}
		if got := l.signalled(); len(got) != 0 {
			t.Fatalf("the server was told at %v", got)
		}
	})
}

// The line that ends an association says which path its datagrams took: the
// application sees them delivered either way.
func TestTheClosingLineSaysWhichPathTheDatagramsTook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(100 * time.Millisecond)
		if l.client.carry(make([]byte, l.client.session.MaxPayload()+1)) != dropped {
			t.Fatal("a datagram past the native payload was not dropped")
		}
		if l.client.carry([]byte("input")) != byNative {
			t.Fatal("a datagram of a verified path went by 0x83")
		}
		l.path.answer(nativeudp.KindData, []byte("state"))
		l.client.tcpAnswer(5)
		l.path.dropDown.Store(true)
		l.at(5 * time.Second)
		if l.client.carry([]byte("input")) == byNative {
			t.Fatal("a datagram of a lost path went native")
		}
		stats := l.client.logStats()
		got := map[string]any{}
		for i := 0; i < len(stats); i += 2 {
			got[stats[i].(string)] = stats[i+1]
		}
		want := map[string]any{"native_sent": uint64(1), "tcp_sent_oversize": uint64(0), "tcp_sent_other": uint64(1),
			"native_received": uint64(1), "tcp_received": uint64(1), "tunnel_drops": uint64(0),
			"native_limit": nativeudp.MaxWire, "size_probes": uint64(0),
			"dropped_oversize_sent": uint64(1), "dropped_oversize_received": uint64(0)}
		if !maps.Equal(got, want) {
			t.Fatalf("closing line %v, want %v", got, want)
		}
	})
}
