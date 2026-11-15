package main

import (
	"bytes"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/veil"
)

// The search for a faster route (docs/veil-spec.md, 10.6.1), in the bubble of
// native_liveness_synctest_test.go.
//
// routeNet is the network between a client with several sockets and a server
// that proves routes as pkg/nativeudp does. The answers go to one socket. A
// probe from another gets a challenge, at most one a second, and only the
// echo of its token moves the answers there; a datagram from any other socket
// is dropped, and so is one that is not the newest the server got. Every
// socket has a route of its own, with half its round trip each way.
type routeNet struct {
	server *nativeudp.Session
	start  time.Time
	rtts   []time.Duration // by the order the sockets opened, the last for the rest
	limits []int           // the longest datagram each route carries, 0 for any; the same
	mu     sync.Mutex
	socks  []*routeSock
	// current is the socket the answers go to, -1 before the first proof;
	// pending is the one challenged last.
	current, pending      int
	token                 [16]byte
	tokens                byte
	expires, challengedAt time.Time
	high                  uint64 // the newest counter, once counted
	counted               bool
	// What came to the server: the application's datagrams it took, the
	// echoes it got, and the datagrams it dropped for their address.
	data     []routeDatum
	echoes   []routeDatum
	offRoute int
	streamed []string // what the server sent to the client natively
	// The next challenge, echo or answer to an echo of a socket is lost
	// while these say so.
	loseChallenge, loseEcho, loseEchoACK func(sock int) bool
	// silence goes silent both ways from its first echo on.
	silence  int
	silenced bool
}

type routeDatum struct {
	at   time.Duration
	sock int
	d    string
}

type routeSock struct {
	net    *routeNet
	i      int
	opened time.Duration
	writes []time.Duration // with net.mu held
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (r *routeNet) rtt(i int) time.Duration { return r.rtts[min(i, len(r.rtts)-1)] }

func (r *routeNet) limit(i int) int {
	if len(r.limits) == 0 {
		return 0
	}
	return r.limits[min(i, len(r.limits)-1)]
}

func (r *routeNet) open() *routeSock {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &routeSock{net: r, i: len(r.socks), opened: time.Since(r.start), in: make(chan []byte, 4096), closed: make(chan struct{})}
	r.socks = append(r.socks, s)
	return s
}

func (s *routeSock) Write(b []byte) (int, error) {
	if s.isClosed() {
		return 0, net.ErrClosed
	}
	s.net.mu.Lock()
	s.writes = append(s.writes, time.Since(s.net.start))
	s.net.mu.Unlock()
	wire := bytes.Clone(b)
	time.AfterFunc(s.net.rtt(s.i)/2, func() { s.net.arrive(s.i, wire) })
	return len(b), nil
}

func (s *routeSock) Read(b []byte) (int, error) {
	if s.isClosed() {
		return 0, net.ErrClosed
	}
	select {
	case w := <-s.in:
		return copy(b, w), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

func (s *routeSock) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *routeSock) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: memClient.IP, Port: memClient.Port + s.i}
}
func (s *routeSock) RemoteAddr() net.Addr { return memServer }
func (s *routeSock) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// arrive is the server reading a datagram of socket i.
func (r *routeNet) arrive(i int, wire []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l := r.limit(i); l != 0 && len(wire) > l || r.silenced && i == r.silence {
		return
	}
	p, err := r.server.Open(wire)
	if err != nil {
		return
	}
	var probe nativeudp.Probe
	var extended bool
	if p.Kind == nativeudp.KindProbe {
		probe, extended = nativeudp.ParseProbe(p.Data)
		if probe.RouteEcho && i == r.silence && i != 0 {
			r.silenced = true
			return
		}
		if probe.RouteEcho && r.loseEcho != nil && r.loseEcho(i) {
			return
		}
	}
	newest := !r.counted || p.Counter > r.high
	if newest {
		r.high, r.counted = p.Counter, true
	}
	at := time.Since(r.start)
	if probe.RouteEcho {
		r.echoes = append(r.echoes, routeDatum{at: at, sock: i})
	}
	if i != r.current && (!newest || !r.follow(i, probe, p.Kind == nativeudp.KindProbe, len(wire))) {
		if p.Kind == nativeudp.KindData {
			r.offRoute++
		}
		return
	}
	switch p.Kind {
	case nativeudp.KindProbe:
		r.server.ApplyProbeLimit(probe)
		if probe.RouteEcho && r.loseEchoACK != nil && r.loseEchoACK(i) {
			return
		}
		_ = r.server.SealWriteAnswer(probe, extended, len(wire), func(w []byte) error { r.down(r.current, w); return nil })
	case nativeudp.KindData:
		r.data = append(r.data, routeDatum{at: at, sock: i, d: string(p.Data)})
	}
}

// follow is Session.follow of pkg/nativeudp.
func (r *routeNet) follow(i int, p nativeudp.Probe, isProbe bool, wire int) bool {
	if !isProbe || !p.RouteProof {
		return false
	}
	now := time.Now()
	if p.RouteEcho && now.Before(r.expires) && r.pending == i && p.RouteToken == r.token {
		r.current, r.pending, r.expires = i, -1, time.Time{}
		return true
	}
	if p.RouteEcho || !r.challengedAt.IsZero() && now.Sub(r.challengedAt) < time.Second {
		return false
	}
	r.tokens++
	r.token = [16]byte{r.tokens}
	r.pending, r.expires, r.challengedAt = i, now.Add(5*time.Second), now
	r.challenge(i, wire)
	return false
}

func (r *routeNet) challenge(i, wire int) {
	if r.loseChallenge != nil && r.loseChallenge(i) {
		return
	}
	_ = r.server.SealWriteChallenge(r.token, wire, func(w []byte) error { r.down(i, w); return nil })
}

// down sends a datagram of the server to socket i, with r.mu held.
func (r *routeNet) down(i int, wire []byte) {
	if i < 0 || r.silenced && i == r.silence {
		return
	}
	if l := r.limit(i); l != 0 && len(wire) > l {
		return
	}
	s, w := r.socks[i], bytes.Clone(wire)
	time.AfterFunc(r.rtt(i)/2, func() {
		select {
		case s.in <- w:
		case <-s.closed:
		}
	})
}

// late has the server answer a probe on socket i every 100 ms until stop is
// closed, as it would answer the probes of the route the socket had, late.
func (r *routeNet) late(i int, stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			r.mu.Lock()
			_ = r.server.SealWriteAnswer(nativeudp.Probe{Generation: 1}, true, 100, func(w []byte) error { r.down(i, w); return nil })
			r.mu.Unlock()
		}
	}()
}

// stream has the server send a numbered datagram every 10 ms to where its
// answers go, until stop is closed.
func (r *routeNet) stream(stop <-chan struct{}) {
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			r.mu.Lock()
			if r.current >= 0 {
				d := "down" + strconv.Itoa(i)
				wire, err := r.server.Seal(nil, nativeudp.KindData, []byte(d))
				if err != nil {
					panic(err)
				}
				r.down(r.current, wire)
				r.streamed = append(r.streamed, d)
			}
			r.mu.Unlock()
		}
	}()
}

// routed is an association on a routeNet: the client tries 3 candidates, and
// every probe interval is 400 ms. Its traffic runs until halt.
type routed struct {
	t      *testing.T
	start  time.Time
	net    *routeNet
	client *nativeClient
	stop   chan struct{}
	halted sync.Once
	mu     sync.Mutex
	sent   []string // by the application
	tunnel []routeDatum
	got    []string        // by the application, from the server
	told   []time.Duration // when the client decided to tell the server
}

func startRouted(t *testing.T, rtts []time.Duration, setup func(*routeNet)) *routed {
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
	r := &routeNet{server: nativeudp.NewSession(sk), start: time.Now(), rtts: rtts, current: -1, pending: -1, silence: -1}
	if setup != nil {
		setup(r)
	}
	rt := &routed{t: t, start: r.start, net: r, stop: make(chan struct{})}
	rt.client = newNativeClient(r.open(), nativeudp.NewSession(ck), func() {
		rt.mu.Lock()
		rt.told = append(rt.told, time.Since(rt.start))
		rt.mu.Unlock()
	})
	rt.client.jitter = func() float64 { return 0 }
	rt.client.candidates = 3
	rt.client.dial = func() (datagramConn, error) { return r.open(), nil }
	go rt.client.run(func(d []byte) {
		rt.mu.Lock()
		rt.got = append(rt.got, string(d))
		rt.mu.Unlock()
	})
	t.Cleanup(func() { rt.halt(); rt.client.close(); synctest.Wait() })
	return rt
}

func (rt *routed) at(d time.Duration) {
	time.Sleep(time.Until(rt.start.Add(d)))
	synctest.Wait()
}

func (rt *routed) halt() { rt.halted.Do(func() { close(rt.stop) }) }

// input has the application send a numbered datagram every 10 ms until halt,
// by 0x83 where the client leaves it there.
func (rt *routed) input() {
	go func() {
		for i := 0; ; i++ {
			select {
			case <-rt.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			d := "up" + strconv.Itoa(i)
			how := rt.client.carry([]byte(d))
			rt.mu.Lock()
			rt.sent = append(rt.sent, d)
			if how == byTunnel {
				rt.tunnel = append(rt.tunnel, routeDatum{at: time.Since(rt.start), d: d})
			}
			rt.mu.Unlock()
			if how == dropped {
				rt.t.Errorf("%s was dropped", d)
			}
		}
	}()
}

// both has the traffic run both ways until halt.
func (rt *routed) both() {
	rt.input()
	rt.net.stream(rt.stop)
}

// traffic runs both ways from now until until, then waits a second for what
// is on the way.
func (rt *routed) traffic(until time.Duration) {
	rt.both()
	rt.at(until)
	rt.halt()
	rt.at(until + time.Second)
}

// exactlyOnce fails the test for what of want got lacks or holds twice.
func exactlyOnce(t *testing.T, way string, want, got []string) {
	t.Helper()
	count := map[string]int{}
	for _, d := range got {
		count[d]++
	}
	var missing, twice []string
	for _, d := range want {
		switch count[d] {
		case 0:
			missing = append(missing, d)
		case 1:
		default:
			twice = append(twice, d)
		}
	}
	if len(missing) != 0 || len(twice) != 0 || len(want) == 0 {
		t.Errorf("%s: %d sent, missing %v, twice %v", way, len(want), missing, twice)
	}
}

// delivered checks that no datagram was lost or doubled either way, and that
// the server dropped none for the address it came from.
func (rt *routed) delivered() {
	rt.t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	r := rt.net
	r.mu.Lock()
	defer r.mu.Unlock()
	up := slices.Clone(r.data)
	got := make([]string, 0, len(up)+len(rt.tunnel))
	for _, d := range slices.Concat(up, rt.tunnel) {
		got = append(got, d.d)
	}
	exactlyOnce(rt.t, "to the server", rt.sent, got)
	exactlyOnce(rt.t, "to the application", r.streamed, rt.got)
	if r.offRoute != 0 {
		rt.t.Errorf("the server dropped %d datagrams for their address", r.offRoute)
	}
}

func (rt *routed) stat(name string) any {
	stats := rt.client.logStats()
	for i := 0; i < len(stats); i += 2 {
		if stats[i] == name {
			return stats[i+1]
		}
	}
	rt.t.Fatalf("no %s in the closing line", name)
	return nil
}

func (rt *routed) socket(i int) *routeSock {
	rt.net.mu.Lock()
	defer rt.net.mu.Unlock()
	if i >= len(rt.net.socks) {
		rt.t.Fatalf("socket %d was never opened", i)
	}
	return rt.net.socks[i]
}

// byTunnelAfter is when the first and the last datagram the client left to
// 0x83 after from went; the test fails if there was none.
func (rt *routed) byTunnelAfter(from time.Duration) (first, last time.Duration) {
	rt.t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, d := range rt.tunnel {
		if d.at > from {
			if first == 0 {
				first = d.at
			}
			last = d.at
		}
	}
	if first == 0 {
		rt.t.Fatalf("no datagram went by 0x83 after %v", from)
	}
	return first, last
}

func (rt *routed) noTunnelAfter(from time.Duration) {
	rt.t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, d := range rt.tunnel {
		if d.at > from {
			rt.t.Fatalf("%s went by 0x83 at %v", d.d, d.at)
		}
	}
}

// serving is the socket the server answers.
func (rt *routed) serving() int {
	rt.net.mu.Lock()
	defer rt.net.mu.Unlock()
	return rt.net.current
}

func (rt *routed) echoesFrom(sock int) []time.Duration {
	rt.net.mu.Lock()
	defer rt.net.mu.Unlock()
	var at []time.Duration
	for _, e := range rt.net.echoes {
		if e.sock == sock {
			at = append(at, e.at)
		}
	}
	return at
}

// lastFrom is when the last datagram of the socket reached the server.
func (rt *routed) lastFrom(sock int) time.Duration {
	rt.net.mu.Lock()
	defer rt.net.mu.Unlock()
	var last time.Duration
	for _, d := range rt.net.data {
		if d.sock == sock {
			last = d.at
		}
	}
	return last
}

const ms = time.Millisecond

// On a path of two routes, 86 and 57 ms, the first candidate at 3 s lands on
// the faster one. Its challenge comes 57 ms after its probe; from then the
// application's datagrams go by 0x83 and nothing leaves the old socket, and
// the echo goes 86 ms later, after the last native datagram of the old route
// reached the server. The server moves its answers at the echo, and the
// client moves its datagrams once the answer to it comes, 57 ms on. Nothing
// is lost or doubled either way, the old socket is read for a second and
// closed, and a challenge it gets then is not echoed.
func TestAFasterRouteTakesTheAssociation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, nil)
		rt.traffic(6 * time.Second)
		rt.delivered()
		if rt.serving() != 1 || rt.client.current().datagramConn != rt.socket(1) {
			t.Fatalf("the server answers socket %d", rt.serving())
		}
		echoes := rt.echoesFrom(1)
		if len(echoes) != 1 {
			t.Fatalf("the candidate echoed at %v", echoes)
		}
		if last := rt.lastFrom(0); echoes[0]-last < 86*ms/2 {
			t.Fatalf("the old route's last datagram reached the server at %v, the echo at %v", last, echoes[0])
		}
		if rt.lastFrom(1) < 5*time.Second {
			t.Fatal("the datagrams did not go by the new socket after the move")
		}
		if !rt.socket(0).isClosed() || rt.socket(1).isClosed() {
			t.Fatal("the old socket is open, or the new one closed")
		}
		if from, to := rt.byTunnelAfter(time.Second); to-from > 86*ms+57*ms+10*ms {
			t.Fatalf("the move sent by 0x83 from %v to %v", from, to)
		}
		if n := logged(logs, "Native UDP moved to a faster route", "rtt_before=86ms", "rtt_after=57ms", "candidate=1"); n != 1 {
			t.Fatalf("%d lines of the move:\n%s", n, logs)
		}
		if strings.Contains(logs.String(), memClient.IP.String()) {
			t.Fatal("a log line names the client's address")
		}
		if rt.stat("native_route_candidates") != uint64(1) || rt.stat("native_route_moved") != true {
			t.Fatal("the closing line does not say the association moved")
		}
	})
}

// A challenge on the replaced socket, while it is still read, is not the
// path's: answered, it would take the server back to the old route.
func TestTheReplacedSocketDoesNotAnswerAChallenge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, nil)
		rt.input()
		rt.at(3500 * time.Millisecond)
		if rt.serving() != 1 || rt.socket(0).isClosed() {
			t.Fatal("the association did not move, or the old socket is not read")
		}
		r := rt.net
		r.mu.Lock()
		r.tokens++
		r.token, r.pending, r.expires = [16]byte{r.tokens}, 0, time.Now().Add(5*time.Second)
		r.challenge(0, nativeudp.MaxWire)
		r.mu.Unlock()
		rt.at(4 * time.Second)
		if rt.serving() != 1 || len(rt.echoesFrom(0)) != 1 {
			t.Fatalf("the replaced socket answered the challenge: the server answers socket %d", rt.serving())
		}
	})
}

// A candidate wins only if it is faster by 10 ms, or by 15% of the round
// trip if that is more: one measurement is enough, since noise only adds to
// a round trip. A candidate that does not win is closed before its challenge
// comes, its token never returns, and the association goes on as it was:
// three candidates 1.2 s apart, and not a datagram by 0x83.
func TestACandidateMustBeFasterByAMargin(t *testing.T) {
	for _, c := range []struct {
		old, candidate time.Duration
		moves          bool
	}{
		// 15% of 40 ms is 6 ms, less than 10.
		{40 * ms, 33 * ms, false},
		{40 * ms, 29 * ms, true},
		// 15% of 100 ms is 15 ms, more than 10.
		{100 * ms, 86 * ms, false},
		{100 * ms, 84 * ms, true},
	} {
		t.Run(c.old.String()+" "+c.candidate.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := startRouted(t, []time.Duration{c.old, c.candidate}, nil)
				rt.traffic(10 * time.Second)
				rt.delivered()
				if moved := rt.serving() != 0; moved != c.moves {
					t.Fatalf("moved %v, want %v", moved, c.moves)
				}
				if c.moves {
					return
				}
				for i := 1; i <= 3; i++ {
					if !rt.socket(i).isClosed() || len(rt.echoesFrom(i)) != 0 {
						t.Fatalf("candidate %d is open or echoed", i)
					}
					if gap := rt.socket(i).opened - rt.socket(i-1).opened; i > 1 && gap < nativeRouteEvery {
						t.Fatalf("candidate %d went %v after the one before", i, gap)
					}
				}
				rt.net.mu.Lock()
				opened := len(rt.net.socks)
				rt.net.mu.Unlock()
				if opened != 4 || rt.stat("native_route_candidates") != uint64(3) || rt.stat("native_route_moved") != false {
					t.Fatalf("%d sockets, the closing line %v", opened, rt.client.logStats())
				}
				rt.noTunnelAfter(time.Second)
			})
		})
	}
}

// The challenge of the first candidate is lost: it is closed when a winner's
// would have come, and nothing changes. The second, 1.2 s later, wins.
func TestALostChallengeCostsTheCandidateOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, func(r *routeNet) {
			r.loseChallenge = func(sock int) bool { return sock == 1 }
		})
		rt.both()
		rt.at(4 * time.Second)
		if !rt.socket(1).isClosed() || len(rt.echoesFrom(1)) != 0 || rt.serving() != 0 {
			t.Fatal("the candidate without a challenge changed something")
		}
		rt.noTunnelAfter(time.Second)
		rt.at(6 * time.Second)
		rt.halt()
		rt.at(7 * time.Second)
		rt.delivered()
		if rt.serving() != 2 || logged(logs, "Native UDP moved to a faster route", "candidate=2") != 1 {
			t.Fatalf("the second candidate did not take the association: the server answers %d", rt.serving())
		}
	})
}

// The echo is lost. The server stays on the old route and the client on the
// new socket: its next probes are ignored while the challenge it had is under
// a second old, then one is challenged again, the client echoes at once, and
// the move is done. The datagrams go by 0x83 meanwhile, and the old socket is
// read until the server answers on the new one.
func TestALostEchoIsProvedAgainOnTheNewSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var lost atomic.Bool
		rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, func(r *routeNet) {
			r.loseEcho = func(sock int) bool { return sock == 1 && !lost.Swap(true) }
		})
		rt.traffic(8 * time.Second)
		rt.delivered()
		if !lost.Load() || rt.serving() != 1 || len(rt.echoesFrom(1)) != 1 {
			t.Fatalf("lost %v, the server answers %d, echoes %v", lost.Load(), rt.serving(), rt.echoesFrom(1))
		}
		if !rt.socket(0).isClosed() || rt.stat("native_route_moved") != true || !rt.client.up.Load() {
			t.Fatal("the move was not finished on the new socket")
		}
		if rt.lastFrom(0) > rt.echoesFrom(1)[0] {
			t.Fatal("the old socket sent after the move")
		}
	})
}

// The answer to the echo is lost. The server moved at the echo, and the next
// probe of the new socket, 400 ms later, is answered there.
func TestALostAnswerToTheEchoIsTheNextProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var lost atomic.Bool
		rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, func(r *routeNet) {
			r.loseEchoACK = func(sock int) bool { return sock == 1 && !lost.Swap(true) }
		})
		rt.traffic(6 * time.Second)
		rt.delivered()
		if !lost.Load() || rt.serving() != 1 || rt.stat("native_route_moved") != true || !rt.socket(0).isClosed() {
			t.Fatalf("lost %v, the server answers %d", lost.Load(), rt.serving())
		}
		if from, to := rt.byTunnelAfter(time.Second); to-from > 86*ms+nativeActiveEvery+57*ms+10*ms {
			t.Fatalf("the move sent by 0x83 from %v to %v", from, to)
		}
	})
}

// The new route goes silent at the echo, and the path is judged there by its
// own round trips: the answers that still reach the replaced socket are the
// old route's, and so is its round trip of 200 ms. The client stops hearing
// the server 250 ms after its second probe in a row went unanswered, not
// twice 200 ms after, and the path is lost there by the usual rule. The old
// socket goes with it: nothing would answer on it once the server is told.
// No datagram of the application is lost.
func TestANewRouteThatGoesSilentIsLostThere(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		rt := startRouted(t, []time.Duration{200 * ms, 57 * ms}, func(r *routeNet) { r.silence = 1 })
		rt.input()
		rt.at(3500 * time.Millisecond)
		rt.net.mu.Lock()
		silenced := rt.net.silenced
		rt.net.mu.Unlock()
		if !silenced || rt.socket(0).isClosed() || !rt.client.up.Load() {
			t.Fatal("the old socket went before the path was lost")
		}
		rt.mu.Lock()
		before := len(rt.told)
		rt.mu.Unlock()
		rt.net.late(0, rt.stop)
		rt.at(6 * time.Second)
		rt.halt()
		rt.at(7 * time.Second)
		if rt.client.up.Load() || logged(logs, "Native UDP path lost") != 1 || !rt.socket(0).isClosed() {
			t.Fatal("the silent route was not lost, or the old socket is open")
		}
		if rt.stat("native_route_moved") != false || rt.client.current().datagramConn != rt.socket(1) {
			t.Fatal("the path left the new socket")
		}
		rt.mu.Lock()
		defer rt.mu.Unlock()
		rt.net.mu.Lock()
		defer rt.net.mu.Unlock()
		// The candidate's probe, the echo, then the probes of the path.
		probes := rt.net.socks[1].writes
		if len(rt.told) <= before || len(probes) < 4 || rt.told[before] <= probes[3] || rt.told[before] > probes[3]+nativeAnswerWait {
			t.Fatalf("told at %v, the new route's probes at %v", rt.told[before:], probes)
		}
		got := []string{}
		for _, d := range slices.Concat(rt.net.data, rt.tunnel) {
			got = append(got, d.d)
		}
		exactlyOnce(t, "to the server", rt.sent, got)
	})
}

// After a move the limit of the new route is searched with a generation of
// its own, and the one found is agreed whether it is lower or higher.
func TestTheLimitOfTheNewRouteIsAgreed(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits []int
	}{
		{"narrower", []int{0, 1300}},
		{"wider", []int{1300, 0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := startRouted(t, []time.Duration{86 * ms, 57 * ms}, func(r *routeNet) { r.limits = c.limits })
				rt.input()
				rt.at(2 * time.Second)
				before := rt.client.session.Limit()
				rt.at(6 * time.Second)
				rt.halt()
				rt.at(7 * time.Second)
				path := rt.net.limit(1)
				if path == 0 {
					path = nativeudp.MaxWire
				}
				limit := rt.client.session.Limit()
				generation, agreed := rt.net.server.NegotiatedLimit()
				if rt.serving() != 1 || limit > path || limit < path-34 || agreed != limit || rt.net.server.Limit() != limit || generation < 2 {
					t.Fatalf("limit %d before, %d after on a route of %d; the server's %d, generation %d", before, limit, path, agreed, generation)
				}
				if l := rt.client.carry(make([]byte, rt.client.session.MaxPayload())); l != byNative {
					t.Fatal("the longest payload of the new limit did not go native")
				}
			})
		})
	}
}

// startSearching is a proving server with the search on a path of 30 ms, and
// a client whose candidates are counted and never open.
func startSearching(t *testing.T, candidates int, setup func(*memPath)) (*liveness, *atomic.Int64) {
	t.Helper()
	l := newLiveness(t, nil, 0, nil, nil, func(p *memPath) {
		p.sizes, p.proveRoute, p.delay = true, true, 30*ms
		if setup != nil {
			setup(p)
		}
	})
	dials := new(atomic.Int64)
	l.client.candidates = candidates
	l.client.dial = func() (datagramConn, error) {
		dials.Add(1)
		return nil, errors.New("no second route here")
	}
	go l.client.run(func([]byte) {})
	return l, dials
}

// No candidate goes where the search cannot gain or is not wanted: with a
// server that does not prove routes or answers as 2.3.0-rc1 does, with
// UDP_NATIVE_ROUTE_CANDIDATES=0, on an association that is idle. One that
// wakes up searches within a second.
func TestNoCandidateGoesWhereTheSearchHasNoPlace(t *testing.T) {
	for name, c := range map[string]struct {
		candidates int
		traffic    bool
		setup      func(*memPath)
	}{
		"server without route proof": {3, true, func(p *memPath) { p.proveRoute = false }},
		"legacy server":              {3, true, func(p *memPath) { p.proveRoute, p.sizes = false, false }},
		"no candidates":              {0, true, nil},
		"idle association":           {3, false, nil},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l, dials := startSearching(t, c.candidates, c.setup)
				stop := make(chan struct{})
				defer close(stop)
				if c.traffic {
					l.input(stop)
				}
				l.at(30 * time.Second)
				if n := dials.Load(); n != 0 || !l.client.up.Load() {
					t.Fatalf("%d candidates, path up %v", n, l.client.up.Load())
				}
				if !c.traffic {
					l.input(stop)
					l.at(31 * time.Second)
					if dials.Load() != 1 {
						t.Fatal("the association woke up and did not search")
					}
				}
			})
		})
	}
}

// A young association does not search: the first candidate goes at 3 s.
func TestTheSearchWaitsForTheAssociationToLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, dials := startSearching(t, 3, nil)
		stop := make(chan struct{})
		defer close(stop)
		l.input(stop)
		l.at(nativeRouteAfter - time.Nanosecond)
		if dials.Load() != 0 {
			t.Fatal("a candidate before 3 s")
		}
		l.at(nativeRouteAfter + 100*ms)
		if dials.Load() != 1 {
			t.Fatalf("%d candidates at 3 s", dials.Load())
		}
	})
}
