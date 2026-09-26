package main

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
)

// The limit of native (docs/veil-spec.md, 10.7), in the bubble: the path in
// memory answers like a server with the search and carries up to limit
// bytes both ways.

func startSized(t *testing.T, limit int, loseSized func(int) bool) *liveness {
	t.Helper()
	return startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) {
		p.sizes, p.limit, p.loseSized = true, limit, loseSized
	})
}

func (l *liveness) announced() []int {
	l.path.mu.Lock()
	defer l.path.mu.Unlock()
	return slices.Clone(l.path.announced)
}

// On a narrow path the client finds a limit no longer than the path, tells
// the server, and both ends keep to it: the longest payload goes native, one
// byte more is dropped.
func TestTheClientFindsTheLimitOfANarrowPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const path = 1357
		l := startSized(t, path, nil)
		l.at(200 * time.Millisecond)
		limit := l.client.session.Limit()
		if limit > path || limit < path-34 {
			t.Fatalf("limit %d on a path of %d", limit, path)
		}
		if got := l.announced(); len(got) == 0 || got[0] != limit {
			t.Fatalf("the probes announced %v, want %d", got, limit)
		}
		if l.path.server.Limit() != limit {
			t.Fatalf("the server keeps to %d, the client found %d", l.path.server.Limit(), limit)
		}
		if n := l.client.stats.sizeProbes.Load(); n != 11 && n != 15 {
			t.Fatalf("%d size probes on a narrow path", n)
		}
		if l.client.carry(make([]byte, l.client.session.MaxPayload())) != byNative {
			t.Fatal("the longest payload did not go native")
		}
		if l.client.carry(make([]byte, l.client.session.MaxPayload()+1)) != dropped {
			t.Fatal("a payload past the limit was not dropped")
		}
		synctest.Wait()
		if l.path.data.Load() != 1 {
			t.Fatalf("%d datagrams reached the server", l.path.data.Load())
		}
	})
}

// Where the PTB for a probe past the path gets through, the socket fails its
// next call with EMSGSIZE, and that call is often the control of the round.
// Without a second write each round lost its control, and three of them
// ended the search at 1200 (stand of M-1, paths 1358 and 1400 with PTB).
func TestAPTBDoesNotCostTheSearchItsControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const path = 1357
		l := startLivenessPath(t, nil, 0, nil, nil, func(p *memPath) {
			p.sizes, p.limit, p.ptb = true, path, true
		})
		l.at(200 * time.Millisecond)
		if limit := l.client.session.Limit(); limit > path || limit < path-34 {
			t.Fatalf("limit %d on a path of %d with PTB", limit, path)
		}
		if l.path.refused.Load() == 0 {
			t.Fatal("no call failed with EMSGSIZE: the test did not model the PTB")
		}
		if n := l.client.stats.sizeProbes.Load(); n != 11 && n != 15 {
			t.Fatalf("%d size probes on a narrow path with PTB", n)
		}
	})
}

// On a path that carries 1500 one round finds the top of the range: every
// probe is answered at once, and the round ends with its last answer.
func TestOneRoundFindsTheLimitOfAWidePath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startSized(t, 0, nil)
		synctest.Wait()
		limit := l.client.session.Limit()
		if limit < nativeudp.MaxWire-8 || limit > nativeudp.MaxWire {
			t.Fatalf("limit %d on a wide path", limit)
		}
		if n := l.client.stats.sizeProbes.Load(); n != 7 {
			t.Fatalf("%d size probes on a wide path", n)
		}
		if got := l.announced(); len(got) != 1 || got[0] != limit {
			t.Fatalf("the probes announced %v", got)
		}
		if !l.client.bounded.Load() {
			t.Fatal("a wide path sends long datagrams by 0x83")
		}
	})
}

// A round whose control went unanswered decides nothing and goes again at
// once, when it is due: max(2 x srtt, 250 ms) after it went out.
func TestARoundWithoutItsControlGoesAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		controls := 0
		l := startSized(t, 0, func(size int) bool {
			if size > 200 {
				return false
			}
			controls++
			return controls == 1
		})
		l.at(250*time.Millisecond - time.Nanosecond)
		if n := l.client.stats.sizeProbes.Load(); n != 7 || len(l.announced()) != 0 {
			t.Fatalf("%d size probes and announced %v before the round was due", n, l.announced())
		}
		l.at(250 * time.Millisecond)
		if n := l.client.stats.sizeProbes.Load(); n != 14 {
			t.Fatalf("%d size probes once the round was due", n)
		}
		if got := l.announced(); len(got) != 1 || got[0] < nativeudp.MaxWire-8 {
			t.Fatalf("the probes announced %v", got)
		}
	})
}

// Below the floor the smallest QUIC packet does not fit native, and the rule
// stays the same: long datagrams are dropped both ways. Sending them by 0x83
// from the start had the search of quic-go take the stream for the path again
// (stand of M-1, IPv6 1280), where a browser whose QUIC does not come up uses
// TCP.
func TestBelowTheFloorTheRuleIsTheSame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		l := startSized(t, 1240, nil)
		l.at(time.Second)
		if l.client.session.Limit() > 1240 {
			t.Fatalf("limit %d on a path of 1240", l.client.session.Limit())
		}
		if l.client.carry(make([]byte, l.client.session.MaxPayload()+1)) != dropped {
			t.Fatal("a long datagram below the floor was not dropped")
		}
		if l.client.tcpAnswer(nativeudp.MaxWire) {
			t.Fatal("a long answer below the floor was delivered")
		}
		if logged(logs, "narrower than the smallest QUIC packet") != 1 {
			t.Fatalf("logs:\n%s", logs)
		}
	})
}

// A server that answers probes with nothing predates the search: the client
// sends it the probes it reads and looks for no limit.
func TestAServerWithoutTheSearchIsNotSearched(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := startLiveness(t, nil)
		l.at(2 * time.Second)
		if l.client.server.Load() != serverLegacy {
			t.Fatal("an empty answer did not mark the server")
		}
		if n := l.client.stats.sizeProbes.Load(); n != 0 {
			t.Fatalf("%d size probes to a server without the search", n)
		}
		l.path.mu.Lock()
		heard := len(l.path.heard)
		l.path.mu.Unlock()
		if heard == 0 {
			t.Fatal("the server never heard ProbeHeard in the form it reads")
		}
		if l.client.session.Limit() != nativeudp.MaxWire || !l.client.bounded.Load() {
			t.Fatal("the limit of a server without the search is not MaxWire")
		}
	})
}

// Long datagrams are dropped both ways until the eighth of one direction:
// then they go by 0x83 to the end of the association, with one line.
func TestTheEighthDroppedDatagramMovesTheLongOnesTo0x83(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		l := startLiveness(t, nil)
		l.at(100 * time.Millisecond)
		long := l.client.session.MaxPayload() + 1
		for i := 1; i < nativeOversizeDrops; i++ {
			if l.client.tcpAnswer(long) {
				t.Fatalf("long answer %d was delivered", i)
			}
		}
		for i := 1; i <= nativeOversizeDrops; i++ {
			if l.client.carry(make([]byte, long)) != dropped {
				t.Fatalf("long datagram %d was not dropped", i)
			}
		}
		if l.client.carry(make([]byte, long)) != byTunnel || !l.client.tcpAnswer(long) {
			t.Fatal("long datagrams after the eighth did not go by 0x83")
		}
		if l.client.carry([]byte("input")) != byNative {
			t.Fatal("a short datagram left native")
		}
		if logged(logs, "keeps sending datagrams longer than native carries") != 1 {
			t.Fatalf("logs:\n%s", logs)
		}
		if l.client.stats.droppedSent.Load() != nativeOversizeDrops || l.client.stats.droppedRecv.Load() != nativeOversizeDrops-1 {
			t.Fatalf("dropped %d sent, %d received", l.client.stats.droppedSent.Load(), l.client.stats.droppedRecv.Load())
		}
	})
}
