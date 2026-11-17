package nativeudp

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// sealRun is n datagrams of client by counter, every third a probe: the
// window counts probes as it counts data.
func sealRun(t *testing.T, client *Session, n int) [][]byte {
	t.Helper()
	wires := make([][]byte, n)
	for i := range wires {
		kind := KindData
		if i%3 == 2 {
			kind = KindProbe
		}
		wire, err := client.Seal(nil, kind, []byte("tick"))
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = wire
	}
	return wires
}

// deliver opens the datagrams of the given counters in that order, each of
// which must open. Open decrypts in place, so it gets copies.
func deliver(t *testing.T, s *Session, wires [][]byte, counters ...int) {
	t.Helper()
	for _, c := range counters {
		if _, err := s.Open(bytes.Clone(wires[c])); err != nil {
			t.Fatalf("counter %d did not open: %v", c, err)
		}
	}
}

func span(from, to int) []int {
	var s []int
	for c := from; c <= to; c++ {
		s = append(s, c)
	}
	return s
}

func wantLoss(t *testing.T, what string, got Loss, lost, late uint64) {
	t.Helper()
	if got != (Loss{Lost: lost, Late: late}) {
		t.Fatalf("%s: lost %d, late %d; want %d, %d", what, got.Lost, got.Late, lost, late)
	}
}

func TestDatagramsInOrderAreNeitherLostNorLate(t *testing.T) {
	client, server := pair(t)
	wires := sealRun(t, client, 3*window)
	deliver(t, server, wires, span(0, len(wires)-1)...)
	wantLoss(t, "so far", server.Loss(), 0, 0)
	wantLoss(t, "at the end", server.FinalLoss(), 0, 0)
}

// Counter 1 comes when 65 is the newest, the last moment the window takes it:
// it is late, and lost neither then nor once the window moves past it.
func TestAGapThatFillsInTheWindowIsLateNotLost(t *testing.T) {
	client, server := pair(t)
	wires := sealRun(t, client, 3*window)
	deliver(t, server, wires, 0)
	deliver(t, server, wires, span(2, 1+lookBehind)...)
	deliver(t, server, wires, 1)
	wantLoss(t, "once it came", server.Loss(), 0, 1)
	deliver(t, server, wires, span(2+lookBehind, len(wires)-1)...)
	wantLoss(t, "so far", server.Loss(), 0, 1)
	wantLoss(t, "at the end", server.FinalLoss(), 0, 1)
}

// Counters 1 to 10 never come. Each is lost when the window leaves it, not
// before, and one that comes after that is refused and stays lost.
func TestAGapThatLeavesTheWindowIsLost(t *testing.T) {
	const gap = 10
	client, server := pair(t)
	wires := sealRun(t, client, 2*window)
	deliver(t, server, wires, 0)
	deliver(t, server, wires, span(gap+1, gap+lookBehind)...)
	wantLoss(t, "with counter 10 still in the window", server.Loss(), gap-1, 0)
	wantLoss(t, "had it ended there", server.FinalLoss(), gap, 0)
	deliver(t, server, wires, gap+lookBehind+1)
	wantLoss(t, "once the window left the gap", server.Loss(), gap, 0)
	if _, err := server.Open(bytes.Clone(wires[5])); err == nil {
		t.Fatal("a counter the window left opened")
	}
	wantLoss(t, "after it came too late", server.Loss(), gap, 0)
	wantLoss(t, "at the end", server.FinalLoss(), gap, 0)
}

// The peer's word that its next counter is 1001 loses 1 to 935 at once, 512
// to 935 without ever having had a tag. 936 to 1000 stay in the window, and
// one of them coming is not late: nothing newer came.
func TestAResyncLosesTheCountersItJumps(t *testing.T) {
	client, server := pair(t)
	wires := sealRun(t, client, 1002)
	deliver(t, server, wires, 0)
	server.Resync(1001)
	wantLoss(t, "after the resync", server.Loss(), 1000-lookBehind-1, 0)
	wantLoss(t, "had it ended there", server.FinalLoss(), 1000, 0)
	deliver(t, server, wires, 990)
	wantLoss(t, "after a counter the resync kept", server.Loss(), 1000-lookBehind-1, 0)
	deliver(t, server, wires, 1001, 1000)
	wantLoss(t, "after 1000 came behind 1001", server.Loss(), 1000-lookBehind, 1)
	// Up to the top every counter came or is lost.
	wantLoss(t, "at the end", server.FinalLoss(), 1002-4, 1)
	server.Resync(1)
	wantLoss(t, "after a stale resync", server.FinalLoss(), 1002-4, 1)

	client.sendMu.Lock()
	client.send += 1 << 40
	client.sendMu.Unlock()
	next := client.Next()
	server.Resync(next)
	wantLoss(t, "after a resync far past the window", server.FinalLoss(), next-4, 1)
	wantLoss(t, "below the window", server.Loss(), next-4-(lookBehind+1), 1)
}

// A forged datagram of counter 1 would be late and take the counter, a replay
// would be late: neither counts, nor does a datagram of another session.
func TestReplaysForgeriesAndForeignDatagramsCountNowhere(t *testing.T) {
	client, server := pair(t)
	other, _ := pairOf(t, 3)
	wires := sealRun(t, client, 4)
	deliver(t, server, wires, 0, 2, 3)
	forged := bytes.Clone(wires[1])
	forged[len(forged)-1] ^= 1
	if _, err := server.Open(forged); err == nil {
		t.Fatal("a forged datagram opened")
	}
	foreign, err := other.Seal(nil, KindData, []byte("tick"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(foreign); err == nil {
		t.Fatal("a datagram of another session opened")
	}
	wantLoss(t, "after the forgery", server.Loss(), 0, 0)
	deliver(t, server, wires, 1)
	wantLoss(t, "after the real counter 1", server.Loss(), 0, 1)
	for _, c := range []int{1, 0, 3} {
		if _, err := server.Open(bytes.Clone(wires[c])); err == nil {
			t.Fatalf("a replay of %d opened", c)
		}
	}
	wantLoss(t, "after the replays", server.Loss(), 0, 1)
	wantLoss(t, "at the end", server.FinalLoss(), 0, 1)
}

// A path that loses about one datagram in eight and holds one in six back by
// up to twice what the window looks behind, so that some come too late to be
// taken. The counts are those of the datagrams as they came.
func TestTheCountsAreThoseOfTheDatagramsAsTheyCame(t *testing.T) {
	const n = 4 * window
	client, server := pair(t)
	wires := sealRun(t, client, n)
	rng := rand.New(rand.NewPCG(1, 2))
	type due struct{ at, counter int }
	var path []due
	for c := range n - 1 {
		switch r := rng.IntN(48); {
		case r < 6:
		case r < 14:
			path = append(path, due{c + 1 + rng.IntN(2*lookBehind), c})
		default:
			path = append(path, due{c, c})
		}
	}
	slices.SortStableFunc(path, func(a, b due) int { return a.at - b.at })
	path = append(path, due{n, n - 1})

	got := make([]bool, n)
	var accepted, late, refused uint64
	newest := -1
	for _, d := range path {
		if _, err := server.Open(bytes.Clone(wires[d.counter])); err != nil {
			refused++
			continue
		}
		accepted++
		got[d.counter] = true
		if d.counter < newest {
			late++
		} else {
			newest = d.counter
		}
	}
	var lost uint64
	for c := range newest - lookBehind {
		if !got[c] {
			lost++
		}
	}
	if late == 0 || refused == 0 || lost == 0 {
		t.Fatalf("the path did not exercise the window: late %d, refused %d, lost %d", late, refused, lost)
	}
	wantLoss(t, "so far", server.Loss(), lost, late)
	wantLoss(t, "at the end", server.FinalLoss(), n-accepted, late)
}

// Through the hub: 1, 3 and 4 may still come while the association lives,
// and are lost once it is removed. The hub's sum follows the session's, the
// resync included, and a second Remove adds nothing.
func TestTheHubCountsWhatIsMissingWhenTheSessionEnds(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
	c := dialHub(t, hub)
	wires := sealRun(t, client, 6)
	for _, i := range []int{0, 5, 2} {
		if _, err := c.Write(wires[i]); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, hub, func(s Stats) bool { return s.Accepted == 3 })
	if st := hub.ExtendedStats(); st.Lost != 0 || st.Late != 1 {
		t.Fatalf("hub lost %d, late %d; want 0, 1", st.Lost, st.Late)
	}
	wantLoss(t, "so far", registered.Loss(), 0, 1)
	wantLoss(t, "had it ended there", registered.FinalLoss(), 3, 1)

	sealRun(t, client, window)
	hub.Resync(registered, client.Next())
	if st, l := hub.ExtendedStats(), registered.Loss(); st.Lost != l.Lost || st.Late != l.Late || l.Lost == 0 {
		t.Fatalf("after the resync the hub has lost %d, late %d, the session %+v", st.Lost, st.Late, l)
	}
	total := client.Next() - 3
	wantLoss(t, "had it ended after the resync", registered.FinalLoss(), total, 1)

	hub.Remove(registered)
	if st := hub.ExtendedStats(); st.Lost != total || st.Late != 1 {
		t.Fatalf("after Remove the hub has lost %d, late %d; want %d, 1", st.Lost, st.Late, total)
	}
	wantLoss(t, "after Remove", registered.Loss(), total, 1)
	hub.Remove(registered)
	if st := hub.ExtendedStats(); st.Lost != total {
		t.Fatalf("a second Remove made the hub's loss %d, want %d", st.Lost, total)
	}
	wantLoss(t, "after a second Remove", registered.FinalLoss(), total, 1)
}

// Under -race: the window moves by datagrams and resyncs while its counts are
// read. What was read never goes down, and at the end every counter came or
// is lost.
func TestTheLossIsReadWhileTheWindowMoves(t *testing.T) {
	const n = 5000
	client, server := pair(t)
	wires := sealRun(t, client, n)
	var wg sync.WaitGroup
	done := make(chan struct{})
	var accepted uint64
	wg.Go(func() {
		defer close(done)
		for c, wire := range wires {
			if c%7 == 3 {
				continue
			}
			if _, err := server.Open(wire); err == nil {
				accepted++
			}
		}
	})
	wg.Go(func() {
		for next := uint64(1000); next < n; next += 1000 {
			server.Resync(next)
			time.Sleep(time.Millisecond)
		}
	})
	wg.Go(func() {
		var last Loss
		for {
			l := server.Loss()
			_ = server.FinalLoss()
			if l.Lost < last.Lost || l.Late < last.Late {
				t.Errorf("the counts went down from %+v to %+v", last, l)
				return
			}
			last = l
			select {
			case <-done:
				return
			default:
			}
		}
	})
	wg.Wait()
	if got := server.FinalLoss().Lost; got+accepted != n {
		t.Fatalf("%d lost and %d accepted of %d", got, accepted, n)
	}
}

// Under -race: two sessions of a hub receive and resync while the hub's sum is
// read. Once both are removed it is the sum of their final counts.
func TestTheHubSumsTheLossOfItsSessionsWhileTheyMove(t *testing.T) {
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	var sessions []*Session
	var wg sync.WaitGroup
	for seed := byte(1); seed <= 2; seed++ {
		client, server := pairOf(t, seed)
		registered := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
		sessions = append(sessions, registered)
		c := dialHub(t, hub)
		wires := sealRun(t, client, 2*window)
		// Every fifth is lost, and every ninth comes after the next one.
		order := span(0, len(wires)-1)
		for i := 4; i+1 < len(order); i += 9 {
			order[i], order[i+1] = order[i+1], order[i]
		}
		wg.Go(func() {
			for i, counter := range order {
				if counter%5 == 1 {
					continue
				}
				_, _ = c.Write(wires[counter])
				if i == window {
					hub.Resync(registered, uint64(i+lookAhead))
				}
			}
		})
	}
	stop := make(chan struct{})
	reader := make(chan struct{})
	go func() {
		defer close(reader)
		var last ExtendedStats
		for {
			st := hub.ExtendedStats()
			for _, s := range sessions {
				_ = s.FinalLoss()
			}
			if st.Lost < last.Lost || st.Late < last.Late {
				t.Errorf("the hub's counts went down from %d/%d to %d/%d", last.Lost, last.Late, st.Lost, st.Late)
				return
			}
			last = st
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
	for _, s := range sessions {
		hub.Remove(s)
	}
	close(stop)
	<-reader
	var sum Loss
	for _, s := range sessions {
		l := s.Loss()
		sum.Lost += l.Lost
		sum.Late += l.Late
	}
	if st := hub.ExtendedStats(); st.Lost != sum.Lost || st.Late != sum.Late || sum.Lost == 0 {
		t.Fatalf("the hub has lost %d, late %d; the sessions %+v", st.Lost, st.Late, sum)
	}
}
