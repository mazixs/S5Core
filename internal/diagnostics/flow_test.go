package diagnostics

import (
	"net"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// everyEvent reports one of each event on f.
func everyEvent(f Flow, addr net.Addr) {
	f.TunnelSetup(time.Millisecond, true)
	f.NativeVerified(addr, addr)
	f.NativeProbe(time.Millisecond)
	f.NativeLost(3)
	f.NativeRestored()
}

// With diagnostics off FlowOf walks nothing, and the zero Flow it returns
// records nothing; with them on, so does the Flow of a socket the recorder
// never took. Neither allocates.
func TestTheZeroFlowRecordsNothing(t *testing.T) {
	var off net.Conn = panicConn{}
	udp := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if f := FlowOf(off); f != (Flow{}) {
		t.Fatal("a flow with the recorder off")
	}
	if n := testing.AllocsPerRun(1000, func() { everyEvent(FlowOf(off), udp) }); n != 0 {
		t.Fatalf("off: %v allocations", n)
	}
	r := testRecorder(t)
	var untaken net.Conn = netConnOf{&fakeConn{}}
	if f := FlowOf(untaken); f != (Flow{}) {
		t.Fatal("a flow for a socket the recorder never took")
	}
	if n := testing.AllocsPerRun(1000, func() { everyEvent(FlowOf(untaken), udp) }); n != 0 {
		t.Fatalf("untaken: %v allocations", n)
	}
	if n := len(r.records()); n != 0 || len(r.claims) != 0 {
		t.Fatalf("%d records, %d claims", n, len(r.claims))
	}
}

// A flow is the selected socket found under the wrappers of the connection,
// and nothing else: not a related socket, a socket no longer sampled, or one
// of a stopped recorder.
func TestAFlowNeedsASelectedSocket(t *testing.T) {
	r := testRecorder(t)
	outer := ObserveConn(&fakeConn{}, "outer", "obfs")
	related := ObserveRelated(outer, &fakeConn{}, "target")
	closed := ObserveConn(&fakeConn{}, "outer", "obfs")
	_ = closed.Close()
	for name, c := range map[string]net.Conn{"related": related, "closed": closed} {
		if f := FlowOf(c); f != (Flow{}) {
			t.Errorf("a flow for a %s socket", name)
		}
	}
	if f := FlowOf(unwrapOf{netConnOf{outer}}); f.s != outer.(*observedConn).s || f.r != r {
		t.Fatal("the walk did not find the selected socket")
	}
	r.stopped.Store(true)
	if f := FlowOf(outer); f != (Flow{}) {
		t.Fatal("a flow of a stopped recorder")
	}
}

// Every event goes into the events of its own flow with its fields, the
// setup as a stage of its own; a loss during a manual incident is one
// rejection, which the ticks after it do not repeat.
func TestEveryEventGoesIntoItsFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		a, b := FlowOf(ObserveConn(&fakeConn{}, "outer", "obfs")), FlowOf(ObserveConn(&fakeConn{}, "outer", "ws"))
		a.TunnelSetup(30*time.Millisecond, true)
		b.TunnelSetup(45*time.Millisecond, false)
		a.NativeVerified(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4000})
		a.NativeProbe(12 * time.Millisecond)
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval)
		a.NativeLost(3)
		stepFor(r, 5*sampleInterval)
		a.NativeRestored()
		a.NativeProbe(15 * time.Millisecond)
		stepFor(r, postWindow)
		if r.health.rejectedWhileManual != 1 {
			t.Fatalf("%d rejected while manual, want the one loss", r.health.rejectedWhileManual)
		}
		m, events := readIncident(t, dir, id)
		if m.Schema != 4 || m.Trigger.Source != sourceManual {
			t.Fatalf("schema %d, trigger %+v", m.Schema, m.Trigger)
		}
		got := map[uint32][]string{}
		for _, e := range events {
			switch e.Kind {
			case "stage", "native_path", "native_probe":
				got[e.Flow] = append(got[e.Flow], e.Kind+" "+mustJSON(t, e.Data))
			case "spike":
				t.Fatalf("a spike during a manual incident: %v", e.Data)
			}
		}
		want := map[uint32][]string{
			1: {
				`stage {"boundary":"tunnel_setup","duration_ns":30000000,"spare":true}`,
				`native_path {"local":"127.0.0.1:50000","remote":"127.0.0.2:4000","state":"verified"}`,
				`native_probe {"rtt_ns":12000000}`,
				`native_path {"state":"lost","unanswered_probes":3}`,
				`native_path {"state":"restored"}`,
				`native_probe {"rtt_ns":15000000}`,
			},
			2: {`stage {"boundary":"tunnel_setup","duration_ns":45000000,"spare":false}`},
		}
		if mustJSON(t, got) != mustJSON(t, want) {
			t.Fatalf("events\n%v\nwant\n%v", got, want)
		}
	})
}

// Once its socket is no longer sampled - closed, or found closed under its
// wrapper - or its recorder stopped, a flow records nothing and claims
// nothing; after the stop it does not even spell the addresses of a path.
func TestAFlowEndsWithItsSampling(t *testing.T) {
	r := testRecorder(t)
	closedUnder := &fakeConn{}
	kernel(t, func(c net.Conn) (tcptune.Counters, error) {
		if c == closedUnder {
			return tcptune.Counters{}, net.ErrClosed
		}
		return tcptune.Counters{}, nil
	})
	udp := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	closed := ObserveConn(&fakeConn{}, "outer", "obfs")
	evicted := ObserveConn(closedUnder, "outer", "obfs")
	live := ObserveConn(&fakeConn{}, "outer", "obfs")
	flows := []Flow{FlowOf(closed), FlowOf(evicted), FlowOf(live)}
	_ = closed.Close()
	r.tick(time.Now())
	before := len(r.records())
	for _, f := range flows[:2] {
		everyEvent(f, udp)
	}
	r.stopped.Store(true)
	everyEvent(flows[2], udp)
	if n := len(r.records()) - before; n != 0 || len(r.claims) != 0 {
		t.Fatalf("%d records, %d claims after the sampling ended", n, len(r.claims))
	}
	if a := testing.AllocsPerRun(10, func() { flows[2].NativeVerified(udp, udp) }); a != 0 {
		t.Fatalf("a verified path after the stop: %v allocations", a)
	}
}

// The loss of a native path starts an automatic incident at the next tick,
// not in the call, named for its reason and its flow. Another loss within
// the cooldown starts nothing and is not counted; one after it starts the
// next incident.
func TestALostPathStartsAnAutomaticIncident(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		_ = ObserveConn(&fakeConn{}, "outer", "ws")
		f := FlowOf(ObserveConn(&fakeConn{}, "outer", "obfs"))
		stepFor(r, 2*sampleInterval)
		f.NativeLost(4)
		if r.pending != nil {
			t.Fatal("the call started the incident")
		}
		stepFor(r, sampleInterval)
		p := r.pending
		if p == nil || p.manual {
			t.Fatal("the loss started no incident")
		}
		lostAt := time.Now()
		stepFor(r, postWindow)
		m, events := readIncident(t, dir, p.id)
		want := manifestTrigger{Source: sourceAutomatic, Reason: "native_path_lost", Flow: 2, UTC: m.Trigger.UTC, ElapsedNS: p.atMono}
		if m.Trigger != want {
			t.Fatalf("trigger %+v, want %+v", m.Trigger, want)
		}
		var order []string
		for _, e := range events {
			if e.Kind == "native_path" || e.Kind == "spike" {
				order = append(order, e.Kind+" "+mustJSON(t, e.Data))
			}
		}
		if len(order) != 2 || order[0] != `native_path {"state":"lost","unanswered_probes":4}` ||
			order[1] != `spike {"incident_id":"`+p.id+`","reason":"native_path_lost"}` {
			t.Fatalf("events %v", order)
		}
		f.NativeLost(3)
		stepFor(r, sampleInterval)
		if r.pending != nil || r.health != (workerHealth{}) {
			t.Fatalf("a loss within the cooldown: pending %v, %+v", r.pending != nil, r.health)
		}
		time.Sleep(time.Until(lostAt.Add(spikeCooldown)))
		f.NativeLost(3)
		stepFor(r, sampleInterval)
		if r.pending == nil || r.pending.spike.reason != spikeNativeLost {
			t.Fatal("a loss after the cooldown started no incident")
		}
	})
}

// A loss shares the cooldown of its socket with the detector, either way
// round, and a loss in the tick of another socket's spike is counted with
// it. A claim stands when its socket closes before the tick, and is taken
// once.
func TestALossIsASpikeOfItsSocket(t *testing.T) {
	r := testRecorder(t)
	fires := map[net.Conn]bool{}
	acked := uint64(0)
	kernel(t, func(c net.Conn) (tcptune.Counters, error) {
		acked++
		var retransmits uint8
		if fires[c] {
			retransmits = 1
		}
		return *linuxSample(10*time.Millisecond, acked, retransmits), nil
	})
	spiked, lost := &fakeConn{}, &fakeConn{}
	afterSpike, afterLoss := FlowOf(ObserveConn(spiked, "outer", "obfs")), FlowOf(ObserveConn(lost, "outer", "obfs"))
	now := time.Now()
	fires[spiked] = true
	afterLoss.NativeLost(3)
	if first, more := r.tick(now); first.reason != spikeNativeLost || first.flow != afterLoss.s.flow || more != 1 {
		t.Fatalf("first %+v, %d more", first, more)
	}
	fires[lost] = true
	afterSpike.NativeLost(3)
	if first, more := r.tick(now.Add(sampleInterval)); first.reason != 0 || more != 0 {
		t.Fatalf("within the cooldowns: first %+v, %d more", first, more)
	}
	closing := ObserveConn(&fakeConn{}, "outer", "obfs")
	f := FlowOf(closing)
	f.NativeLost(3)
	_ = closing.Close()
	if first, _ := r.tick(now.Add(spikeCooldown)); first.reason != spikeNativeLost || first.flow != f.s.flow {
		t.Fatalf("the claim of a closed socket: %+v", first)
	}
	delete(fires, spiked)
	delete(fires, lost)
	if first, more := r.tick(now.Add(2 * spikeCooldown)); first.reason != 0 || more != 0 {
		t.Fatalf("a claim taken twice: %+v, %d more", first, more)
	}
}

// Losses while an incident is written - each the first or the second of its
// tick - are one rejection each, which the ticks after them do not repeat.
func TestLossesDuringAnotherIncidentAreOneRejectionEach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := dirRecorder(t, false)
		var flows []Flow
		for range 3 {
			flows = append(flows, FlowOf(ObserveConn(&fakeConn{}, "outer", "obfs")))
		}
		flows[0].NativeLost(3)
		stepFor(r, sampleInterval)
		p := r.pending
		if p == nil || p.spike.flow != flows[0].s.flow {
			t.Fatal("the first loss started no incident")
		}
		flows[1].NativeLost(3)
		flows[2].NativeLost(3)
		stepFor(r, 10*sampleInterval)
		if r.pending != p || r.health.rejectedWhileAutomatic != 2 {
			t.Fatalf("%d rejected while automatic, want the two losses", r.health.rejectedWhileAutomatic)
		}
	})
}

// What every tunnel and every native UDP association pays with diagnostics
// off.
func BenchmarkFlowOfDisabled(b *testing.B) {
	var c net.Conn = &fakeConn{}
	b.ReportAllocs()
	for b.Loop() {
		_ = FlowOf(c)
	}
}

// A probe's round trip, as an answered probe of a native path records it:
// on the zero Flow and on a selected socket's.
func BenchmarkFlowEvent(b *testing.B) {
	testRecorder(b)
	for _, bc := range []struct {
		name string
		f    Flow
	}{{"zero", Flow{}}, {"recorded", FlowOf(ObserveConn(&fakeConn{}, "outer", "obfs"))}} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				bc.f.NativeProbe(time.Millisecond)
			}
		})
	}
}
