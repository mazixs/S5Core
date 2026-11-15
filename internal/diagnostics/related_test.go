package diagnostics

import (
	"net"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// netConnOf and unwrapOf are wrappers the walk goes through.
type netConnOf struct{ net.Conn }

func (w netConnOf) NetConn() net.Conn { return w.Conn }

type unwrapOf struct{ net.Conn }

func (w unwrapOf) Unwrap() net.Conn { return w.Conn }

func TestObserveRelatedOffReturnsTheConnectionUntouched(t *testing.T) {
	var outer, related net.Conn = panicConn{}, panicConn{}
	if got := ObserveRelated(outer, related, "target"); got != related {
		t.Fatalf("got %T", got)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = ObserveRelated(outer, related, "target") }); n != 0 {
		t.Fatalf("%v allocations per call", n)
	}
}

// The other side of a relay is recorded beside a selected socket found under
// the wrappers of the outer connection, and beside nothing else: a socket
// the recorder never took or no longer samples, a related socket, or with
// the recorder stopped. A related connection without a socket is left too.
func TestARelatedSocketNeedsASelectedOuterSocket(t *testing.T) {
	r := testRecorder(t)
	untaken := &fakeConn{}
	if got := ObserveRelated(netConnOf{&fakeConn{}}, untaken, "target"); got != untaken {
		t.Fatal("related to a socket the recorder never took")
	}
	outer := ObserveConn(&fakeHalfConn{}, "outer", "obfs")
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	if got := ObserveRelated(outer, pipe, "target"); got != pipe {
		t.Fatal("a pipe was taken for a socket")
	}
	related, ok := ObserveRelated(unwrapOf{netConnOf{outer}}, &fakeHalfConn{}, "target").(*observedHalfConn)
	if !ok {
		t.Fatal("the walk did not find the selected socket")
	}
	if f := related.s.flow; *f != (flowInfo{id: 2, outer: 1, leg: "target", transport: "tcp", local: "127.0.0.1:1080", remote: "127.0.0.1:443"}) {
		t.Fatalf("flow %+v", f)
	}
	closed := ObserveConn(&fakeConn{}, "outer", "obfs")
	_ = closed.Close()
	for name, o := range map[string]net.Conn{"related": related, "closed": closed} {
		c := &fakeConn{}
		if got := ObserveRelated(o, c, "application"); got != c {
			t.Errorf("related to a %s socket", name)
		}
	}
	idle := ObserveConn(&fakeConn{}, "outer", "obfs")
	r.stopped.Store(true)
	c := &fakeConn{}
	if got := ObserveRelated(idle, c, "target"); got != c {
		t.Fatal("a stopped recorder took a related socket")
	}
	if n := len(ofKind(r.records(), kindFlowOpen)); n != 4 {
		t.Fatalf("%d flows, want three selected and one related", n)
	}
}

// A related socket takes neither a slot nor a token, and a selected socket
// has one at a time; the slots stay with the selected ones. A related socket
// that outlives its outer one still counts: there are never more related
// sockets than slots.
func TestARelatedSocketTakesNoSlotAndComesOneAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testRecorder(t)
		var outers, related []net.Conn
		for range selectedSockets {
			outers = append(outers, ObserveConn(&fakeConn{}, "outer", "obfs"))
		}
		for _, o := range outers {
			c, ok := ObserveRelated(o, &fakeConn{}, "target").(*observedConn)
			if !ok {
				t.Fatal("no related socket with every slot and token taken")
			}
			related = append(related, c)
		}
		if r.taken != selectedSockets || len(r.sockets) != 2*selectedSockets ||
			r.selection != (selection{last: r.selection.last, admitted: selectedSockets}) {
			t.Fatalf("%d taken, %d sampled, %+v", r.taken, len(r.sockets), r.selection)
		}
		time.Sleep(time.Hour)
		if _, ok := ObserveConn(&fakeConn{}, "outer", "obfs").(*fakeConn); !ok || r.selection.omittedActive != 1 {
			t.Fatal("a related socket left a slot to another selected one")
		}
		second := &fakeConn{}
		if got := ObserveRelated(outers[0], second, "target"); got != second {
			t.Fatal("a second related socket at once")
		}
		_ = related[0].Close()
		if _, ok := ObserveRelated(outers[0], second, "target").(*observedConn); !ok {
			t.Fatal("a related socket closed left no place for the next one")
		}
		_ = outers[1].Close()
		replacement, ok := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn)
		if !ok {
			t.Fatal("a selected socket closed beside a live related one kept its slot")
		}
		if r.taken != selectedSockets || len(r.sockets) != 2*selectedSockets {
			t.Fatalf("%d taken, %d sampled", r.taken, len(r.sockets))
		}
		over := &fakeConn{}
		if got := ObserveRelated(replacement, over, "target"); got != over {
			t.Fatal("more related sockets than slots")
		}
		_ = related[1].Close()
		if _, ok := ObserveRelated(replacement, over, "target").(*observedConn); !ok {
			t.Fatal("a related socket that outlived its outer one kept its place")
		}
	})
}

// An incident holds a related flow like any other - its open, samples,
// stages and close - and its manifest names the flow it belongs to, which an
// outer flow does without.
func TestAnIncidentTiesTheRelatedFlowToItsOuterFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		outer := ObserveConn(&fakeConn{}, "outer", "obfs")
		related := ObserveRelated(outer, &fakeHalfConn{}, "target")
		_, _ = related.Write(make([]byte, 10))
		stepFor(r, 2*sampleInterval)
		_ = related.Close()
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval+postWindow)
		m, events := readIncident(t, dir, id)
		want := []manifestFlow{
			{Flow: 1, Leg: "outer", Transport: "obfs", Local: "127.0.0.1:1080", Remote: "127.0.0.1:443"},
			{Flow: 2, OuterFlow: 1, Leg: "target", Transport: "tcp", Local: "127.0.0.1:1080", Remote: "127.0.0.1:443"},
		}
		if m.Schema != 4 || !slices.Equal(m.Flows, want) {
			t.Fatalf("schema %d, flows %+v", m.Schema, m.Flows)
		}
		var raw struct {
			Flows []map[string]any `json:"flows"`
		}
		if err := readManifest(filepath.Join(dir, id+manifestSuffix), &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw.Flows[0]["outer_flow"]; ok {
			t.Fatalf("an outer flow names an outer flow: %v", raw.Flows[0])
		}
		var kinds []string
		for _, e := range events {
			if e.Flow != 2 {
				continue
			}
			if e.Leg != "target" || e.Transport != "tcp" {
				t.Fatalf("a related event %+v", e)
			}
			if e.Kind == "socket" {
				kinds = append(kinds, e.Kind+":"+e.Data["reason"].(string))
			} else {
				kinds = append(kinds, e.Kind)
			}
		}
		if wantKinds := []string{"flow_open", "socket:open", "stage", "socket:periodic", "socket:periodic", "socket:close", "flow_close"}; !slices.Equal(kinds, wantKinds) {
			t.Fatalf("related events %v, want %v", kinds, wantKinds)
		}
	})
}

// The detector watches the selected sockets alone: a related socket whose
// retransmit timer fires starts nothing, and its samples go into the
// incident its outer socket starts.
func TestOnlyASelectedSocketStartsAnIncident(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw := &fakeConn{}
		outerFires := false
		acked := uint64(0)
		kernel(t, func(c net.Conn) (tcptune.Counters, error) {
			acked++
			var retransmits uint8
			if c != raw || outerFires {
				retransmits = 1
			}
			return *linuxSample(10*time.Millisecond, acked, retransmits), nil
		})
		r, dir := dirRecorder(t, false)
		outer := ObserveConn(raw, "outer", "obfs")
		_ = ObserveRelated(outer, &fakeConn{}, "target")
		stepFor(r, 5*time.Second)
		if r.pending != nil || r.health != (workerHealth{}) {
			t.Fatalf("a related socket started an incident: %+v", r.health)
		}
		outerFires = true
		stepFor(r, sampleInterval)
		p := r.pending
		if p == nil || p.spike.flow.id != 1 {
			t.Fatal("the outer socket started no incident")
		}
		stepFor(r, postWindow)
		_, events := readIncident(t, dir, p.id)
		samples := map[uint32]int{}
		for _, e := range events {
			if e.Kind == "socket" {
				samples[e.Flow]++
			}
		}
		if samples[2] == 0 || samples[2] != samples[1] {
			t.Fatalf("socket samples by flow %v", samples)
		}
	})
}

// With every slot taken, two minutes of samples fit the ring without pushing
// any out. Idle, each selected socket beside its related one, its queue and
// the answers to the keepalive of a native path, every 10 s at the most,
// take less than three quarters of it. Native associations under traffic,
// whose probes are answered every 400 ms at the most, fit it.
func TestTheWindowOfEverySocketFitsTheRing(t *testing.T) {
	for _, c := range []struct {
		name       string
		related    bool
		probeEvery time.Duration
		under      int
	}{
		{"idle", true, 10 * time.Second, ringRecords * 3 / 4},
		{"native under traffic", false, 400 * time.Millisecond, ringRecords},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := testRecorder(t)
				var flows []Flow
				for range selectedSockets {
					outer := ObserveConn(&fakeConn{}, "outer", "obfs")
					if c.related {
						_ = ObserveRelated(outer, &fakeConn{}, "target")
					}
					if ObserveQueue(outer, &fakeQueue{}) == nil {
						t.Fatal("a queue was not watched")
					}
					flows = append(flows, FlowOf(outer))
				}
				start := time.Now()
				nextTick, nextProbe := start.Add(sampleInterval), start.Add(c.probeEvery)
				for end := start.Add(historyWindow + time.Minute); time.Now().Before(end); {
					time.Sleep(time.Until(nextTick))
					for ; !nextProbe.After(time.Now()); nextProbe = nextProbe.Add(c.probeEvery) {
						for _, f := range flows {
							f.NativeProbe(time.Millisecond)
						}
					}
					r.tick(time.Now())
					nextTick = nextTick.Add(sampleInterval)
				}
				t.Logf("%d records held", r.ring.count)
				if r.ring.overwritten != 0 || r.ring.count >= c.under {
					t.Fatalf("%d records held, %d overwritten", r.ring.count, r.ring.overwritten)
				}
			})
		})
	}
}
