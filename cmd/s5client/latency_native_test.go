package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/diagnostics"
)

// automaticIncident is the one incident in dir, which a lost native path
// started; it returns the flow the trigger names and the incident's events.
func automaticIncident(t *testing.T, dir string) (flow uint32, events []latencyEvent) {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join(dir, "*.manifest.json"))
	if err != nil || len(manifests) != 1 {
		t.Fatalf("manifests %v, %v", manifests, err)
	}
	data, err := os.ReadFile(manifests[0])
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		IncidentID string `json:"incident_id"`
		Trigger    struct {
			Source string `json:"source"`
			Reason string `json:"reason"`
			Flow   uint32 `json:"flow"`
		} `json:"trigger"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Trigger.Source != "automatic" || m.Trigger.Reason != "native_path_lost" || m.Trigger.Flow == 0 {
		t.Fatalf("trigger %+v", m.Trigger)
	}
	return m.Trigger.Flow, readEvents(t, filepath.Join(dir, m.IncidentID+".events.jsonl"))
}

// nativeFeed is what an incident holds of the native path beside flow, in
// order, each entry after the elapsed time of its record: "verified <local>
// <remote>", "lost <unanswered>", "restored", and "probe <round trip>".
func nativeFeed(events []latencyEvent, flow uint32) []string {
	var feed []string
	for _, e := range events {
		at := fmt.Sprint(time.Duration(e.ElapsedNS), " ")
		switch {
		case e.Flow != flow:
		case e.Kind == "native_probe":
			feed = append(feed, fmt.Sprint(at, "probe ", time.Duration(e.Data.RTTNS)))
		case e.Kind == "native_path" && e.Data.State == "verified":
			feed = append(feed, fmt.Sprint(at, "verified ", e.Data.Local, " ", e.Data.Remote))
		case e.Kind == "native_path" && e.Data.State == "lost":
			feed = append(feed, fmt.Sprint(at, "lost ", e.Data.UnansweredProbes))
		case e.Kind == "native_path":
			feed = append(feed, at+e.Data.State)
		}
	}
	return feed
}

// recordedLiveness is an association beside a recorded transport, in the
// bubble: every answer comes 20 ms after its probe, the jitter is zero, lose
// says which probes are lost, and setup, if set, changes the path further.
// Its records are timed from the start of the association.
func recordedLiveness(t *testing.T, transport net.Conn, lose func(int64) bool, setup func(*memPath)) (l *liveness, dir string, stop func()) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "diag")
	t.Setenv("S5_DIAGNOSTICS_DIR", dir)
	stop = diagnostics.StartLatency()
	t.Cleanup(stop)
	synctest.Wait()
	flow := diagnostics.FlowOf(diagnostics.ObserveConn(transport, "outer", "obfs"))
	if flow == (diagnostics.Flow{}) {
		t.Fatal("the transport was not selected")
	}
	l = newLiveness(t, lose, 0, nil, nil, func(p *memPath) {
		p.delay = 20 * time.Millisecond
		if setup != nil {
			setup(p)
		}
	})
	l.client.flow = flow
	go l.client.run(func([]byte) {})
	return l, dir, stop
}

// The feed of a path that breaks and heals. The probe at 0 s verifies the
// path and is followed at once by the one that says the client hears the
// server. The probe at 10.02 s is lost, and the answer to the one at 10.42 s
// comes while both are out; the keepalive at 20.42 s goes out 10 s later and
// has a round trip. The break at 25 s loses the keepalive at 30.42 s and the
// two after it, and at 31.62 s the path is lost with three unanswered, which
// starts the tunnel's incident. The break heals at 31.5 s: the retry at
// 31.62 s goes out alone by the count and restores the path, but the answers
// to the three before it could still come until 41.22 s, and so could they
// to the probe that follows at once. The keepalive at 41.64 s has a round
// trip again.
func TestALostPathLeavesNoRoundTripALateAnswerCouldFake(t *testing.T) {
	transport, _ := tcpPair(t)
	synctest.Test(t, func(t *testing.T) {
		l, dir, stop := recordedLiveness(t, transport, func(i int64) bool { return i == 3 }, nil)
		l.at(25 * time.Second)
		l.path.dropDown.Store(true)
		l.at(31500 * time.Millisecond)
		l.path.dropDown.Store(false)
		l.at(42 * time.Second)
		stop()
		if n := l.path.probes.Load(); n != 11 {
			t.Fatalf("%d probes, want 11", n)
		}
		tunnel, events := automaticIncident(t, dir)
		want := []string{
			"20ms probe 20ms", "20ms verified " + memClient.String() + " " + memServer.String(), "40ms probe 20ms",
			"20.44s probe 20ms", "31.62s lost 3", "31.64s restored", "41.66s probe 20ms",
		}
		if got := nativeFeed(events, tunnel); !slices.Equal(got, want) {
			t.Fatalf("the feed of flow %d:\n%v\nwant\n%v", tunnel, got, want)
		}
	})
}

// The probe at 10.02 s is lost, and the answer to the one at 10.42 s comes
// while both are out: it says nothing of either, and the answer to the other
// could still come until 20.42 s. The traffic at 12 s probes at once and then
// every 400 ms until 14 s, each probe alone by the count, and none of them
// has a round trip; the keepalive at 24 s has one again.
func TestAnAnswerWhileTwoProbesAreOutLeavesNoRoundTripALateAnswerCouldFake(t *testing.T) {
	transport, _ := tcpPair(t)
	synctest.Test(t, func(t *testing.T) {
		l, dir, stop := recordedLiveness(t, transport, func(i int64) bool { return i == 3 }, nil)
		l.at(12 * time.Second)
		l.client.used(l.client.clock(time.Now()))
		l.at(25 * time.Second)
		events := saveIncident(t, dir, stop)
		if n := l.path.probes.Load(); n != 11 {
			t.Fatalf("%d probes, want 11", n)
		}
		want := []string{
			"20ms probe 20ms", "20ms verified " + memClient.String() + " " + memServer.String(), "40ms probe 20ms",
			"24.02s probe 20ms",
		}
		if got := nativeFeed(events, outerFlow(t, events)); !slices.Equal(got, want) {
			t.Fatalf("the feed:\n%v\nwant\n%v", got, want)
		}
	})
}

// Where the server proves the route first, the probe at 0 s gets a challenge
// at 20 ms, and the first answer comes at 40 ms, to the echo. Its round trip
// is the echo's, not that of the probe the count has out.
func TestTheRoundTripBehindARouteProofIsTheEchos(t *testing.T) {
	transport, _ := tcpPair(t)
	synctest.Test(t, func(t *testing.T) {
		l, dir, stop := recordedLiveness(t, transport, nil, func(p *memPath) { p.proveRoute = true })
		l.at(time.Second)
		events := saveIncident(t, dir, stop)
		want := []string{
			"40ms probe 20ms", "40ms verified " + memClient.String() + " " + memServer.String(), "60ms probe 20ms",
		}
		if got := nativeFeed(events, outerFlow(t, events)); !slices.Equal(got, want) {
			t.Fatalf("the feed:\n%v\nwant\n%v", got, want)
		}
	})
}

// outerFlow is the one outer flow of events.
func outerFlow(t *testing.T, events []latencyEvent) uint32 {
	t.Helper()
	var flows []uint32
	for _, e := range events {
		if e.Kind == "flow_open" && e.Leg == "outer" {
			flows = append(flows, e.Flow)
		}
	}
	if len(flows) != 1 {
		t.Fatalf("outer flows %v", flows)
	}
	return flows[0]
}
