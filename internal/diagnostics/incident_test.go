package diagnostics

import (
	"bufio"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/privatefs/privatefstest"
	"github.com/mazixs/S5Core/internal/tcptune"
)

// dirRecorder is a recorder over a new private directory, without its
// worker: the test steps it.
func dirRecorder(t *testing.T, flight bool) (*recorder, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "diag")
	r, err := newDirRecorder(dir, "run", flight)
	if err != nil {
		t.Fatal(err)
	}
	if !current.CompareAndSwap(nil, r) {
		t.Fatal("a recorder is running already")
	}
	t.Cleanup(func() {
		current.CompareAndSwap(r, nil)
		if r.flight != nil {
			r.flight.Stop()
		}
		if p := r.pending; p != nil {
			_ = p.f.Close()
		}
	})
	return r, dir
}

// stepFor ticks the recorder through d of the bubble's time.
func stepFor(r *recorder, d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); {
		time.Sleep(sampleInterval)
		r.step(time.Now())
	}
}

func writeMarker(t *testing.T, dir, id string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, markerName), []byte(`{"incident_id":"`+id+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

type savedEvent struct {
	Seq       uint64         `json:"seq"`
	ElapsedNS int64          `json:"elapsed_ns"`
	Flow      uint32         `json:"flow"`
	Kind      string         `json:"kind"`
	Data      map[string]any `json:"data"`
}

func readIncident(t *testing.T, dir, id string) (*manifest, []savedEvent) {
	t.Helper()
	var m manifest
	if err := readManifest(filepath.Join(dir, id+manifestSuffix), &m); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, id+eventsSuffix))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []savedEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e savedEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("%v: %s", err, sc.Bytes())
		}
		events = append(events, e)
	}
	return &m, events
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// An operator's marker saves the history before it and the post window
// after it, every record once and in order, and a manifest that says what
// shaped them. The marker left in place starts nothing more.
func TestAMarkerSavesTheWindowAroundIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		o := ObserveConn(&fakeConn{}, "outer", "obfs")
		stepFor(r, 30*time.Second)
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval)
		if r.pending == nil || r.pending.id != id {
			t.Fatal("the marker started no incident")
		}
		at := r.pending.atMono
		_, _ = o.Write(make([]byte, 10))
		stepFor(r, postWindow)
		if r.pending != nil {
			t.Fatal("the incident is still being written after its post window")
		}
		want := []string{id + eventsSuffix, id + manifestSuffix, markerName}
		if got := files(t, dir); !slices.Equal(got, want) {
			t.Fatalf("files %v, want %v", got, want)
		}
		for _, name := range want[:2] {
			privatefstest.RequirePrivate(t, filepath.Join(dir, name))
		}
		m, events := readIncident(t, dir, id)
		if m.IncidentID != id || m.RunID != "run" || m.Trigger.Source != sourceManual || m.Trace != "disabled" ||
			m.Window.ShutdownBeforePostEnd || m.Window.Truncated || m.Window.LostBeforeCapture != 0 ||
			m.Limits != limits || len(m.RuntimeHistogramBounds) != len(runtimeHistograms) {
			t.Fatalf("manifest %+v", m)
		}
		var raw struct {
			Trigger map[string]any `json:"trigger"`
		}
		if err := readManifest(filepath.Join(dir, id+manifestSuffix), &raw); err != nil || raw.Trigger["flow"] != nil {
			t.Fatalf("a manual trigger names a flow: %v, %v", raw.Trigger, err)
		}
		if len(m.Flows) != 1 || m.Flows[0] != (manifestFlow{Flow: 1, Leg: "outer", Transport: "obfs", Local: "127.0.0.1:1080", Remote: "127.0.0.1:443"}) {
			t.Fatalf("flows %+v", m.Flows)
		}
		first, last := events[0], events[len(events)-1]
		if first.Seq != m.Window.FirstSeq || last.Seq != m.Window.LastSeq || uint64(len(events)) != last.Seq-first.Seq+1 {
			t.Fatalf("%d events, seq %d to %d, manifest %d to %d", len(events), first.Seq, last.Seq, m.Window.FirstSeq, m.Window.LastSeq)
		}
		if first.Kind != "flow_open" || at-first.ElapsedNS < int64(29*time.Second) || last.ElapsedNS-at < int64(postWindow-sampleInterval) {
			t.Fatalf("the window runs from %v before the trigger to %v after", time.Duration(at-first.ElapsedNS), time.Duration(last.ElapsedNS-at))
		}
		kinds := map[string]int{}
		for _, e := range events {
			kinds[e.Kind]++
		}
		if kinds["runtime"] < 200 || kinds["socket"] < 200 || kinds["stage"] != 1 {
			t.Fatalf("kinds %v", kinds)
		}
		stepFor(r, 10*time.Second)
		if r.pending != nil || r.health.failed != 0 {
			t.Fatal("the marker left in place started another incident")
		}
	})
}

// spiking makes every socket's kernel say its retransmit timer fires.
func spiking(t *testing.T) {
	acked := uint64(0)
	kernel(t, func(net.Conn) (tcptune.Counters, error) {
		acked++
		return *linuxSample(10*time.Millisecond, acked, 1), nil
	})
}

// A spike saves an incident of its own that names the spike and its flow.
func TestASpikeSavesAnAutomaticIncident(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		spiking(t)
		r, dir := dirRecorder(t, false)
		_ = ObserveConn(&fakeConn{}, "outer", "obfs")
		stepFor(r, sampleInterval)
		p := r.pending
		if p == nil || p.manual {
			t.Fatal("the spike started no incident")
		}
		stepFor(r, postWindow)
		m, _ := readIncident(t, dir, p.id)
		want := manifestTrigger{Source: sourceAutomatic, Reason: "retransmit_timeout", Flow: 1, UTC: m.Trigger.UTC, ElapsedNS: p.atMono}
		if m.Trigger != want || !m.Trigger.UTC.Equal(p.at) {
			t.Fatalf("trigger %+v, want %+v at %v", m.Trigger, want, p.at)
		}
	})
}

// A marker during an automatic incident takes it over: one incident, the
// history of the automatic one, the post window from the marker on.
func TestAMarkerTakesOverTheAutomaticIncident(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		spiking(t)
		r, dir := dirRecorder(t, false)
		_ = ObserveConn(&fakeConn{}, "outer", "obfs")
		stepFor(r, sampleInterval)
		p := r.pending
		if p == nil || p.manual {
			t.Fatal("the spike started no incident")
		}
		auto, autoAt := p.id, p.atMono
		_ = ObserveConn(&fakeConn{}, "outer", "ws")
		stepFor(r, sampleInterval) // the second socket's spike is dropped
		if r.health.rejectedWhileAutomatic != 1 {
			t.Fatalf("rejected while automatic: %d", r.health.rejectedWhileAutomatic)
		}
		stepFor(r, 10*time.Second)
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval)
		if r.pending != p || p.id != id || !p.manual {
			t.Fatal("the marker did not take the incident over")
		}
		stepFor(r, postWindow-10*time.Second)
		if r.pending == nil {
			t.Fatal("the post window did not start anew at the marker")
		}
		stepFor(r, 10*time.Second)
		for _, name := range files(t, dir) {
			if strings.HasPrefix(name, auto) {
				t.Errorf("%s left", name)
			}
		}
		m, events := readIncident(t, dir, id)
		if m.Trigger.Source != sourceManual || m.Trigger.PriorAutomaticIncident != auto || m.Trigger.Reason != "" {
			t.Fatalf("trigger %+v", m.Trigger)
		}
		var spikes int
		for _, e := range events {
			if e.Kind == "spike" {
				spikes++
				if e.Data["incident_id"] != auto || e.Data["reason"] != "retransmit_timeout" {
					t.Errorf("spike %v", e.Data)
				}
			}
		}
		if spikes != 1 || m.Window.StartElapsedNS > autoAt {
			t.Fatalf("%d spikes; the window starts %v after the spike", spikes, time.Duration(m.Window.StartElapsedNS-autoAt))
		}
	})
}

// A trigger while an incident is written is counted and dropped: a marker
// during a manual incident, a spike during any.
func TestATriggerDuringAManualIncidentIsCounted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		first := uuid.New().String()
		writeMarker(t, dir, first)
		stepFor(r, sampleInterval)
		writeMarker(t, dir, uuid.New().String())
		spiking(t)
		_ = ObserveConn(&fakeConn{}, "outer", "obfs")
		stepFor(r, sampleInterval)
		if r.pending.id != first || r.health.rejectedWhileManual != 2 {
			t.Fatalf("pending %s, rejected while manual %d", r.pending.id, r.health.rejectedWhileManual)
		}
	})
}

// A marker whose incident a process before this one saved starts nothing,
// and costs nothing.
func TestAMarkerFromBeforeARestartStartsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval+postWindow)
		current.CompareAndSwap(r, nil)
		again, err := newDirRecorder(dir, "", false)
		if err != nil {
			t.Fatal(err)
		}
		stepFor(again, 5*time.Second)
		if again.pending != nil || again.health != (workerHealth{}) {
			t.Fatalf("a restart took the marker again: %+v", again.health)
		}
	})
}

// A marker that cannot be read is counted at every poll.
func TestABadMarkerIsCountedAtEveryPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		path := filepath.Join(dir, markerName)
		for i, bad := range []func() error{
			func() error { return os.WriteFile(path, []byte("{"), 0o600) },
			func() error { return os.WriteFile(path, []byte(`{"incident_id":"not a uuid"}`), 0o600) },
			func() error { return os.WriteFile(path, make([]byte, markerMaxBytes+1), 0o600) },
			func() error { _ = os.Remove(path); return os.Mkdir(path, 0o700) },
		} {
			if err := bad(); err != nil {
				t.Fatal(err)
			}
			before := r.health.rejectedMarker
			stepFor(r, 3*sampleInterval)
			if r.health.rejectedMarker-before != 3 || r.pending != nil {
				t.Fatalf("marker %d: %d rejections in three polls", i, r.health.rejectedMarker-before)
			}
		}
	})
}

// More records between two drains than the ring holds are counted as lost,
// not skipped in silence.
func TestRecordsLostBeforeTheirCaptureAreCounted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		s := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn).s
		writeMarker(t, dir, uuid.New().String())
		stepFor(r, sampleInterval)
		for range ringRecords + 100 {
			r.stage(s, stageWrite, slowWrite, 1, nil, false)
		}
		stepFor(r, sampleInterval)
		if lost := r.pending.lost; lost < 100 || lost > 110 {
			t.Fatalf("lost %d", lost)
		}
	})
}

// An incident whose file reaches its share of the budget ends truncated,
// with its manifest.
func TestAnIncidentPastItsShareEndsTruncated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		r.budget = incidentReserve + 4096 // and the marker
		s := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn).s
		for range 8000 {
			r.stage(s, stageWrite, slowWrite, 1, nil, false)
		}
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval+postWindow)
		m, _ := readIncident(t, dir, id)
		info, err := os.Stat(filepath.Join(dir, id+eventsSuffix))
		if err != nil {
			t.Fatal(err)
		}
		if !m.Window.Truncated || info.Size() > incidentReserve+4096 {
			t.Fatalf("truncated %v at %d bytes", m.Window.Truncated, info.Size())
		}
	})
}

// fakeIncident leaves a saved incident in dir, its events of size bytes.
func fakeIncident(t *testing.T, dir, source, prior string, at time.Time, size int) string {
	t.Helper()
	id := uuid.New().String()
	var m manifest
	m.Trigger.Source, m.Trigger.UTC, m.Trigger.PriorAutomaticIncident = source, at, prior
	data, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{id + manifestSuffix: data, id + eventsSuffix: make([]byte, size), id + traceSuffix: make([]byte, size)} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// Room is made from the oldest automatic incident on; a manual one stays,
// and so does the automatic one it took over. Without one left, there is
// no room.
func TestRoomComesFromTheOldestAutomaticIncident(t *testing.T) {
	r, dir := dirRecorder(t, false)
	t0 := time.Unix(1_000_000, 0)
	const size = 100 << 10
	taken := fakeIncident(t, dir, sourceAutomatic, "", t0.Add(-time.Hour), size)
	manual := fakeIncident(t, dir, sourceManual, taken, t0.Add(-2*time.Hour), size)
	older := fakeIncident(t, dir, sourceAutomatic, "", t0, size)
	newer := fakeIncident(t, dir, sourceAutomatic, "", t0.Add(time.Minute), size)
	room, err := r.room()
	if err != nil {
		t.Fatal(err)
	}
	r.budget -= room + size // room is size short
	if got, err := r.makeRoom(size); err != nil || got < size || r.health.rotated != 1 {
		t.Fatalf("room %d (%v), %d rotated", got, err, r.health.rotated)
	}
	if got, err := r.makeRoom(3 * size); err != nil || got < 3*size || r.health.rotated != 2 {
		t.Fatalf("room %d (%v), %d rotated", got, err, r.health.rotated)
	}
	for _, name := range files(t, dir) {
		if id := incidentOf(name); id == older || id == newer {
			t.Errorf("%s left", name)
		}
	}
	if n := len(files(t, dir)); n != 6 {
		t.Fatalf("%d files left of the manual incident and the one it took over", n)
	}
	if _, err := r.makeRoom(10 * size); !errors.Is(err, errNoRoom) {
		t.Fatalf("no room left gives %v", err)
	}
	_ = manual
}

// With no room left the recorder stops for good: the wrappers pass calls
// through, and the incident being written stays as its partial file.
func TestNoRoomStopsTheRecorder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		o := ObserveConn(&fakeConn{}, "outer", "obfs")
		writeMarker(t, dir, uuid.New().String())
		stepFor(r, sampleInterval)
		r.budget = 0
		for r.ticks%diskCheckEvery != diskCheckEvery-1 {
			r.step(time.Now())
		}
		if r.step(time.Now()) || !r.stopped.Load() || current.Load() != nil || r.pending != nil || r.health.failed != 1 {
			t.Fatal("the recorder goes on without room")
		}
		before := len(r.records())
		_, _ = o.Write(make([]byte, 1))
		if len(r.records()) != before {
			t.Fatal("a stopped recorder recorded a write")
		}
		var partial int
		for _, name := range files(t, dir) {
			if strings.HasSuffix(name, ".partial") {
				partial++
			}
		}
		if partial != 1 {
			t.Fatalf("%d partial files", partial)
		}
	})
}

// The trace of an incident is written beside it, by a goroutine of its own,
// and the manifest says whether it is there.
func TestAnIncidentKeepsItsTrace(t *testing.T) {
	r, dir := dirRecorder(t, true)
	s := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn).s
	if op := r.beginOperation(s.flow, "s5core.transport_write"); op.task == nil {
		t.Fatal("no task in the trace")
	} else {
		op.end()
	}
	id := uuid.New().String()
	r.trigger(time.Now(), id, true, spike{})
	r.traces.Wait()
	if info, err := os.Stat(filepath.Join(dir, id+traceSuffix)); err != nil || info.Size() == 0 {
		t.Fatalf("trace: %v", err)
	}
	privatefstest.RequirePrivate(t, filepath.Join(dir, id+traceSuffix))
	r.finish(r.pending, false)
	if m, _ := readIncident(t, dir, id); m.Trace != "captured" {
		t.Fatalf("trace %s", m.Trace)
	}
	r.tracing.Store(true)
	if state := r.captureTrace(uuid.New().String()); state.Load() != traceSkipped {
		t.Fatalf("a second trace at once: %s", traceNames[state.Load()])
	}
	r.tracing.Store(false)
	r.budget = 0
	if state := r.captureTrace(uuid.New().String()); state.Load() != traceFailed {
		t.Fatalf("a trace without room: %s", traceNames[state.Load()])
	}
}
