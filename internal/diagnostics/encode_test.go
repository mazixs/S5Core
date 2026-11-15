package diagnostics

import (
	"encoding/json/v2"
	"math"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

var testFlow = &flowInfo{id: 7, leg: "outer", transport: "obfs", local: "127.0.0.1:1080", remote: "127.0.0.1:443"}

// decode reads one line of events.jsonl, which must be a JSON object and end
// with its newline.
func decode(t *testing.T, line []byte) map[string]any {
	t.Helper()
	s, ok := strings.CutSuffix(string(line), "\n")
	if !ok || strings.Contains(s, "\n") {
		t.Fatalf("not one line: %q", line)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	return v
}

func TestARecordIsOneLineWithItsFlow(t *testing.T) {
	wall := time.Date(2026, 11, 15, 10, 0, 0, 123456789, time.UTC)
	got := decode(t, appendRecord(nil, &record{
		seq: 42, mono: 1500, wall: wall.UnixNano(), dur: int64(30 * time.Millisecond), n: 16384,
		flow: testFlow, kind: kindStage, what: stageWrite, flags: flagSlow | flagError,
	}))
	want := map[string]any{
		"seq": 42.0, "elapsed_ns": 1500.0, "utc": "2026-11-15T10:00:00.123456789Z",
		"flow": 7.0, "leg": "outer", "transport": "obfs", "kind": "stage",
		"data": map[string]any{
			"boundary": "transport_write", "duration_ns": 3e7, "bytes": 16384.0,
			"error": true, "periodic": false, "slow": true,
		},
	}
	if a, b := mustJSON(t, got), mustJSON(t, want); a != b {
		t.Fatalf("got %s\nwant %s", a, b)
	}
	process := decode(t, appendRecord(nil, &record{kind: kindSpike, what: spikeRTO, payload: "id"}))
	if process["flow"] != 0.0 || process["leg"] != "process" || process["transport"] != nil {
		t.Errorf("a process record: %v", process)
	}
	if d := process["data"].(map[string]any); d["reason"] != "retransmit_timeout" || d["incident_id"] != "id" {
		t.Errorf("a spike: %v", d)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A socket record carries the counters the kernel gave, by name and unit,
// and nothing for the rest.
func TestASocketRecordCarriesOnlyTheKnownCounters(t *testing.T) {
	s := &tcpSample{available: true, readWait: 2 * time.Second, counters: tcptune.Counters{
		Has: tcptune.CounterRTT | tcptune.CounterSinceAck | tcptune.CounterBytesAcked | tcptune.CounterTimeoutEpisodes,
		RTT: 25 * time.Millisecond, SinceAck: 1500 * time.Millisecond, BytesAcked: 1 << 40, TimeoutEpisodes: 3,
		MinRTT: time.Second, // not in Has
	}}
	d := decode(t, appendRecord(nil, &record{flow: testFlow, kind: kindSocket, what: sampleTick, payload: s}))["data"].(map[string]any)
	want := map[string]any{
		"reason": "periodic", "available": true, "read_wait_max_ns": 2e9,
		"tcp": map[string]any{"rtt_us": 25000.0, "since_ack_ms": 1500.0, "bytes_acked": float64(1 << 40), "timeout_episodes": 3.0},
	}
	if a, b := mustJSON(t, d), mustJSON(t, want); a != b {
		t.Fatalf("got %s\nwant %s", a, b)
	}
	d = decode(t, appendRecord(nil, &record{flow: testFlow, kind: kindSocket, what: sampleClose, payload: &tcpSample{}}))["data"].(map[string]any)
	if mustJSON(t, d) != `{"available":false,"reason":"close"}` {
		t.Errorf("an unavailable close sample: %v", d)
	}
}

// Every counter has a name of its own, with its unit.
func TestEveryCounterHasItsOwnName(t *testing.T) {
	seen := map[string]bool{}
	var all tcptune.CounterField
	for _, f := range tcpFields {
		if seen[f.name] || all&f.f != 0 {
			t.Errorf("%s twice", f.name)
		}
		seen[f.name], all = true, all|f.f
	}
	if all != tcptune.CounterTimeoutEpisodes<<1-1 {
		t.Errorf("fields %b have no name", tcptune.CounterTimeoutEpisodes<<1-1&^all)
	}
}

func TestFlowRecords(t *testing.T) {
	open := decode(t, appendRecord(nil, &record{flow: testFlow, kind: kindFlowOpen}))
	if d := open["data"].(map[string]any); d["local"] != "127.0.0.1:1080" || d["remote"] != "127.0.0.1:443" || open["kind"] != "flow_open" {
		t.Errorf("flow_open: %v", open)
	}
	if _, ok := open["data"].(map[string]any)["outer_flow"]; ok {
		t.Errorf("an outer flow names an outer flow: %v", open)
	}
	related := &flowInfo{id: 8, outer: 7, leg: "target", transport: "tcp"}
	if d := decode(t, appendRecord(nil, &record{flow: related, kind: kindFlowOpen}))["data"].(map[string]any); d["outer_flow"] != 7.0 {
		t.Errorf("a related flow_open: %v", d)
	}
	closed := decode(t, appendRecord(nil, &record{flow: testFlow, kind: kindFlowClose, payload: &flowTotals{reads: 3, writes: 4}}))
	if d := closed["data"].(map[string]any); d["read_calls"] != 3.0 || d["write_calls"] != 4.0 {
		t.Errorf("flow_close: %v", closed)
	}
	odd := *testFlow
	odd.remote = "\x00\"\xff"
	if d := decode(t, appendRecord(nil, &record{flow: &odd, kind: kindFlowOpen}))["data"].(map[string]any); d["remote"] != "\x00\"�" {
		t.Errorf("an address that is no UTF-8 reads %q", d["remote"])
	}
}

func TestARuntimeRecordNamesTheMetrics(t *testing.T) {
	s := &runtimeSample{counts: []uint64{1, 2, 3, 4, 5}, ends: [len(runtimeHistograms)]int{2, 5}}
	samples := make([]metrics.Sample, len(runtimeScalars))
	for i, name := range runtimeScalars {
		samples[i].Name = name
	}
	metrics.Read(samples)
	for i := range samples {
		s.scalars[i] = samples[i].Value
	}
	s.scalars[1] = metrics.Value{} // a metric this Go version does not have
	d := decode(t, appendRecord(nil, &record{kind: kindRuntime, payload: s}))["data"].(map[string]any)
	if len(d) != len(runtimeScalars)+len(runtimeHistograms) {
		t.Errorf("%d metrics, want %d", len(d), len(runtimeScalars)+len(runtimeHistograms))
	}
	if d[runtimeScalars[1]] != nil || d["/sched/goroutines:goroutines"].(float64) < 1 {
		t.Errorf("scalars: %v", d)
	}
	if mustJSON(t, d[runtimeHistograms[0]]) != "[1,2]" || mustJSON(t, d[runtimeHistograms[1]]) != "[3,4,5]" {
		t.Errorf("histograms: %v %v", d[runtimeHistograms[0]], d[runtimeHistograms[1]])
	}
	for _, f := range []float64{math.Inf(1), math.NaN()} {
		if got := string(appendFloat(nil, f)); got != "null" {
			t.Errorf("%v writes %s", f, got)
		}
	}
}

// Writing a line into the worker's buffer allocates nothing.
func TestAppendRecordDoesNotAllocate(t *testing.T) {
	buf := make([]byte, 0, 4096)
	recs := []record{
		{flow: testFlow, kind: kindStage, what: stageRead, flags: flagPeriodic},
		{flow: testFlow, kind: kindSocket, what: sampleTick, payload: &tcpSample{available: true, counters: tcptune.Counters{Has: 1<<21 - 1}}},
		{flow: testFlow, kind: kindQueue, payload: &QueueState{Frames: 1024, Writing: true, WriteElapsed: time.Second}},
		{flow: testFlow, kind: kindStage, what: stageSetup, flags: flagSpare},
		{flow: testFlow, kind: kindNativePath, what: pathVerified, payload: &pathAddrs{local: "127.0.0.1:50000", remote: "127.0.0.2:4000"}},
		{flow: testFlow, kind: kindNativePath, what: pathLost, n: 3},
		{flow: testFlow, kind: kindNativeProbe, dur: int64(time.Millisecond)},
	}
	for i := range recs {
		if n := testing.AllocsPerRun(100, func() { buf = appendRecord(buf[:0], &recs[i]) }); n != 0 {
			t.Errorf("%s %d: %v allocations", kindNames[recs[i].kind], recs[i].what, n)
		}
	}
}
