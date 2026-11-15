package diagnostics

import (
	"bufio"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"slices"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/buildinfo"
	"github.com/mazixs/S5Core/internal/privatefs"
)

const (
	// postWindow is how long an incident goes on after its trigger.
	postWindow = 90 * time.Second
	// markerName is the file an operator writes to start an incident:
	// {"incident_id":"<UUID>"}.
	markerName     = "trigger.json"
	markerMaxBytes = 4096
	// traceMinAge and traceMaxBytes size the flight recorder's window.
	traceMinAge   = 30 * time.Second
	traceMaxBytes = 32 << 20

	manifestSchema  = 1
	eventsSuffix    = ".events.jsonl"
	manifestSuffix  = ".manifest.json"
	traceSuffix     = ".trace"
	sourceManual    = "manual"
	sourceAutomatic = "automatic"
)

// The state of an incident's trace.
const (
	traceDisabled int32 = iota // no flight recorder
	traceWriting
	traceCaptured
	traceFailed
	traceSkipped // the trace of an earlier incident was still being written
)

var traceNames = [...]string{traceDisabled: "disabled", traceWriting: "writing", traceCaptured: "captured", traceFailed: "failed", traceSkipped: "skipped"}

// incident is the one being written. Only the worker uses it.
type incident struct {
	id     string
	manual bool
	prior  string // the automatic incident a manual marker took over
	spike  spike  // what started an automatic one
	at     time.Time
	atMono int64

	f       *os.File // the events file, until it is complete
	w       *bufio.Writer
	written int64
	quota   int64

	first, last uint64 // the records written
	firstRec    record // its times
	lastRec     record
	lost        uint64
	truncated   bool
	failed      error
	flows       map[*flowInfo]struct{}
	trace       *atomic.Int32
}

// workerHealth is what the worker counts; the manifest reports it.
type workerHealth struct {
	rejectedMarker, rejectedWhileManual, rejectedWhileAutomatic uint64
	failed, rotated                                             uint64
}

// trigger starts an incident, or a manual marker takes over the automatic
// one being written: it keeps the history and begins the post window anew.
// Any other trigger while one is written is counted and dropped.
func (r *recorder) trigger(now time.Time, id string, manual bool, sp spike) {
	if p := r.pending; p != nil {
		switch {
		case manual && !p.manual:
			p.prior, p.id, p.manual, p.spike = p.id, id, true, spike{}
			p.at, p.atMono = now, int64(now.Sub(r.start))
			p.trace = r.captureTrace(id)
		default:
			r.reject(1)
		}
		return
	}
	room, err := r.makeRoom(incidentReserve)
	if err != nil {
		r.giveUp(err)
		return
	}
	f, err := privatefs.CreateTemp(r.dir, id+eventsSuffix+".*.partial")
	if err != nil {
		r.health.failed++
		slog.Error("Latency incident not saved", "incident", id, "error", err)
		return
	}
	p := &incident{
		id: id, manual: manual, spike: sp, at: now, atMono: int64(now.Sub(r.start)),
		f: f, w: bufio.NewWriterSize(f, 64<<10), quota: min(room, incidentFileMax),
		flows: make(map[*flowInfo]struct{}),
	}
	if !manual {
		r.push(record{flow: sp.flow, kind: kindSpike, what: sp.reason, payload: id})
	}
	r.mu.Lock()
	if r.ring.count > 0 {
		p.last = r.ring.recs[r.ring.head].seq - 1
	} else {
		p.last = r.ring.seq
	}
	r.mu.Unlock()
	r.pending = p
	p.trace = r.captureTrace(id)
	r.drain(p)
}

// reject counts n triggers dropped while an incident is written.
func (r *recorder) reject(n int) {
	if p := r.pending; p != nil && p.manual {
		r.health.rejectedWhileManual += uint64(n)
	} else {
		r.health.rejectedWhileAutomatic += uint64(n)
	}
}

// drain writes what the ring holds after the incident's last record, a
// chunk at a time: the lock is held for the copy only.
func (r *recorder) drain(p *incident) {
	for p.failed == nil && !p.truncated {
		r.mu.Lock()
		recs, lost := r.ring.copyAfter(p.last, r.chunk)
		r.mu.Unlock()
		p.lost += lost
		if len(recs) == 0 {
			break
		}
		for i := range recs {
			if !r.write(p, &recs[i]) {
				break
			}
		}
		clear(recs)
	}
	if p.failed == nil {
		p.failed = p.w.Flush()
	}
}

// write adds one record to the events file. A file that reaches its quota
// asks for more room once and ends truncated without it.
func (r *recorder) write(p *incident, rec *record) bool {
	r.line = appendRecord(r.line[:0], rec)
	if p.written+int64(len(r.line)) > p.quota {
		if p.quota < incidentFileMax {
			if room, err := r.makeRoom(int64(len(r.line))); err == nil {
				p.quota = min(p.written+room, incidentFileMax)
			}
		}
		if p.written+int64(len(r.line)) > p.quota {
			p.truncated = true
			return false
		}
	}
	if _, err := p.w.Write(r.line); err != nil {
		p.failed = err
		return false
	}
	p.written += int64(len(r.line))
	if p.first == 0 {
		p.first, p.firstRec = rec.seq, *rec
	}
	p.last, p.lastRec = rec.seq, *rec
	if rec.flow != nil {
		p.flows[rec.flow] = struct{}{}
	}
	return true
}

// finish writes the rest of the incident and its manifest, the manifest
// last: an incident with a manifest is complete.
func (r *recorder) finish(p *incident, shutdown bool) {
	// Pending through the drain: the room it asks for must not come from
	// its own partial file.
	r.drain(p)
	r.pending = nil
	err := r.commit(p.f, p.id+eventsSuffix, p.failed)
	if err == nil {
		var data []byte
		data, err = json.Marshal(r.manifest(p, shutdown), json.Deterministic(true), jsontext.WithIndent("  "))
		if err == nil {
			// A few kilobytes past the budget, so that a truncated incident
			// is still complete.
			err = r.writeFile(p.id+manifestSuffix, data)
		}
	}
	if err != nil {
		r.health.failed++
		slog.Error("Latency incident not saved", "incident", p.id, "error", err)
	}
}

type manifest struct {
	Schema                 int                   `json:"schema"`
	IncidentID             string                `json:"incident_id"`
	RunID                  string                `json:"run_id"`
	BootID                 string                `json:"boot_id"`
	ProcessID              int                   `json:"process_id"`
	GoVersion              string                `json:"go_version"`
	BuildVersion           string                `json:"build_version"`
	GOOS                   string                `json:"goos"`
	GOARCH                 string                `json:"goarch"`
	RecorderStartUTC       time.Time             `json:"recorder_start_utc"`
	Trigger                manifestTrigger       `json:"trigger"`
	Window                 manifestWindow        `json:"window"`
	Trace                  string                `json:"trace"`
	Flows                  []manifestFlow        `json:"flows"`
	Limits                 manifestLimits        `json:"limits"`
	Health                 manifestHealth        `json:"health"`
	RuntimeHistogramBounds map[string][]*float64 `json:"runtime_histogram_bounds"`
}

type manifestTrigger struct {
	Source                 string    `json:"source"`
	Reason                 string    `json:"reason,omitempty"`
	Flow                   uint32    `json:"flow,omitzero"`
	PriorAutomaticIncident string    `json:"prior_automatic_incident,omitempty"`
	UTC                    time.Time `json:"utc"`
	ElapsedNS              int64     `json:"elapsed_ns"`
}

type manifestWindow struct {
	FirstSeq              uint64    `json:"first_seq,omitzero"`
	LastSeq               uint64    `json:"last_seq,omitzero"`
	StartElapsedNS        int64     `json:"start_elapsed_ns,omitzero"`
	EndElapsedNS          int64     `json:"end_elapsed_ns,omitzero"`
	StartUTC              time.Time `json:"start_utc,omitzero"`
	EndUTC                time.Time `json:"end_utc,omitzero"`
	LostBeforeCapture     uint64    `json:"lost_before_capture"`
	ShutdownBeforePostEnd bool      `json:"shutdown_before_post_end"`
	Truncated             bool      `json:"truncated"`
}

type manifestFlow struct {
	Flow      uint32 `json:"flow"`
	Leg       string `json:"leg"`
	Transport string `json:"transport"`
	Local     string `json:"local"`
	Remote    string `json:"remote"`
}

// manifestLimits is every constant that shaped the records, so a reader
// needs no source to read them.
type manifestLimits struct {
	SampleIntervalNS     int64 `json:"sample_interval_ns"`
	TransportSampleEvery int   `json:"transport_sample_every"`
	SlowWriteNS          int64 `json:"slow_write_ns"`
	RingRecords          int   `json:"ring_records"`
	HistoryWindowNS      int64 `json:"history_window_ns"`
	PostWindowNS         int64 `json:"post_window_ns"`
	SelectedSockets      int   `json:"selected_sockets"`
	NewSocketBurst       int   `json:"new_socket_burst"`
	NewSocketsPerSecond  int   `json:"new_sockets_per_second"`
	SpikeExcessNS        int64 `json:"spike_excess_ns"`
	SpikeStreak          int   `json:"spike_streak"`
	SpikeCooldownNS      int64 `json:"spike_cooldown_ns"`
	DiskBudgetBytes      int64 `json:"disk_budget_bytes"`
	FreeDiskReserveBytes int64 `json:"free_disk_reserve_bytes"`
	IncidentFileMaxBytes int64 `json:"incident_file_max_bytes"`
	TraceMinAgeNS        int64 `json:"trace_min_age_ns"`
	TraceMaxBytes        int64 `json:"trace_max_bytes"`
}

var limits = manifestLimits{
	SampleIntervalNS: int64(sampleInterval), TransportSampleEvery: transportSampleEvery,
	SlowWriteNS: int64(slowWrite), RingRecords: ringRecords, HistoryWindowNS: int64(historyWindow),
	PostWindowNS: int64(postWindow), SelectedSockets: selectedSockets, NewSocketBurst: newSocketBurst,
	NewSocketsPerSecond: newSocketsPerSecond, SpikeExcessNS: int64(spikeExcess), SpikeStreak: spikeStreak,
	SpikeCooldownNS: int64(spikeCooldown), DiskBudgetBytes: diskBudget, FreeDiskReserveBytes: freeDiskReserve,
	IncidentFileMaxBytes: incidentFileMax, TraceMinAgeNS: int64(traceMinAge), TraceMaxBytes: traceMaxBytes,
}

type manifestHealth struct {
	Overwritten            uint64            `json:"overwritten"`
	RejectedMarker         uint64            `json:"rejected_marker"`
	RejectedWhileManual    uint64            `json:"rejected_while_manual"`
	RejectedWhileAutomatic uint64            `json:"rejected_while_automatic"`
	FailedSnapshots        uint64            `json:"failed_snapshots"`
	RotatedIncidents       uint64            `json:"rotated_incidents"`
	Selection              manifestSelection `json:"selection"`
}

type manifestSelection struct {
	Admitted      uint64 `json:"admitted"`
	OmittedRate   uint64 `json:"omitted_rate"`
	OmittedActive uint64 `json:"omitted_active"`
	EvictedClosed uint64 `json:"evicted_closed"`
}

func (r *recorder) manifest(p *incident, shutdown bool) *manifest {
	r.mu.Lock()
	overwritten, sel := r.ring.overwritten, r.selection
	r.mu.Unlock()
	m := &manifest{
		Schema: manifestSchema, IncidentID: p.id, RunID: r.runID, BootID: r.bootID,
		ProcessID: os.Getpid(), GoVersion: runtime.Version(), BuildVersion: buildinfo.Version(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, RecorderStartUTC: r.start.UTC(),
		Trigger: manifestTrigger{
			Source: sourceAutomatic, PriorAutomaticIncident: p.prior,
			UTC: p.at.UTC(), ElapsedNS: p.atMono,
		},
		Window: manifestWindow{
			LostBeforeCapture: p.lost, ShutdownBeforePostEnd: shutdown, Truncated: p.truncated,
		},
		Trace:  traceNames[p.trace.Load()],
		Flows:  []manifestFlow{},
		Limits: limits,
		Health: manifestHealth{
			Overwritten: overwritten, RejectedMarker: r.health.rejectedMarker,
			RejectedWhileManual: r.health.rejectedWhileManual, RejectedWhileAutomatic: r.health.rejectedWhileAutomatic,
			FailedSnapshots: r.health.failed, RotatedIncidents: r.health.rotated,
			Selection: manifestSelection{Admitted: sel.admitted, OmittedRate: sel.omittedRate, OmittedActive: sel.omittedActive, EvictedClosed: sel.evictedClosed},
		},
		RuntimeHistogramBounds: r.sampler.histogramBounds(),
	}
	if p.manual {
		m.Trigger.Source = sourceManual
	} else {
		m.Trigger.Reason = spikeNames[p.spike.reason]
		if p.spike.flow != nil {
			m.Trigger.Flow = p.spike.flow.id
		}
	}
	if p.first != 0 {
		m.Window.FirstSeq, m.Window.LastSeq = p.first, p.last
		m.Window.StartElapsedNS, m.Window.EndElapsedNS = p.firstRec.mono, p.lastRec.mono
		m.Window.StartUTC, m.Window.EndUTC = time.Unix(0, p.firstRec.wall).UTC(), time.Unix(0, p.lastRec.wall).UTC()
	}
	for f := range p.flows {
		m.Flows = append(m.Flows, manifestFlow{Flow: f.id, Leg: f.leg, Transport: f.transport, Local: f.local, Remote: f.remote})
	}
	slices.SortFunc(m.Flows, func(a, b manifestFlow) int { return cmp.Compare(a.Flow, b.Flow) })
	return m
}

// histogramBounds are the bucket bounds of the runtime histograms, as of
// the last tick; an unbounded end is null.
func (sm *sampler) histogramBounds() map[string][]*float64 {
	out := make(map[string][]*float64, len(runtimeHistograms))
	for i, name := range runtimeHistograms {
		v := sm.metrics[len(runtimeScalars)+i].Value
		if v.Kind() != metrics.KindFloat64Histogram {
			continue
		}
		var bounds []*float64
		for _, b := range v.Float64Histogram().Buckets {
			if math.IsInf(b, 0) {
				bounds = append(bounds, nil)
			} else {
				bounds = append(bounds, &b)
			}
		}
		out[name] = bounds
	}
	return out
}

// pollMarker reads the operator's marker. A marker that is not a regular
// file of at most markerMaxBytes holding a UUID is counted at every poll; a
// marker seen already, or one whose incident was saved before this process
// started, starts nothing.
func (r *recorder) pollMarker() (string, bool) {
	data, err := readMarker(filepath.Join(r.dir, markerName))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	var id string
	if err == nil {
		var m struct {
			IncidentID string `json:"incident_id"`
		}
		if err = json.Unmarshal(data, &m); err == nil {
			var u uuid.UUID
			u, err = uuid.Parse(m.IncidentID)
			id = u.String()
		}
	}
	if err != nil {
		r.health.rejectedMarker++
		return "", false
	}
	if id == r.lastMarker {
		return "", false
	}
	r.lastMarker = id
	if p := r.pending; p != nil && (p.id == id || p.prior == id) {
		return "", false
	}
	if _, err := os.Lstat(filepath.Join(r.dir, id+manifestSuffix)); err == nil {
		return "", false
	}
	return id, true
}

// openMarker opens the marker; a test removes it first.
var openMarker = os.Open

// readMarker reads the marker. One removed between the look and the read
// gives fs.ErrNotExist too: no marker, not a bad one.
func readMarker(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > markerMaxBytes {
		return nil, errors.New("the marker is not a regular file of at most 4096 bytes")
	}
	f, err := openMarker(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, markerMaxBytes+1))
	if err == nil && len(b) > markerMaxBytes {
		err = errors.New("the marker grew past 4096 bytes")
	}
	return b, err
}

// captureTrace writes the flight recorder's window for the incident id in
// a goroutine of its own, one at a time: a large write must not hold up the
// ticks. The room is made here, on the worker, which alone removes files.
func (r *recorder) captureTrace(id string) *atomic.Int32 {
	state := new(atomic.Int32)
	if r.flight == nil {
		return state
	}
	if !r.tracing.CompareAndSwap(false, true) {
		state.Store(traceSkipped)
		return state
	}
	r.traceID = id
	room, err := r.makeRoom(incidentReserve)
	var f *os.File
	if err == nil {
		f, err = privatefs.CreateTemp(r.dir, id+traceSuffix+".*.partial")
	}
	if err != nil {
		r.tracing.Store(false)
		state.Store(traceFailed)
		slog.Error("Latency incident trace not saved", "incident", id, "error", err)
		return state
	}
	state.Store(traceWriting)
	r.traces.Go(func() {
		defer r.tracing.Store(false)
		_, err := r.flight.WriteTo(&quotaWriter{w: f, left: min(room, incidentFileMax)})
		if err = r.commit(f, id+traceSuffix, err); err != nil {
			state.Store(traceFailed)
			slog.Error("Latency incident trace not saved", "incident", id, "error", err)
			return
		}
		state.Store(traceCaptured)
	})
	return state
}
