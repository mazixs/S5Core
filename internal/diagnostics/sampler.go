package diagnostics

import (
	"errors"
	"net"
	"runtime/metrics"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// countersOf is tcptune.CountersOf; a test stands in a kernel.
var countersOf = tcptune.CountersOf

// sampleInterval is how often the worker samples the runtime and every
// sampled socket.
const sampleInterval = 500 * time.Millisecond

// sampler is what the worker reuses from tick to tick.
type sampler struct {
	metrics []metrics.Sample // runtimeScalars, then runtimeHistograms
	sockets []*socket
	queues  []*watchedQueue // of each of sockets, nil where none is watched
	// claims are the recorder's, taken at the tick; the two slices take
	// turns.
	claims []*socket
}

func newSampler() sampler {
	s := sampler{metrics: make([]metrics.Sample, 0, len(runtimeScalars)+len(runtimeHistograms))}
	for _, name := range runtimeScalars {
		s.metrics = append(s.metrics, metrics.Sample{Name: name})
	}
	for _, name := range runtimeHistograms {
		s.metrics = append(s.metrics, metrics.Sample{Name: name})
	}
	return s
}

func (sm *sampler) readRuntime() *runtimeSample {
	metrics.Read(sm.metrics)
	hists := sm.metrics[len(runtimeScalars):]
	n := 0
	for i := range hists {
		if hists[i].Value.Kind() == metrics.KindFloat64Histogram {
			n += len(hists[i].Value.Float64Histogram().Counts)
		}
	}
	s := &runtimeSample{counts: make([]uint64, 0, n)}
	for i := range runtimeScalars {
		s.scalars[i] = sm.metrics[i].Value
	}
	for i := range hists {
		if hists[i].Value.Kind() == metrics.KindFloat64Histogram {
			s.counts = append(s.counts, hists[i].Value.Float64Histogram().Counts...)
		}
		s.ends[i] = len(s.counts)
	}
	return s
}

// spike is what the detector found in a tick.
type spike struct {
	flow   *flowInfo
	reason uint8
}

// tick samples the runtime and every sampled socket, and the queue in front
// of a socket right after it. It returns the first spike of the tick, and
// how many more there were: the losses of native paths claimed since the
// tick before come first, then what the detector saw. A socket closed under
// its wrapper is evicted here.
func (r *recorder) tick(now time.Time) (first spike, more int) {
	r.push(record{kind: kindRuntime, payload: r.sampler.readRuntime()})
	r.mu.Lock()
	for s := range r.sockets {
		r.sampler.sockets = append(r.sampler.sockets, s)
		r.sampler.queues = append(r.sampler.queues, s.queue)
	}
	r.claims, r.sampler.claims = r.sampler.claims, r.claims
	r.mu.Unlock()
	note := func(s *socket, reason uint8) {
		if first.reason == 0 {
			first = spike{flow: s.flow, reason: reason}
		} else {
			more++
		}
	}
	// A claim stands whether or not its socket is still sampled.
	for _, s := range r.sampler.claims {
		if s.detector.claim(now) {
			note(s, spikeNativeLost)
		}
	}
	clear(r.sampler.claims)
	r.sampler.claims = r.sampler.claims[:0]
	for i, s := range r.sampler.sockets {
		c, err := countersOf(s.conn)
		if errors.Is(err, net.ErrClosed) {
			r.evict(s)
			continue
		}
		r.push(record{flow: s.flow, kind: kindSocket, what: sampleTick, payload: &tcpSample{
			counters: c, available: err == nil, readWait: time.Duration(s.readWait.Swap(0)),
		}})
		if w := r.sampler.queues[i]; w != nil {
			r.sampleQueue(s, w)
		}
		// A related socket starts no incident: its path is not the tunnel's.
		if err != nil || s.outer != nil {
			continue
		}
		if reason := s.detector.observe(now, &c); reason != 0 {
			note(s, reason)
		}
	}
	clear(r.sampler.sockets)
	clear(r.sampler.queues)
	r.sampler.sockets, r.sampler.queues = r.sampler.sockets[:0], r.sampler.queues[:0]
	return first, more
}

// evict ends the sampling of a socket that was closed under its wrapper,
// which itself was never closed.
func (r *recorder) evict(s *socket) {
	r.mu.Lock()
	if r.unsampleLocked(s) {
		r.selection.evictedClosed++
		r.pushLocked(record{flow: s.flow, kind: kindFlowClose, payload: &flowTotals{reads: s.reads.Load(), writes: s.writes.Load(), evicted: true}})
	}
	r.mu.Unlock()
}
