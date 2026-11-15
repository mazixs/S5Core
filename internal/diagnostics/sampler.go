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
// selected socket.
const sampleInterval = 500 * time.Millisecond

// sampler is what the worker reuses from tick to tick.
type sampler struct {
	metrics []metrics.Sample // runtimeScalars, then runtimeHistograms
	sockets []*socket
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

// tick samples the runtime and every selected socket. It returns the first
// spike the detector saw, and how many more it saw in the same tick. A
// socket closed under its wrapper gives its slot back here.
func (r *recorder) tick(now time.Time) (first spike, more int) {
	r.push(record{kind: kindRuntime, payload: r.sampler.readRuntime()})
	r.mu.Lock()
	for s := range r.sockets {
		r.sampler.sockets = append(r.sampler.sockets, s)
	}
	r.mu.Unlock()
	for _, s := range r.sampler.sockets {
		c, err := countersOf(s.conn)
		if errors.Is(err, net.ErrClosed) {
			r.evict(s)
			continue
		}
		r.push(record{flow: s.flow, kind: kindSocket, what: sampleTick, payload: &tcpSample{
			counters: c, available: err == nil, readWait: time.Duration(s.readWait.Swap(0)),
		}})
		if err != nil {
			continue
		}
		switch reason := s.detector.observe(now, &c); {
		case reason == 0:
		case first.reason == 0:
			first = spike{flow: s.flow, reason: reason}
		default:
			more++
		}
	}
	clear(r.sampler.sockets)
	r.sampler.sockets = r.sampler.sockets[:0]
	return first, more
}

// evict gives back the slot of a socket that was closed under its wrapper,
// which itself was never closed.
func (r *recorder) evict(s *socket) {
	r.mu.Lock()
	_, selected := r.sockets[s]
	delete(r.sockets, s)
	if selected {
		r.selection.evictedClosed++
		r.pushLocked(record{flow: s.flow, kind: kindFlowClose, payload: &flowTotals{reads: s.reads.Load(), writes: s.writes.Load(), evicted: true}})
	}
	r.mu.Unlock()
}
