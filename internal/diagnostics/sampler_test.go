package diagnostics

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// kernel stands in countersOf for a test.
func kernel(t testing.TB, f func(net.Conn) (tcptune.Counters, error)) {
	t.Helper()
	countersOf = f
	t.Cleanup(func() { countersOf = tcptune.CountersOf })
}

// A tick records the runtime and every selected socket, with the longest
// read since the tick before.
func TestATickSamplesTheRuntimeAndEverySocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testRecorder(t)
		slow := &fakeConn{}
		slow.readDelay.Store(int64(2 * time.Second))
		waiting := ObserveConn(slow, "outer", "obfs")
		_ = ObserveConn(&fakeConn{}, "outer", "ws")
		_, _ = waiting.Read(make([]byte, 1))
		for range 2 {
			if first, more := r.tick(time.Now()); first.reason != 0 || more != 0 {
				t.Fatal("a spike from a kernel that says nothing")
			}
		}
		recs := r.records()
		rt := ofKind(recs, kindRuntime)
		if len(rt) != 2 || len(rt[0].payload.(*runtimeSample).counts) == 0 {
			t.Fatalf("runtime records %+v", rt)
		}
		waits := map[string][]time.Duration{}
		for _, rec := range ofKind(recs, kindSocket) {
			if rec.what == sampleTick {
				waits[rec.flow.transport] = append(waits[rec.flow.transport], rec.payload.(*tcpSample).readWait)
			}
		}
		if w := waits["obfs"]; len(w) != 2 || w[0] != 2*time.Second || w[1] != 0 {
			t.Fatalf("read waits of the slow socket %v", w)
		}
		if w := waits["ws"]; len(w) != 2 || w[0] != 0 {
			t.Fatalf("read waits of the other socket %v", w)
		}
	})
}

// The detector sees the counters of every tick; a second spike in the same
// tick is only counted.
func TestATickReportsTheFirstSpike(t *testing.T) {
	r := testRecorder(t)
	acked := uint64(0)
	kernel(t, func(net.Conn) (tcptune.Counters, error) {
		acked++
		return *linuxSample(10*time.Millisecond, acked, 1), nil
	})
	a := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn).s.flow
	b := ObserveConn(&fakeConn{}, "outer", "ws").(*observedConn).s.flow
	first, more := r.tick(time.Now())
	if (first.flow != a && first.flow != b) || first.reason != spikeRTO || more != 1 {
		t.Fatalf("first %+v, more %d", first, more)
	}
	if first, more := r.tick(time.Now()); first.reason != 0 || more != 0 {
		t.Fatal("a spike inside the cooldown")
	}
}

// A socket found closed under a wrapper nobody closed gives its slot back
// with a flow_close of its own; the wrapper's close later adds nothing. A
// related one gives its place beside its outer socket back the same way.
func TestASocketClosedUnderItsWrapperIsEvicted(t *testing.T) {
	r := testRecorder(t)
	closed, closedRelated := &fakeConn{}, &fakeConn{}
	kernel(t, func(c net.Conn) (tcptune.Counters, error) {
		if c == closed || c == closedRelated {
			return tcptune.Counters{}, net.ErrClosed
		}
		return tcptune.Counters{}, nil
	})
	o := ObserveConn(closed, "outer", "obfs")
	live := ObserveConn(&fakeConn{}, "outer", "obfs")
	related := ObserveRelated(live, closedRelated, "target")
	r.tick(time.Now())
	if len(r.sockets) != 1 || r.taken != 1 || r.selection.evictedClosed != 2 {
		t.Fatalf("%d sampled, %d taken, %d evicted", len(r.sockets), r.taken, r.selection.evictedClosed)
	}
	_ = o.Close()
	_ = related.Close()
	closes := ofKind(r.records(), kindFlowClose)
	if len(closes) != 2 || !closes[0].payload.(*flowTotals).evicted || !closes[1].payload.(*flowTotals).evicted {
		t.Fatalf("flow_close records %+v", closes)
	}
	if _, ok := ObserveRelated(live, &fakeConn{}, "target").(*observedConn); !ok {
		t.Fatal("an evicted related socket kept its place")
	}
}

// A tick without sockets allocates the runtime sample and its counts, and
// nothing for the metrics it reads.
func TestATickWithoutSocketsAllocatesTheRuntimeSample(t *testing.T) {
	r := testRecorder(t)
	now := time.Now()
	if n := testing.AllocsPerRun(100, func() { r.tick(now) }); n > 2 {
		t.Fatalf("%v allocations per tick", n)
	}
}

// A tick with every slot taken by a live loopback socket, as the worker
// makes it every sampleInterval, and with a queue in front of each.
func BenchmarkSampleTick(b *testing.B) {
	for _, bc := range []struct {
		name   string
		n      int
		queues bool
	}{{"sockets=0", 0, false}, {"sockets=32", selectedSockets, false}, {"sockets=32/queues", selectedSockets, true}} {
		b.Run(bc.name, func(b *testing.B) {
			r := testRecorder(b)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			for range bc.n {
				c, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				s, err := ln.Accept()
				if err != nil {
					b.Fatal(err)
				}
				defer c.Close()
				defer s.Close()
				o := ObserveConn(c, "outer", "obfs")
				if bc.queues && ObserveQueue(o, &fakeQueue{}) == nil {
					b.Fatal("a queue was not watched")
				}
			}
			if len(r.sockets) != bc.n {
				b.Fatalf("%d selected", len(r.sockets))
			}
			now := time.Now()
			b.ReportAllocs()
			for b.Loop() {
				r.tick(now)
			}
		})
	}
}
