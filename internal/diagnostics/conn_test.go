package diagnostics

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// One write in transportSampleEvery is recorded, and every slow one; a read
// only in its turn, however long it waited, and its wait goes to the socket.
func TestPeriodicCallsAndSlowWritesAreRecorded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testRecorder(t)
		c := &fakeConn{}
		o := ObserveConn(c, "outer", "obfs")
		b := make([]byte, 100)
		for i := range 2 * transportSampleEvery {
			if i == 10 {
				c.writeDelay.Store(int64(slowWrite))
				c.readDelay.Store(int64(time.Second))
			}
			_, _ = o.Write(b)
			_, _ = o.Read(b)
			c.writeDelay.Store(0)
			c.readDelay.Store(0)
		}
		var writes, reads []record
		for _, rec := range ofKind(r.records(), kindStage) {
			if rec.what == stageWrite {
				writes = append(writes, rec)
			} else {
				reads = append(reads, rec)
			}
		}
		if len(writes) != 3 || writes[0].flags != flagPeriodic || writes[1].flags != flagSlow ||
			writes[1].dur != int64(slowWrite) || writes[1].n != 100 || writes[2].flags != flagPeriodic {
			t.Fatalf("writes %+v", writes)
		}
		if len(reads) != 2 || reads[0].flags != flagPeriodic || reads[1].flags != flagPeriodic {
			t.Fatalf("reads %+v", reads)
		}
		s := o.(*observedConn).s
		if s.readWait.Load() != int64(time.Second) || s.reads.Load() != 2*transportSampleEvery {
			t.Fatalf("read wait %v after %d reads", time.Duration(s.readWait.Load()), s.reads.Load())
		}
	})
}

// The wrapper keeps what the code above it asks of the connection.
func TestTheWrapperKeepsTheConnection(t *testing.T) {
	testRecorder(t)
	half := &fakeHalfConn{}
	o := ObserveConn(half, "outer", "ws")
	cw, ok := o.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil || !half.halfClosed {
		t.Fatal("CloseWrite did not reach the connection")
	}
	plain := ObserveConn(&fakeConn{}, "outer", "obfs")
	if _, ok := plain.(interface{ CloseWrite() error }); ok {
		t.Fatal("a connection without CloseWrite got one")
	}
	if nc := o.(interface{ NetConn() net.Conn }).NetConn(); nc != half {
		t.Fatalf("NetConn is %T", nc)
	}
	if sc, err := tcptune.Socket(o); err != nil || sc != half {
		t.Fatalf("the walk found %T (%v)", sc, err)
	}
	at := time.Unix(1, 0)
	if err := o.SetDeadline(at); err != nil || !half.deadline.Equal(at) {
		t.Fatal("the deadline did not pass through")
	}
	if o.LocalAddr().String() != "127.0.0.1:1080" {
		t.Fatal("the address did not pass through")
	}
}

// Closing records the last counters and the totals once, and gives the slot
// back; the connection is closed every time it is asked.
func TestClosingRecordsTheFlowOnce(t *testing.T) {
	r := testRecorder(t)
	c := &fakeConn{}
	o := ObserveConn(c, "outer", "obfs")
	_, _ = o.Write(make([]byte, 10))
	_ = o.Close()
	_ = o.Close()
	recs := r.records()
	closes := ofKind(recs, kindFlowClose)
	if len(closes) != 1 || *closes[0].payload.(*flowTotals) != (flowTotals{writes: 1}) {
		t.Fatalf("flow_close records %+v", closes)
	}
	var reasons []uint8
	for _, rec := range ofKind(recs, kindSocket) {
		reasons = append(reasons, rec.what)
		if rec.payload.(*tcpSample).available {
			t.Error("a kernel that says nothing gave counters")
		}
	}
	if len(reasons) != 2 || reasons[0] != sampleOpen || reasons[1] != sampleClose {
		t.Fatalf("socket samples %v", reasons)
	}
	if len(r.sockets) != 0 || c.closed.Load() != 2 {
		t.Fatalf("%d selected, closed %d times", len(r.sockets), c.closed.Load())
	}
}

// A recorder that stopped leaves its wrappers passing calls through.
func TestAStoppedRecorderRecordsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testRecorder(t)
		c := &fakeConn{}
		o := ObserveConn(c, "outer", "obfs")
		before := len(r.records())
		r.stopped.Store(true)
		c.writeDelay.Store(int64(time.Second))
		for range 2 * transportSampleEvery {
			_, _ = o.Write([]byte{1})
			_, _ = o.Read([]byte{1})
		}
		_ = o.Close()
		if after := len(r.records()); after != before || len(r.sockets) != 0 {
			t.Fatalf("%d records after the stop, %d selected", after-before, len(r.sockets))
		}
	})
}
