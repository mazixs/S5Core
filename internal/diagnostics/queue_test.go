package diagnostics

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// fakeQueue holds the frames a test gives it and counts the samples that
// read it; onRead, when set, runs inside the read.
type fakeQueue struct {
	frames, reads atomic.Int64
	onRead        func()
}

func (q *fakeQueue) QueueState() QueueState {
	q.reads.Add(1)
	if q.onRead != nil {
		q.onRead()
	}
	return QueueState{Frames: int(q.frames.Load())}
}

// stateQueue answers every sample with the same state.
type stateQueue QueueState

func (q *stateQueue) QueueState() QueueState { return QueueState(*q) }

func TestObserveQueueOffWatchesNothing(t *testing.T) {
	var c net.Conn = panicConn{}
	q := &fakeQueue{}
	if stop := ObserveQueue(c, q); stop != nil {
		t.Fatal("a queue watched with the recorder off")
	}
	if n := testing.AllocsPerRun(1000, func() { _ = ObserveQueue(c, q) }); n != 0 {
		t.Fatalf("%v allocations per call", n)
	}
}

// A queue is watched beside a selected socket found under the wrappers of
// the connection, one queue at a time, and beside nothing else: a socket the
// recorder never took or no longer samples, a related socket, or with the
// recorder stopped.
func TestAQueueNeedsASelectedSocketOfItsOwn(t *testing.T) {
	r := testRecorder(t)
	q := &fakeQueue{}
	outer := ObserveConn(&fakeConn{}, "outer", "obfs")
	related := ObserveRelated(outer, &fakeConn{}, "target")
	closed := ObserveConn(&fakeConn{}, "outer", "obfs")
	_ = closed.Close()
	for name, c := range map[string]net.Conn{
		"untaken": netConnOf{&fakeConn{}}, "related": related, "closed": closed,
	} {
		if stop := ObserveQueue(c, q); stop != nil {
			t.Errorf("a queue watched beside a %s socket", name)
		}
	}
	stop := ObserveQueue(unwrapOf{netConnOf{outer}}, q)
	if stop == nil {
		t.Fatal("the walk did not find the selected socket")
	}
	if again := ObserveQueue(outer, &fakeQueue{}); again != nil {
		t.Fatal("a second queue watched beside one socket")
	}
	stop()
	next := &fakeQueue{}
	if ObserveQueue(outer, next) == nil {
		t.Fatal("a queue whose watch ended left no place for the next one")
	}
	stop()
	r.tick(time.Now())
	if next.reads.Load() != 1 || q.reads.Load() != 0 {
		t.Fatalf("the stop of an ended watch ended the next one: %d reads of it", next.reads.Load())
	}
	idle := ObserveConn(&fakeConn{}, "outer", "obfs")
	r.stopped.Store(true)
	if stop := ObserveQueue(idle, q); stop != nil {
		t.Fatal("a stopped recorder watched a queue")
	}
	if n := len(ofKind(r.records(), kindQueue)); n != 1 {
		t.Fatalf("%d queue records, want the one of the next queue", n)
	}
}

// A tick records the queue right after the socket it is in front of, as it
// reads it, once per tick; a socket without one records none. A queue says
// nothing to the detector.
func TestATickRecordsTheQueueAfterItsSocket(t *testing.T) {
	r := testRecorder(t)
	q := &stateQueue{Frames: 3, Bytes: 3 * 2048, DroppedFull: 4, DroppedAge: 5,
		WaitMax: 120 * time.Millisecond, Writing: true, WriteElapsed: 700 * time.Millisecond}
	watched := ObserveConn(&fakeConn{}, "outer", "obfs")
	_ = ObserveConn(&fakeConn{}, "outer", "ws")
	if stop := ObserveQueue(watched, q); stop == nil {
		t.Fatal("the queue was not watched")
	}
	for range 2 {
		if first, more := r.tick(time.Now()); first.reason != 0 || more != 0 {
			t.Fatal("a spike from a kernel that says nothing")
		}
	}
	flow := watched.(*observedConn).s.flow
	n := 0
	recs := r.records()
	for i, rec := range recs {
		if rec.kind != kindQueue {
			continue
		}
		n++
		if rec.flow != flow || *rec.payload.(*QueueState) != QueueState(*q) {
			t.Fatalf("queue record %+v of flow %d", rec.payload, rec.flow.id)
		}
		if prev := recs[i-1]; prev.kind != kindSocket || prev.flow != flow || prev.what != sampleTick {
			t.Fatalf("the queue record follows %+v", prev)
		}
	}
	if n != 2 {
		t.Fatalf("%d queue records in two ticks", n)
	}
}

// The end of a watch ends its records however it comes: its stop, twice
// over, the socket's close, or the socket found closed under its wrapper. A
// queue no longer watched is no longer read.
func TestTheEndOfAWatchEndsItsRecords(t *testing.T) {
	r := testRecorder(t)
	closedUnder := &fakeConn{}
	kernel(t, func(c net.Conn) (tcptune.Counters, error) {
		if c == closedUnder {
			return tcptune.Counters{}, net.ErrClosed
		}
		return tcptune.Counters{}, nil
	})
	stopped, closed, evicted := &fakeQueue{}, &fakeQueue{}, &fakeQueue{}
	stop := ObserveQueue(ObserveConn(&fakeConn{}, "outer", "obfs"), stopped)
	toClose := ObserveConn(&fakeConn{}, "outer", "obfs")
	if stop == nil || ObserveQueue(toClose, closed) == nil || ObserveQueue(ObserveConn(closedUnder, "outer", "obfs"), evicted) == nil {
		t.Fatal("a queue was not watched")
	}
	r.tick(time.Now())
	stop()
	stop()
	_ = toClose.Close()
	r.tick(time.Now())
	r.tick(time.Now())
	for name, q := range map[string]*fakeQueue{"stopped": stopped, "closed": closed} {
		if n := q.reads.Load(); n != 1 {
			t.Errorf("the %s queue was read %d times, want once before its end", name, n)
		}
	}
	if n := evicted.reads.Load(); n != 0 {
		t.Errorf("the queue of a socket closed under its wrapper was read %d times", n)
	}
	if n := len(ofKind(r.records(), kindQueue)); n != 2 {
		t.Fatalf("%d queue records, want the two of the first tick", n)
	}
	if again := ObserveQueue(toClose, &fakeQueue{}); again != nil {
		t.Fatal("a queue watched beside a closed socket")
	}
}

// A watch that ends while a sample reads its queue - by its stop or by the
// socket's close - leaves no record of what was read.
func TestAWatchEndedDuringItsSampleRecordsNothing(t *testing.T) {
	for _, end := range []string{"stop", "close"} {
		t.Run(end, func(t *testing.T) {
			r := testRecorder(t)
			c := ObserveConn(&fakeConn{}, "outer", "obfs")
			q := &fakeQueue{}
			stop := ObserveQueue(c, q)
			q.onRead = stop
			if end == "close" {
				q.onRead = func() { _ = c.Close() }
			}
			r.tick(time.Now())
			if q.reads.Load() != 1 || len(ofKind(r.records(), kindQueue)) != 0 {
				t.Fatalf("%d reads, %d queue records", q.reads.Load(), len(ofKind(r.records(), kindQueue)))
			}
		})
	}
}

// admitAll gives the selection the tokens of a burst, so that a test of
// what follows a selection is not held to its rate.
func admitAll(r *recorder) {
	r.mu.Lock()
	r.selection.credit = newSocketBurst * newSocketInterval
	r.mu.Unlock()
}

// Watches that begin and end from many goroutines - by their stop, by the
// socket's close, in either order - while ticks sample them leave no watch
// behind and no queue read after its end.
func TestWatchesTicksAndStopsFromManyGoroutines(t *testing.T) {
	r := testRecorder(t)
	var watched atomic.Int64
	var ticking sync.WaitGroup
	done := make(chan struct{})
	ticking.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
				r.tick(time.Now())
			}
		}
	})
	var queues []*fakeQueue
	var mu sync.Mutex
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				admitAll(r)
				c := ObserveConn(&fakeConn{}, "outer", "obfs")
				q := &fakeQueue{}
				q.frames.Store(int64(i))
				stop := ObserveQueue(c, q)
				if stop == nil {
					continue
				}
				watched.Add(1)
				if (g+i)%2 == 0 {
					stop()
				}
				_ = c.Close()
				stop()
				mu.Lock()
				queues = append(queues, q)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	close(done)
	ticking.Wait()
	if watched.Load() < 8*200/2 {
		t.Fatalf("%d of %d queues watched", watched.Load(), 8*200)
	}
	reads := make([]int64, len(queues))
	for i, q := range queues {
		reads[i] = q.reads.Load()
	}
	r.tick(time.Now())
	for i, q := range queues {
		if q.reads.Load() != reads[i] {
			t.Fatal("a queue was read after its watch ended")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sockets) != 0 || r.taken != 0 {
		t.Fatalf("%d sockets sampled, %d taken", len(r.sockets), r.taken)
	}
}

// An incident holds the queue records of its flow, named with their units,
// and its manifest is of schema 3.
func TestAnIncidentHoldsTheQueueOfAFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, dir := dirRecorder(t, false)
		o := ObserveConn(&fakeConn{}, "outer", "obfs")
		q := &stateQueue{Frames: 2, Bytes: 4096, DroppedFull: 1, DroppedAge: 7, WaitMax: 30 * time.Millisecond}
		stop := ObserveQueue(o, q)
		stepFor(r, 2*sampleInterval)
		*q = stateQueue{Writing: true, WriteElapsed: 400 * time.Millisecond}
		stepFor(r, sampleInterval)
		stop()
		id := uuid.New().String()
		writeMarker(t, dir, id)
		stepFor(r, sampleInterval+postWindow)
		m, events := readIncident(t, dir, id)
		if m.Schema != 3 {
			t.Fatalf("schema %d", m.Schema)
		}
		var got []string
		for _, e := range events {
			if e.Kind == "queue" {
				if e.Flow != 1 || e.Leg != "outer" || e.Transport != "obfs" {
					t.Fatalf("a queue event %+v", e)
				}
				got = append(got, mustJSON(t, e.Data))
			}
		}
		idle := `{"dropped_age_frames":7,"dropped_full_frames":1,"frame_wait_max_ns":30000000,"queued_buffer_bytes":4096,"queued_frames":2,"writing":false}`
		writing := `{"dropped_age_frames":0,"dropped_full_frames":0,"frame_wait_max_ns":0,"queued_buffer_bytes":0,"queued_frames":0,"write_elapsed_ns":400000000,"writing":true}`
		if len(got) != 3 || got[0] != idle || got[1] != idle || got[2] != writing {
			t.Fatalf("queue events %v", got)
		}
	})
}
