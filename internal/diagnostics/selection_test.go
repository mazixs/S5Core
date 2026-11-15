package diagnostics

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// panicConn fails a test that touches it: with diagnostics off, ObserveConn
// must not even walk the wrappers.
type panicConn struct{}

func (panicConn) Read([]byte) (int, error)         { panic("read") }
func (panicConn) Write([]byte) (int, error)        { panic("write") }
func (panicConn) Close() error                     { panic("close") }
func (panicConn) LocalAddr() net.Addr              { panic("local") }
func (panicConn) RemoteAddr() net.Addr             { panic("remote") }
func (panicConn) SetDeadline(time.Time) error      { panic("deadline") }
func (panicConn) SetReadDeadline(time.Time) error  { panic("deadline") }
func (panicConn) SetWriteDeadline(time.Time) error { panic("deadline") }
func (panicConn) NetConn() net.Conn                { panic("walk") }

func TestObserveConnOffReturnsTheConnectionUntouched(t *testing.T) {
	var c net.Conn = panicConn{}
	if got := ObserveConn(c, "outer", "obfs"); got != c {
		t.Fatalf("got %T", got)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = ObserveConn(c, "outer", "obfs") }); n != 0 {
		t.Fatalf("%v allocations per call", n)
	}
}

func TestOnlyASocketIsSelected(t *testing.T) {
	r := testRecorder(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := ObserveConn(a, "outer", "obfs"); got != a {
		t.Fatalf("a pipe came back as %T", got)
	}
	if r.selection.admitted != 0 || len(r.records()) != 0 {
		t.Fatal("a pipe was selected")
	}
	r.stopped.Store(true)
	c := &fakeConn{}
	if got := ObserveConn(c, "outer", "obfs"); got != c {
		t.Fatal("a stopped recorder selected a socket")
	}
}

// A burst of newSocketBurst, then newSocketsPerSecond; idle time refills no
// more than the burst, and a clock reading from before the last one takes
// nothing back.
func TestSelectionTakesABurstThenARate(t *testing.T) {
	var s selection
	t0 := time.Unix(1000, 0)
	allowed := func(at time.Time, n int) (k int) {
		for range n {
			if s.allow(at) {
				k++
			}
		}
		return k
	}
	if k := allowed(t0, 100); k != newSocketBurst {
		t.Fatalf("burst %d, want %d", k, newSocketBurst)
	}
	if k := allowed(t0.Add(time.Second), 100); k != newSocketsPerSecond {
		t.Fatalf("after a second %d, want %d", k, newSocketsPerSecond)
	}
	if k := allowed(t0.Add(time.Second-time.Millisecond), 100); k != 0 {
		t.Fatalf("an older clock reading got %d", k)
	}
	if k := allowed(t0.Add(time.Hour), 100); k != newSocketBurst {
		t.Fatalf("after an hour %d, want %d", k, newSocketBurst)
	}
	if k := allowed(t0.Add(time.Hour+newSocketInterval/2), 1) + allowed(t0.Add(time.Hour+newSocketInterval), 1); k != 1 {
		t.Fatalf("one interval gave %d", k)
	}
}

// Short connections give their slots back but not their tokens, so a churn
// of them is held to the rate; held connections keep their slots whatever
// the tokens.
func TestSlotsAndTokensBoundTheSelection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testRecorder(t)
		for range 100 {
			_ = ObserveConn(&fakeConn{}, "outer", "obfs").Close()
		}
		if r.selection.admitted != newSocketBurst || r.selection.omittedRate != 100-newSocketBurst {
			t.Fatalf("churn: %+v", r.selection)
		}
		time.Sleep(time.Hour)
		var held []net.Conn
		for range selectedSockets + 1 {
			held = append(held, ObserveConn(&fakeConn{}, "outer", "obfs"))
		}
		if _, ok := held[selectedSockets].(*fakeConn); !ok || r.selection.omittedActive != 1 || len(r.sockets) != selectedSockets {
			t.Fatalf("held: %+v, %d selected", r.selection, len(r.sockets))
		}
		time.Sleep(time.Hour)
		_ = held[0].Close()
		if _, ok := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn); !ok {
			t.Fatal("a slot given back was not taken")
		}
	})
}

// Selections and closes from many goroutines leave every selected socket
// with one flow_open and one flow_close and the slots all free.
func TestSelectionFromManyGoroutines(t *testing.T) {
	r := testRecorder(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 50 {
				_ = ObserveConn(&fakeConn{}, "outer", "obfs").Close()
			}
		})
	}
	wg.Wait()
	sel := r.selection
	if sel.admitted+sel.omittedRate+sel.omittedActive != 16*50 || len(r.sockets) != 0 {
		t.Fatalf("%+v, %d still selected", sel, len(r.sockets))
	}
	recs := r.records()
	opened, closed := ofKind(recs, kindFlowOpen), ofKind(recs, kindFlowClose)
	if uint64(len(opened)) != sel.admitted || len(closed) != len(opened) {
		t.Fatalf("%d admitted, %d flow_open, %d flow_close", sel.admitted, len(opened), len(closed))
	}
	ids := map[uint32]bool{}
	for _, rec := range opened {
		if ids[rec.flow.id] {
			t.Fatalf("flow %d twice", rec.flow.id)
		}
		ids[rec.flow.id] = true
	}
}
