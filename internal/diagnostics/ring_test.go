package diagnostics

import (
	"slices"
	"testing"
	"time"
	"unsafe"
)

func pushAt(g *ring, at time.Duration, payload any) {
	g.push(record{mono: int64(at), kind: kindRuntime, payload: payload})
}

func seqs(recs []record) []uint64 {
	out := make([]uint64, len(recs))
	for i := range recs {
		out[i] = recs[i].seq
	}
	return out
}

// A full ring gives up its oldest record, counts it, and lets its payload go.
func TestAFullRingDropsTheOldestRecord(t *testing.T) {
	g := newRing(4)
	for i := range 6 {
		pushAt(&g, time.Duration(i)*time.Second, &flowTotals{reads: uint64(i)})
	}
	got, lost := g.copyAfter(0, make([]record, 0, 8))
	if want := []uint64{3, 4, 5, 6}; !slices.Equal(seqs(got), want) || lost != 2 {
		t.Fatalf("records %v (lost %d), want %v (lost 2)", seqs(got), lost, want)
	}
	if g.overwritten != 2 {
		t.Errorf("overwritten %d, want 2", g.overwritten)
	}
	for i := range g.recs {
		if r := &g.recs[i]; r.seq < 3 && r.payload != nil {
			t.Errorf("slot %d still holds record %d", i, r.seq)
		}
	}
}

// What is older than historyWindow goes without being counted as lost to a
// full ring; the newest record stays however old.
func TestTheRingForgetsWhatIsOlderThanTheWindow(t *testing.T) {
	g := newRing(16)
	pushAt(&g, 0, nil)
	pushAt(&g, time.Minute, nil)
	pushAt(&g, historyWindow+time.Minute, nil)
	got, _ := g.copyAfter(0, make([]record, 0, 16))
	if want := []uint64{2, 3}; !slices.Equal(seqs(got), want) || g.overwritten != 0 {
		t.Fatalf("records %v (overwritten %d), want %v", seqs(got), g.overwritten, want)
	}
	pushAt(&g, 10*historyWindow, nil)
	if got, _ := g.copyAfter(0, make([]record, 0, 16)); !slices.Equal(seqs(got), []uint64{4}) {
		t.Fatalf("records %v, want only the newest", seqs(got))
	}
}

// copyAfter goes on from where the last copy stopped, across the end of the
// slice, in chunks of its capacity, and says what it can no longer give.
func TestCopyAfterContinuesInChunks(t *testing.T) {
	g := newRing(5)
	for i := range 7 {
		pushAt(&g, time.Duration(i), nil)
	}
	buf := make([]record, 0, 2)
	var all []uint64
	last := uint64(3)
	for {
		got, lost := g.copyAfter(last, buf)
		if lost != 0 {
			t.Fatalf("lost %d after %d", lost, last)
		}
		if len(got) == 0 {
			break
		}
		all = append(all, seqs(got)...)
		last = got[len(got)-1].seq
	}
	if want := []uint64{4, 5, 6, 7}; !slices.Equal(all, want) {
		t.Fatalf("copied %v, want %v", all, want)
	}
	if got, lost := g.copyAfter(0, buf); lost != 2 || !slices.Equal(seqs(got), []uint64{3, 4}) {
		t.Fatalf("from the start: %v, lost %d", seqs(got), lost)
	}
	empty := newRing(2)
	if got, lost := empty.copyAfter(0, buf); len(got) != 0 || lost != 0 {
		t.Fatalf("an empty ring gave %v, lost %d", seqs(got), lost)
	}
}

// Asking again with nothing new costs nothing, and neither does a copy into
// the worker's buffer.
func TestCopyAfterDoesNotAllocate(t *testing.T) {
	g := newRing(ringRecords)
	for i := range ringRecords + 100 {
		pushAt(&g, time.Duration(i), nil)
	}
	buf := make([]record, 0, copyChunk)
	if n := testing.AllocsPerRun(100, func() { g.copyAfter(g.seq-copyChunk, buf) }); n != 0 {
		t.Fatalf("%v allocations per copy", n)
	}
	if n := testing.AllocsPerRun(100, func() { g.copyAfter(g.seq, buf) }); n != 0 {
		t.Fatalf("%v allocations per copy of nothing", n)
	}
}

func BenchmarkCopyAfter(b *testing.B) {
	g := newRing(ringRecords)
	for i := range ringRecords {
		pushAt(&g, time.Duration(i), nil)
	}
	buf := make([]record, 0, copyChunk)
	b.ReportAllocs()
	for b.Loop() {
		g.copyAfter(g.seq-copyChunk, buf)
	}
}

func TestARecordIsSixtyFourBytes(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(record{}) != 64 {
		t.Fatalf("a record is %d bytes", unsafe.Sizeof(record{}))
	}
}
