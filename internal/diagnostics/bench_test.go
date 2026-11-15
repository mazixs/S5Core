package diagnostics

import (
	"net"
	"testing"
)

// What every accept and every tunnel pays with diagnostics off.
func BenchmarkObserveConnDisabled(b *testing.B) {
	var c net.Conn = &fakeConn{}
	b.ReportAllocs()
	for b.Loop() {
		_ = ObserveConn(c, "outer", "obfs")
	}
}

// What every CONNECT relay pays with diagnostics off.
func BenchmarkObserveRelatedDisabled(b *testing.B) {
	var outer, related net.Conn = &fakeConn{}, &fakeConn{}
	b.ReportAllocs()
	for b.Loop() {
		_ = ObserveRelated(outer, related, "target")
	}
}

// What every native UDP association's writer pays with diagnostics off.
func BenchmarkObserveQueueDisabled(b *testing.B) {
	var c net.Conn = &fakeConn{}
	q := &fakeQueue{}
	b.ReportAllocs()
	for b.Loop() {
		_ = ObserveQueue(c, q)
	}
}

// One read and one write through the wrapper, outside their turn: direct,
// through a stopped recorder's wrapper, recorded, and recorded as the related
// side of a relay.
func BenchmarkObservedTransport(b *testing.B) {
	direct := &fakeConn{}
	testRecorder(b)
	recorded := ObserveConn(&fakeConn{}, "outer", "obfs")
	related := ObserveRelated(recorded, &fakeConn{}, "target")
	stopped := ObserveConn(&fakeConn{}, "outer", "obfs")
	stoppedRecorder := newRecorder()
	stoppedRecorder.stopped.Store(true)
	stopped.(*observedConn).r = stoppedRecorder
	p := make([]byte, 1)
	for _, bc := range []struct {
		name string
		conn net.Conn
	}{{"direct", direct}, {"stopped", stopped}, {"recorded", recorded}, {"related", related}} {
		b.Run(bc.name+"/read", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = bc.conn.Read(p)
			}
		})
		b.Run(bc.name+"/write", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = bc.conn.Write(p)
			}
		})
	}
}

// A stage record, as a periodic or slow call makes it on the forwarding
// path.
func BenchmarkRecordStage(b *testing.B) {
	r := testRecorder(b)
	s := ObserveConn(&fakeConn{}, "outer", "obfs").(*observedConn).s
	b.ReportAllocs()
	for b.Loop() {
		r.stage(s, stageWrite, slowWrite, 16384, nil, false)
	}
}
