package nativeudp

import (
	"testing"
	"time"
)

func BenchmarkHubReceiveWindowAdvance(b *testing.B) {
	_, s, registered, _ := benchHub(b)
	h := &Hub{sessions: map[*Session]struct{}{registered: {}}, index: make(map[[8]byte]*Session), spent: make(map[[8]byte]*Session)}
	for tag := range registered.recvTags {
		h.index[tag] = registered
	}
	wire, err := s.Seal(nil, KindData, []byte("tick"))
	if err != nil {
		b.Fatal(err)
	}
	// Claim/decrypt is outside the shared lock; benchmark the hot publication
	// step with a one-counter advance, including its fixed change buffer.
	var tag [8]byte
	copy(tag[:], wire[:8])
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.settle(registered, tag, uint64(i))
	}
}

func BenchmarkHubResyncWindow(b *testing.B) {
	h, _, s, _ := benchHub(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.recvMu.Lock()
		s.resynced = time.Time{}
		s.recvMu.Unlock()
		h.Resync(s, uint64(i+1)*window)
	}
}
