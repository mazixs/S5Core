package nativeudp

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Waiting for one association's receive lock must not stall the shared
// index, including stats and unrelated associations.
func TestResyncWaitDoesNotHoldSharedIndex(t *testing.T) {
	_, s := pair(t)
	h := &Hub{sessions: map[*Session]struct{}{s: {}}, index: make(map[[8]byte]*Session), spent: make(map[[8]byte]*Session)}
	for tag := range s.recvTags {
		h.index[tag] = s
	}
	s.recvMu.Lock()
	done := make(chan struct{})
	go func() { h.Resync(s, 1<<40); close(done) }()
	// Mutex waits are not durable blocking in testing/synctest.
	// Give Resync time to reach the held receive lock before querying
	// the unrelated shared index.
	time.Sleep(10 * time.Millisecond)
	stats := make(chan Stats, 1)
	go func() { stats <- h.Stats() }()
	select {
	case got := <-stats:
		if got.Active != 1 {
			t.Errorf("active=%d", got.Active)
		}
	case <-time.After(time.Second):
		t.Error("resync held the shared index while waiting for one session")
	}
	s.recvMu.Unlock()
	<-done
}

func TestConcurrentResyncAndRemoveLeaveNoTags(t *testing.T) {
	h, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		_, peer := pairOf(t, byte(i))
		s := h.RegisterPeer(peer.keys, netip.MustParseAddr("127.0.0.1"))
		wg.Add(2)
		go func() {
			defer wg.Done()
			for n := uint64(1); n <= 20; n++ {
				h.Resync(s, n<<32)
			}
		}()
		go func() { defer wg.Done(); h.Remove(s) }()
	}
	wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions)+len(h.index)+len(h.spent) != 0 {
		t.Fatalf("remaining sessions=%d tags=%d spent=%d", len(h.sessions), len(h.index), len(h.spent))
	}
}
