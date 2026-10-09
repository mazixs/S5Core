package socks5

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// phaseLog records what a server reports about its phases.
type phaseLog struct {
	mu       sync.Mutex
	observed []Phase
	inPhase  map[Phase]int64
}

func (l *phaseLog) config() *Config {
	l.inPhase = map[Phase]int64{}
	return &Config{
		ObservePhase: func(p Phase, _ time.Duration, _ bool) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.observed = append(l.observed, p)
		},
		CountPhase: func(p Phase, delta int64) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.inPhase[p] += delta
		},
	}
}

func serveOnce(t *testing.T, cfg *Config, client func(net.Conn)) {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = s.ServeConnContext(context.Background(), serverSide)
		close(done)
	}()
	client(clientSide)
	_ = clientSide.Close()
	<-done
}

// A peer that never sends the version byte - a probe, an unused spare from
// a client (plan task R4-9) - is not a session and records no phase.
func TestASilentPeerRecordsNoPhaseDuration(t *testing.T) {
	var log phaseLog
	serveOnce(t, log.config(), func(net.Conn) {})

	if len(log.observed) != 0 {
		t.Fatalf("a silent peer recorded phases %v", log.observed)
	}
	for p, n := range log.inPhase {
		if n != 0 {
			t.Fatalf("phase %s gauge left at %d", p, n)
		}
	}
	if _, ok := log.inPhase[PhaseHandshake]; !ok {
		t.Fatal("the silent peer was never counted in the handshake gauge")
	}
}

func TestAPeerThatSpokeRecordsItsHandshake(t *testing.T) {
	var log phaseLog
	serveOnce(t, log.config(), func(c net.Conn) {
		_, _ = c.Write([]byte{Socks5Version})
	})

	var handshake, session bool
	for _, p := range log.observed {
		handshake = handshake || p == PhaseHandshake
		session = session || p == PhaseSession
	}
	if !handshake || !session {
		t.Fatalf("a peer that sent the version byte recorded %v", log.observed)
	}
}
