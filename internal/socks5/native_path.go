package socks5

import (
	"sync"
	"sync/atomic"
)

// answerPath is where the answers of a 0x84 association go: native while the
// client says it hears the server, by the control connection once it says it
// does not. It says the first by UDP and the second by TCP, so the two arrive
// in either order, and each word is placed by the client's datagram counter:
// a native datagram or a heard probe carries its own, a loss signal the one
// the client was at when it decided. A word older than the newest of the
// other kind changes nothing (finding F2 of the 2.3.0-rc1 audit,
// docs/veil-spec.md, 10.6).
type answerPath struct {
	native atomic.Bool
	count  *NativeCounters
	// moves counts this association's own moves to the stream, which count
	// holds for the whole server.
	moves atomic.Int64
	mu    sync.Mutex
	// heard is the highest counter of a native datagram or heard probe, lost
	// the highest next of a loss signal; each only once it has come.
	heard, lost       uint64
	hasHeard, hasLost bool
}

func (p *answerPath) Native() bool { return p.native.Load() }

// Heard is a native datagram or a heard probe. One sealed before the latest
// loss signal was decided is older news.
func (p *answerPath) Heard(counter uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hasLost && counter < p.lost {
		p.count.StaleHeard.Add(1)
		return
	}
	if !p.hasHeard || counter > p.heard {
		p.heard, p.hasHeard = counter, true
	}
	if !p.native.Swap(true) {
		p.count.ToNative.Add(1)
	}
}

// Lost is a loss signal with the counter of the client's next datagram. A
// datagram or heard probe with that counter or later was sealed after the
// client decided, and outranks it.
func (p *answerPath) Lost(next uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasLost || next > p.lost {
		p.lost, p.hasLost = next, true
	}
	if p.hasHeard && next <= p.heard {
		p.count.StaleLoss.Add(1)
		return
	}
	p.toTCP()
}

// Gone is a native path that can carry nothing more. It says nothing about
// the client, so the next word that outranks the last loss signal brings the
// answers back.
func (p *answerPath) Gone() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.toTCP()
}

func (p *answerPath) toTCP() {
	if p.native.Swap(false) {
		p.count.ToTCP.Add(1)
		p.moves.Add(1)
	}
}
