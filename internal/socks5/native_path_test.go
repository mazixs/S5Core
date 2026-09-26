package socks5

import "testing"

// Each word of the client is placed by its counter, whichever way it came
// and whenever it arrived (finding F2 of
// docs/reports/v2.3-rc1-audit-2026-09-26.md).
func TestTheAnswerPathOrdersTheClientsWordsByCounter(t *testing.T) {
	type word struct {
		heard   bool
		counter uint64
	}
	heard := func(c uint64) word { return word{true, c} }
	lost := func(c uint64) word { return word{false, c} }
	for _, tc := range []struct {
		name   string
		words  []word
		native bool
	}{
		{"nothing heard yet", nil, false},
		{"heard", []word{heard(0)}, true},
		{"lost after heard", []word{heard(3), lost(4)}, false},
		{"late loss decided before the datagram", []word{heard(9), lost(5)}, true},
		{"loss decided at the datagram's counter", []word{heard(5), lost(5)}, true},
		{"heard sealed before the loss", []word{lost(5), heard(4)}, false},
		{"heard sealed at the loss's next", []word{lost(5), heard(5)}, true},
		{"an old loss does not lower the bar", []word{lost(8), lost(5), heard(6)}, false},
		{"an old datagram does not lower the bar", []word{heard(9), heard(2), lost(5)}, true},
		{"loss after recovery", []word{lost(5), heard(7), lost(8)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := answerPath{count: new(NativeCounters)}
			for _, w := range tc.words {
				if w.heard {
					p.Heard(w.counter)
				} else {
					p.Lost(w.counter)
				}
			}
			if p.Native() != tc.native {
				t.Fatalf("native %v, want %v", p.Native(), tc.native)
			}
		})
	}
}

// A path that is gone takes the answers to TCP, and the next word that
// outranks the last loss signal brings them back.
func TestAGoneAnswerPathComesBackWithTheNextWord(t *testing.T) {
	p := answerPath{count: new(NativeCounters)}
	p.Lost(3)
	p.Heard(4)
	p.Gone()
	if p.Native() {
		t.Fatal("native after Gone")
	}
	p.Heard(2)
	if p.Native() {
		t.Fatal("a datagram older than the loss signal brought the answers back")
	}
	p.Heard(5)
	if !p.Native() {
		t.Fatal("the next datagram did not bring the answers back")
	}
}
