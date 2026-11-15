package tcptune

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestAConnectionWithoutASocketHasNoCounters(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if c, err := CountersOf(a); !errors.Is(err, ErrNoSocket) {
		t.Fatalf("a pipe has counters %+v (%v)", c, err)
	}
}

func TestKnownNeedsEveryField(t *testing.T) {
	c := Counters{Has: CounterRTT | CounterBytesSent}
	for f, want := range map[CounterField]bool{
		CounterRTT:                     true,
		CounterRTT | CounterBytesSent:  true,
		CounterRTT | CounterBytesAcked: false,
		CounterTimeoutEpisodes:         false,
	} {
		if got := c.Known(f); got != want {
			t.Errorf("Known(%b) = %v, want %v", f, got, want)
		}
	}
}

// exchange moves n bytes each way and waits for both, so each side has
// acknowledged what the other sent.
func exchange(t *testing.T, c, s net.Conn, n int) {
	t.Helper()
	b := make([]byte, n)
	for _, p := range [][2]net.Conn{{c, s}, {s, c}} {
		if _, err := p[0].Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(p[1], b); err != nil {
			t.Fatal(err)
		}
	}
}
