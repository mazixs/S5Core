package socks5

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// gatedWriter holds every write until it is let through, and records what
// was written.
type gatedWriter struct {
	mu      sync.Mutex
	gate    chan struct{}
	written [][]byte
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	<-w.gate
	w.mu.Lock()
	w.written = append(w.written, append([]byte(nil), p...))
	w.mu.Unlock()
	return len(p), nil
}

func (w *gatedWriter) frames() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.written...)
}

func startTunnelWriter(t *testing.T, w *gatedWriter) *TunnelWriter {
	t.Helper()
	tw := NewTunnelWriter(w, func() []byte { return []byte("control") }, nil)
	done := make(chan error, 1)
	go func() { done <- tw.Run() }()
	t.Cleanup(func() {
		tw.Stop()
		close(w.gate)
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return tw
}

// A frame past the queue is dropped and counted, and Submit does not wait for
// the stream.
func TestATunnelWriterDropsWhatItsQueueCannotHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriter(t, w)
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		for i := 0; i < tunnelQueueFrames; i++ {
			if !tw.Submit([]byte("queued"), nil, 6) {
				t.Fatalf("frame %d did not fit a queue of %d", i, tunnelQueueFrames)
			}
		}
		if tw.Submit([]byte("past"), nil, 4) {
			t.Fatal("a frame past the queue was taken")
		}
		if got := tw.Dropped(); got != 1 {
			t.Fatalf("dropped %d, want 1", got)
		}
	})
}

// The byte budget counts the buffers frames take, so a few big frames fill it
// long before the queue is full.
func TestATunnelWriterBoundsTheBytesItHolds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriter(t, w)
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		big := make([]byte, 60000)
		taken := 0
		for tw.Submit(big, nil, len(big)) {
			taken++
		}
		if want := tunnelQueueBytes / (2 + 65535); taken != want {
			t.Fatalf("%d big frames taken, want %d", taken, want)
		}
		if !tw.Submit([]byte("small"), nil, 5) {
			t.Fatal("a small frame did not fit what the big ones left")
		}
	})
}

// A frame that waited past its age is dropped when its turn comes, and one
// that did not is written whole.
func TestATunnelWriterDropsAFrameThatWaitedTooLong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriter(t, w)
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		tw.Submit([]byte("stale"), nil, 5)
		time.Sleep(tunnelFrameAge + time.Millisecond)
		tw.Submit([]byte("fresh"), nil, 5)
		w.gate <- struct{}{}
		w.gate <- struct{}{}
		synctest.Wait()
		got := w.frames()
		if len(got) != 2 || string(got[0]) != "first" || string(got[1]) != "fresh" {
			t.Fatalf("written %q, want first and fresh", got)
		}
		if tw.Dropped() != 1 {
			t.Fatalf("dropped %d, want the stale frame", tw.Dropped())
		}
	})
}

// The control frame goes ahead of every queued frame, and one asked for twice
// before it is written is written once.
func TestTheControlFrameGoesAheadOfTheQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriter(t, w)
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		tw.Submit([]byte("second"), []byte("-body"), 11)
		tw.Control()
		tw.Control()
		for range 3 {
			w.gate <- struct{}{}
		}
		synctest.Wait()
		got := w.frames()
		want := [][]byte{[]byte("first"), []byte("control"), []byte("second-body")}
		if len(got) != len(want) {
			t.Fatalf("written %q, want %q", got, want)
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("written %q, want %q", got, want)
			}
		}
	})
}

// An error of written stops the writer with that error, as the end of an
// account ends the association.
func TestAnErrorOfWrittenStopsTheTunnelWriter(t *testing.T) {
	stop := errors.New("quota")
	var buf bytes.Buffer
	tw := NewTunnelWriter(&buf, func() []byte { return nil }, func(payload int) error {
		if payload == 3 {
			return stop
		}
		return nil
	})
	tw.Submit([]byte("ab"), nil, 2)
	tw.Submit([]byte("abc"), nil, 3)
	tw.Submit([]byte("never"), nil, 5)
	if err := tw.Run(); !errors.Is(err, stop) {
		t.Fatalf("Run returned %v, want the error of written", err)
	}
	if buf.String() != "ababc" {
		t.Fatalf("written %q", buf.String())
	}
}
