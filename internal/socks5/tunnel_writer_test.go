package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/diagnostics"
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

// gatedSocket is a gatedWriter that is a connection, with nothing under it
// for the walks to find.
type gatedSocket struct {
	net.Conn
	*gatedWriter
}

func (s gatedSocket) Write(p []byte) (int, error) { return s.gatedWriter.Write(p) }

func startTunnelWriter(t *testing.T, w *gatedWriter) *TunnelWriter {
	t.Helper()
	return startTunnelWriterAs(t, w, (*TunnelWriter).Run)
}

// watchedRun runs a writer as Run does once the latency recorder watches its
// queue.
func watchedRun(tw *TunnelWriter) error { return tw.run(true) }

func startTunnelWriterAs(t *testing.T, w *gatedWriter, run func(*TunnelWriter) error) *TunnelWriter {
	t.Helper()
	tw := NewTunnelWriter(gatedSocket{gatedWriter: w}, func() []byte { return []byte("control") }, nil)
	done := make(chan error, 1)
	go func() { done <- run(tw) }()
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

// A watched writer shows its queue at each sample: what waits in it, the
// write in progress - a frame's or the control frame's - and how long it has
// taken so far, the longest wait of a frame written since the sample before,
// taken once, and the drops since it started.
func TestAWatchedTunnelWriterShowsItsQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriterAs(t, w, watchedRun)
		expect := func(when string, want diagnostics.QueueState) {
			t.Helper()
			if got := tw.QueueState(); got != want {
				t.Fatalf("%s: %+v, want %+v", when, got, want)
			}
		}
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)
		tw.Submit([]byte("second"), nil, 6)
		tw.Submit([]byte("third"), nil, 5)
		expect("a write held", diagnostics.QueueState{Frames: 2, Bytes: 2 * tunnelSmallFrame, Writing: true, WriteElapsed: 100 * time.Millisecond})
		time.Sleep(50 * time.Millisecond)
		w.gate <- struct{}{}
		synctest.Wait()
		expect("the next write", diagnostics.QueueState{Frames: 1, Bytes: tunnelSmallFrame, WaitMax: 50 * time.Millisecond, Writing: true})
		expect("the wait taken", diagnostics.QueueState{Frames: 1, Bytes: tunnelSmallFrame, Writing: true})
		time.Sleep(tunnelFrameAge)
		w.gate <- struct{}{}
		synctest.Wait()
		expect("a frame dropped by its age", diagnostics.QueueState{DroppedAge: 1})
		tw.Control()
		synctest.Wait()
		time.Sleep(20 * time.Millisecond)
		expect("the control frame held", diagnostics.QueueState{DroppedAge: 1, Writing: true, WriteElapsed: 20 * time.Millisecond})
		w.gate <- struct{}{}
		tw.Submit([]byte("fourth"), nil, 6)
		synctest.Wait()
		for range tunnelQueueFrames {
			tw.Submit([]byte("queued"), nil, 6)
		}
		tw.Submit([]byte("past"), nil, 4)
		expect("a full queue", diagnostics.QueueState{Frames: tunnelQueueFrames, Bytes: tunnelQueueBytes, DroppedFull: 1, DroppedAge: 1, Writing: true})
	})
}

// A writer the recorder does not watch keeps nothing for it.
func TestAnUnwatchedTunnelWriterKeepsNoQueueState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &gatedWriter{gate: make(chan struct{})}
		tw := startTunnelWriter(t, w)
		tw.Submit([]byte("first"), nil, 5)
		synctest.Wait()
		time.Sleep(10 * time.Millisecond)
		tw.Submit([]byte("second"), nil, 6)
		time.Sleep(10 * time.Millisecond)
		w.gate <- struct{}{}
		synctest.Wait()
		if got := tw.QueueState(); got != (diagnostics.QueueState{}) {
			t.Fatalf("an unwatched writer holding its second write: %+v", got)
		}
	})
}

// Samples read a watched writer while it takes frames, writes them and the
// control frame, and stops, and after it has stopped.
func TestSamplesOfAWatchedTunnelWriterRaceNothing(t *testing.T) {
	tw := NewTunnelWriter(io.Discard, func() []byte { return []byte{0, 0} }, nil)
	done := make(chan error, 1)
	go func() { done <- tw.run(true) }()
	sampled := make(chan struct{})
	var sampling sync.WaitGroup
	sampling.Go(func() {
		for {
			select {
			case <-sampled:
				return
			default:
				_ = tw.QueueState()
			}
		}
	})
	for i := range 4000 {
		tw.Submit([]byte("frame"), nil, 5)
		if i%64 == 0 {
			tw.Control()
		}
	}
	tw.Stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(sampled)
	sampling.Wait()
	if st := tw.QueueState(); st.Writing || st.Frames != 0 {
		t.Fatalf("a writer that stopped: %+v", st)
	}
}

// takingSocket takes every write at once and says when it has taken the
// number it waits for. The walks go through it to the connection it wraps,
// which is never written to.
type takingSocket struct {
	net.Conn
	taken, wait atomic.Int64
	reached     chan struct{}
}

func (c *takingSocket) Write(p []byte) (int, error) {
	if c.taken.Add(1) == c.wait.Load() {
		c.reached <- struct{}{}
	}
	return len(p), nil
}

func (c *takingSocket) NetConn() net.Conn { return c.Conn }

// A writer on a socket the recorder selected holds the watch of its queue
// while it runs, and gives it back when it ends.
func TestARunningTunnelWriterHoldsTheWatchOfItsSocket(t *testing.T) {
	startLatency(t)
	dialed, _ := loopbackPair(t)
	observed := diagnostics.ObserveConn(dialed, "outer", "obfs")
	if observed == dialed {
		t.Fatal("the recorder did not select the socket")
	}
	socket := &takingSocket{Conn: observed, reached: make(chan struct{})}
	tw := NewTunnelWriter(socket, func() []byte { return nil }, nil)
	done := make(chan error, 1)
	go func() { done <- tw.Run() }()
	socket.wait.Store(1)
	tw.Submit([]byte("frame"), nil, 5)
	<-socket.reached
	other := NewTunnelWriter(io.Discard, nil, nil)
	if stop := diagnostics.ObserveQueue(observed, other); stop != nil {
		stop()
		t.Fatal("a second queue watched beside a running writer")
	}
	tw.Stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stop := diagnostics.ObserveQueue(observed, other)
	if stop == nil {
		t.Fatal("a writer that ended kept the watch of its socket")
	}
	stop()
}

// What a frame costs through a TunnelWriter whose stream takes it at once, in
// bursts of 256: with the latency recorder off, and with the writer's socket
// selected by it.
func BenchmarkTunnelWriterFrame(b *testing.B) {
	for _, mode := range []string{"off", "selected"} {
		b.Run(mode, func(b *testing.B) {
			dialed, _ := loopbackPair(b)
			c := dialed
			if mode == "selected" {
				startLatency(b)
				if c = diagnostics.ObserveConn(dialed, "outer", "obfs"); c == dialed {
					b.Fatal("the recorder did not select the socket")
				}
			}
			socket := &takingSocket{Conn: c, reached: make(chan struct{})}
			tw := NewTunnelWriter(socket, func() []byte { return nil }, nil)
			done := make(chan error, 1)
			go func() { done <- tw.Run() }()
			defer func() {
				tw.Stop()
				<-done
			}()
			const burst = 256
			frame := make([]byte, 64)
			b.ReportAllocs()
			for b.Loop() {
				socket.wait.Store(socket.taken.Load() + burst)
				for range burst {
					tw.Submit(frame, nil, len(frame))
				}
				<-socket.reached
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*burst), "ns/frame")
		})
	}
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
