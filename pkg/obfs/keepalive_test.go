package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

// writeLog records what a connection put on the wire and when. Everything a
// keepalive has to get right - that it happens, that it stops happening when
// there is traffic, and that its frames are the size of real ones - is
// visible here and nowhere else.
type writeLog struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
	times []time.Time
}

func (w *writeLog) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.sizes = append(w.sizes, len(b))
	w.times = append(w.times, time.Now())
	w.mu.Unlock()
	return w.Conn.Write(b)
}

func (w *writeLog) snapshot() ([]int, []time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]int(nil), w.sizes...), append([]time.Time(nil), w.times...)
}

// keepalivePair wires a client with keepalive to a server that reads and
// discards, over a real socket. net.Pipe would not do: it is synchronous, so
// a keepalive would block until someone read it.
func keepalivePair(t *testing.T, min, max time.Duration) (net.Conn, *writeLog, chan []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	psk := bytes.Repeat([]byte("k"), 32)
	payloads := make(chan []byte, 64)

	accepted := make(chan struct{})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		close(accepted)
		server, err := NewServerConn(raw, Config{PSK: psk, MaxPadding: 0})
		if err != nil {
			return
		}
		defer server.Close()
		buf := make([]byte, 64*1024)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				payloads <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	log := &writeLog{Conn: raw}

	client, err := NewClientConn(log, Config{
		PSK:          psk,
		MaxPadding:   0,
		KeepaliveMin: min,
		KeepaliveMax: max,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	<-accepted
	return client, log, payloads
}

func TestAnIdleConnectionKeepsSendingFrames(t *testing.T) {
	client, log, payloads := keepalivePair(t, 20*time.Millisecond, 60*time.Millisecond)

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-payloads:
		if string(got) != "hello" {
			t.Fatalf("the server read %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first write never arrived")
	}

	time.Sleep(500 * time.Millisecond)

	sizes, _ := log.snapshot()
	if len(sizes) < 4 {
		t.Fatalf("only %d writes in half a second of idling: the connection is not being held open", len(sizes))
	}

	// And none of it reached the peer as data.
	select {
	case got := <-payloads:
		t.Fatalf("a keepalive surfaced at the peer as %d bytes of payload: %q", len(got), got)
	default:
	}
}

func TestTrafficSuppressesTheKeepalive(t *testing.T) {
	client, log, payloads := keepalivePair(t, 40*time.Millisecond, 80*time.Millisecond)

	deadline := time.Now().Add(400 * time.Millisecond)
	writes := 0
	for time.Now().Before(deadline) {
		if _, err := client.Write([]byte("busy")); err != nil {
			t.Fatalf("write: %v", err)
		}
		writes++
		time.Sleep(10 * time.Millisecond)
	}
	// Drain what the peer received so the channel cannot fill and block it.
	for len(payloads) > 0 {
		<-payloads
	}

	sizes, _ := log.snapshot()
	if len(sizes) > writes {
		t.Errorf("%d writes on the wire for %d application writes: the keepalive fired while the connection was busy",
			len(sizes), writes)
	}
}

func TestAKeepaliveIsTheSizeOfARealFrame(t *testing.T) {
	client, log, _ := keepalivePair(t, 20*time.Millisecond, 40*time.Millisecond)

	// One frame per write, so every entry in the log is one frame's length.
	payload := bytes.Repeat([]byte("x"), 300)
	for i := 0; i < 5; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	dataSizes, _ := log.snapshot()
	data := make(map[int]bool, len(dataSizes))
	for _, n := range dataSizes {
		data[n] = true
	}
	// The salt rides in front of the first frame, so that write is longer
	// than a frame and is not a length a keepalive should copy.
	sent := len(dataSizes)

	time.Sleep(400 * time.Millisecond)

	all, _ := log.snapshot()
	keepalives := all[sent:]
	if len(keepalives) == 0 {
		t.Fatal("no keepalive was sent")
	}
	for _, n := range keepalives {
		if !data[n] {
			t.Errorf("a keepalive of %d bytes went out, and no data frame on this connection was that size (%v)",
				n, dataSizes)
		}
	}
}

// The gate for Ф4-8: the intervals must not pile up on a constant. A frame
// every 45 seconds to the millisecond identifies the protocol without
// decrypting anything.
//
// The check is stealth.Intervals, the same function the level-2 checklist runs
// (Ф4-1), so that what passes here is what passes there.
func TestTheIntervalsAreNotAConstant(t *testing.T) {
	const (
		lo = 20 * time.Millisecond
		hi = 60 * time.Millisecond
	)
	client, log, _ := keepalivePair(t, lo, hi)

	if _, err := client.Write([]byte("start")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	_, times := log.snapshot()
	if len(times) < 20 {
		t.Fatalf("only %d frames were sent, too few to look at the spread", len(times))
	}

	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]).Seconds())
	}

	// A bucket of a millisecond is the resolution an observer across a network
	// would have. A fixed period puts nearly everything in one bucket.
	report := stealth.Intervals(gaps, 0.001)
	if report.TopShare > 0.35 {
		t.Errorf("%.0f%% of the %d intervals fall in the same %v bucket (around %.3fs) - that is a period, not a spread",
			report.TopShare*100, report.Samples, time.Millisecond, report.TopBucket)
	}

	// And the spread has to cover the configured range rather than hugging
	// one end of it.
	minGap, maxGap := gaps[0], gaps[0]
	for _, g := range gaps {
		if g < minGap {
			minGap = g
		}
		if g > maxGap {
			maxGap = g
		}
	}
	if span := maxGap - minGap; span < (hi-lo).Seconds()/2 {
		t.Errorf("intervals run from %.3fs to %.3fs, a span of %.3fs out of the %v configured",
			minGap, maxGap, span, hi-lo)
	}
	t.Logf("%d intervals from %.3fs to %.3fs, most common millisecond holds %.0f%%",
		report.Samples, minGap, maxGap, report.TopShare*100)
}

// Closing a connection must stop its timer. One goroutine left behind per
// connection is how a server with five thousand of them runs out of memory
// slowly enough that nobody connects it to the keepalive.
func TestClosingStopsTheKeepalive(t *testing.T) {
	client, log, _ := keepalivePair(t, 10*time.Millisecond, 20*time.Millisecond)

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close: %v", err)
	}

	before, _ := log.snapshot()
	time.Sleep(200 * time.Millisecond)
	after, _ := log.snapshot()

	if len(after) != len(before) {
		t.Errorf("%d more writes after Close: the keepalive goroutine outlived the connection", len(after)-len(before))
	}
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second close: %v", err)
	}
}

// Keepalive is off unless it is asked for, and a connection without it sends
// nothing of its own.
func TestWithoutKeepaliveNothingIsSent(t *testing.T) {
	client, log, _ := keepalivePair(t, 0, 0)

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	sizes, _ := log.snapshot()
	if len(sizes) != 1 {
		t.Errorf("%d writes on an idle connection with keepalive disabled, want 1", len(sizes))
	}
}

var _ io.ReadWriteCloser = (net.Conn)(nil)
