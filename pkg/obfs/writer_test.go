package obfs

import (
	"bytes"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// Plan task Ф4-6: decide how a connection with more than one writer is made
// safe, and decide it by measurement rather than by taste.
//
// The comment this layer used to carry said net.Conn guarantees sequential
// Write calls. It does not - the documented contract is the opposite, that
// multiple goroutines may call a Conn at once - and the pre-allocated frame
// buffer, the counters and the mask scratch were all shared on the strength of
// that claim. Nothing had gone wrong yet only because there happened to be one
// writer per connection; keepalive (Ф4-8) or multiplexing would have ended
// that, and the corruption would have been rare, load-dependent and
// unreproducible.
//
// Two designs were on the table, and the same one has to serve both layers:
//
//   - a mutex per direction, which is what pkg/transport/ws already does;
//   - a single writer goroutine fed by a queue, the shape smux and yamux use,
//     which is also where a keepalive frame would be injected.
//
// TestTheWriterChoiceIsMadeByMeasurement prices them. The queue is not free -
// every write costs a channel round trip and two goroutine wake-ups - and it
// only starts paying for itself when there is a second producer that has to be
// scheduled anyway. The plan's rule is: if the p95 gap is under a millisecond,
// take the smaller change. It is, by three orders of magnitude, so the mutex
// wins and ws keeps the shape it already had.

// sinkConn accepts writes and returns nothing, so a measurement sees the cost
// of the writer design and not the cost of a socket.
type sinkConn struct{}

func (sinkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (sinkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (sinkConn) Close() error                     { return nil }
func (sinkConn) LocalAddr() net.Addr              { return benchAddr{} }
func (sinkConn) RemoteAddr() net.Addr             { return benchAddr{} }
func (sinkConn) SetDeadline(time.Time) error      { return nil }
func (sinkConn) SetReadDeadline(time.Time) error  { return nil }
func (sinkConn) SetWriteDeadline(time.Time) error { return nil }

// queuedWriter is the alternative design, built only to be measured: one
// goroutine owns the connection and callers hand it their buffers.
type queuedWriter struct {
	reqs chan writeReq
	wg   sync.WaitGroup
}

type writeReq struct {
	b    []byte
	resp chan error
}

func newQueuedWriter(c net.Conn, depth int) *queuedWriter {
	q := &queuedWriter{reqs: make(chan writeReq, depth)}
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for req := range q.reqs {
			_, err := c.Write(req.b)
			req.resp <- err
		}
	}()
	return q
}

// Write blocks until the frame has reached the connection, which is what
// net.Conn.Write promises and what makes the error meaningful. A queue that
// returned early would have to copy the caller's buffer and would lose the
// error, so this is the honest version of the design.
func (q *queuedWriter) Write(b []byte, resp chan error) error {
	q.reqs <- writeReq{b: b, resp: resp}
	return <-resp
}

func (q *queuedWriter) Close() {
	close(q.reqs)
	q.wg.Wait()
}

func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func TestTheWriterChoiceIsMadeByMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement")
	}

	const (
		writers        = 4
		writesPerRound = 500
	)
	payload := bytes.Repeat([]byte("x"), 1200)
	psk := bytes.Repeat([]byte("k"), 32)

	measure := func(write func(id int, resp chan error) error) []time.Duration {
		all := make([][]time.Duration, writers)
		var wg sync.WaitGroup
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resp := make(chan error, 1)
				samples := make([]time.Duration, 0, writesPerRound)
				for i := 0; i < writesPerRound; i++ {
					start := time.Now()
					if err := write(id, resp); err != nil {
						t.Errorf("writer %d: %v", id, err)
						return
					}
					samples = append(samples, time.Since(start))
				}
				all[id] = samples
			}(w)
		}
		wg.Wait()

		var merged []time.Duration
		for _, s := range all {
			merged = append(merged, s...)
		}
		return merged
	}

	withMutex, err := NewClientConn(sinkConn{}, Config{PSK: psk, MTU: 1400})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	mutexSamples := measure(func(int, chan error) error {
		_, err := withMutex.Write(payload)
		return err
	})

	behindQueue, err := NewClientConn(sinkConn{}, Config{PSK: psk, MTU: 1400})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	queue := newQueuedWriter(behindQueue, writers)
	queueSamples := measure(func(_ int, resp chan error) error {
		return queue.Write(payload, resp)
	})
	queue.Close()

	mutexP95 := percentile(mutexSamples, 0.95)
	queueP95 := percentile(queueSamples, 0.95)
	gap := mutexP95 - queueP95
	if gap < 0 {
		gap = -gap
	}

	t.Logf("p95 latency with %d concurrent writers: mutex %v, writer goroutine with a queue %v, gap %v",
		writers, mutexP95, queueP95, gap)

	if gap >= time.Millisecond {
		t.Fatalf("p95 gap is %v, which is at or above the 1 ms the plan sets as the point where the faster design wins on its own: decide by the number, not by this test", gap)
	}
	t.Logf("gap below 1 ms, so the rule picks the smaller change: a mutex per direction, in obfs and in ws alike")
}

// The gate for Ф4-6: whatever the design, two goroutines writing to one
// connection must not corrupt each other's frames, and -race must be quiet.
// Each writer sends a message of its own, so a frame built from two writers at
// once shows up as a message that is not one of the ones sent.
func TestTwoGoroutinesCanWriteToOneConnection(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client, server := obfsPair(t, Config{PSK: psk, MaxPadding: 128, MTU: 512})

	const (
		writers  = 4
		messages = 100
		msgLen   = 1500 // several frames each, so writes really do interleave
	)

	want := make(map[byte][]byte, writers)
	for w := 0; w < writers; w++ {
		tag := byte('A' + w)
		want[tag] = bytes.Repeat([]byte{tag}, msgLen)
	}

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, writers*messages*msgLen)
		n, _ := io.ReadFull(server, buf)
		received <- buf[:n]
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(tag byte) {
			defer wg.Done()
			msg := want[tag]
			for i := 0; i < messages; i++ {
				if _, err := client.Write(msg); err != nil {
					t.Errorf("writer %c: %v", tag, err)
					return
				}
			}
		}(byte('A' + w))
	}
	wg.Wait()

	stream := <-received
	if len(stream) != writers*messages*msgLen {
		t.Fatalf("the reader got %d bytes, want %d", len(stream), writers*messages*msgLen)
	}

	// A mutex held for a whole Write keeps each message contiguous, so the
	// stream is a sequence of whole messages. A shared buffer would show up
	// here as a chunk carrying two tags.
	counts := make(map[byte]int)
	for off := 0; off < len(stream); off += msgLen {
		chunk := stream[off : off+msgLen]
		tag := chunk[0]
		expected, ok := want[tag]
		if !ok {
			t.Fatalf("message at offset %d starts with %q, which no writer sent", off, tag)
		}
		if !bytes.Equal(chunk, expected) {
			t.Fatalf("the message at offset %d is not one writer's: it mixes %q with other tags", off, tag)
		}
		counts[tag]++
	}
	for tag, n := range counts {
		if n != messages {
			t.Fatalf("writer %c has %d messages in the stream, want %d", tag, n, messages)
		}
	}
}

// A reader and a writer on one connection is the ordinary case - every relayed
// connection has both - and it used to share the nonce and mask scratch
// between them.
func TestReadingAndWritingAtOnceIsSafe(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client, server := obfsPair(t, Config{PSK: psk, MaxPadding: 64, MTU: 700})

	const rounds = 300
	payload := bytes.Repeat([]byte("duplex "), 200)

	go func() {
		buf := make([]byte, len(payload))
		for i := 0; i < rounds; i++ {
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			if _, err := server.Write(buf); err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(payload))
		for i := 0; i < rounds; i++ {
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Errorf("client read %d: %v", i, err)
				return
			}
			if !bytes.Equal(buf, payload) {
				t.Errorf("round %d came back changed", i)
				return
			}
		}
	}()

	for i := 0; i < rounds; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("client write %d: %v", i, err)
		}
	}
	wg.Wait()
}
