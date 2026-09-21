package obfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// countingConn records everything written to it and counts the write calls,
// which is how the tests below see both the frames on the wire and the number
// of syscalls that carried them.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.buf.Write(p)
	return len(p), nil
}

func (c *countingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *countingConn) Close() error                     { return nil }
func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) LocalAddr() net.Addr              { return benchAddr{} }
func (c *countingConn) RemoteAddr() net.Addr             { return benchAddr{} }

func (c *countingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// frameSizes walks the wire bytes and returns the size of every frame, its
// two-byte header included. The length is masked on the wire, so the walk
// needs the sender's mask key and frame counter - which is the point of the
// masking, and the reason this helper takes the connection.
//
// It fails the test if the stream does not end on a frame boundary, which
// would mean the writer left a partial frame behind.
func frameSizes(t *testing.T, wire []byte, c net.Conn) []int {
	t.Helper()
	oc := c.(*conn)

	// The opening is the prologue as this connection encodes it, which is
	// longer than the prologue itself when the encoding is printable.
	opening := len(oc.wirePrologue)
	if len(wire) < opening {
		t.Fatalf("stream is %d bytes, shorter than its %d-byte opening", len(wire), opening)
	}
	var sizes []int
	var counter uint64
	for off := opening; off < len(wire); counter++ {
		if off+2 > len(wire) {
			t.Fatalf("stream ends mid-header at offset %d of %d", off, len(wire))
		}
		masked := binary.BigEndian.Uint16(wire[off : off+2])
		body := int(masked ^ oc.sendMask(counter))
		if off+2+body > len(wire) {
			t.Fatalf("frame %d at offset %d claims %d bytes, only %d left", counter, off, body, len(wire)-off-2)
		}
		sizes = append(sizes, 2+body)
		off += 2 + body
	}
	return sizes
}

// TestOneMegabyteWriteStaysWithinTheMTU is the Ф4-2 gate. A frame used to be
// as large as the caller's write, so the 32 KiB buffer of the relay's
// io.CopyBuffer produced 32 KiB frames: a length no network path emits, and a
// length distribution that follows the relay's buffer rather than the traffic.
func TestOneMegabyteWriteStaysWithinTheMTU(t *testing.T) {
	for _, mtu := range []int{MinMTU, 576, DefaultMTU, 9000} {
		t.Run(fmt.Sprintf("MTU%d", mtu), func(t *testing.T) {
			raw := &countingConn{}
			c, err := NewClientConn(raw, Config{PSK: []byte(benchPSK), MaxPadding: 256, MTU: mtu})
			if err != nil {
				t.Fatal(err)
			}

			payload := benchPayload(1 << 20)
			n, err := c.Write(payload)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(payload) {
				t.Fatalf("Write reported %d bytes of %d", n, len(payload))
			}

			sizes := frameSizes(t, raw.bytes(), c)
			if len(sizes) == 0 {
				t.Fatal("no frames on the wire")
			}
			largest := 0
			for _, s := range sizes {
				if s > largest {
					largest = s
				}
			}
			if largest > mtu {
				t.Errorf("largest frame is %d bytes, MTU is %d", largest, mtu)
			}
			t.Logf("MTU %d: %d frames, largest %d bytes, %d write calls",
				mtu, len(sizes), largest, raw.writes)
		})
	}
}

// TestSegmentingDoesNotMultiplyTheSyscalls guards the other half of the same
// change: cutting a 32 KiB write into ~24 frames must not turn one write call
// into 24. Frames are batched, so the count follows the batch size.
func TestSegmentingDoesNotMultiplyTheSyscalls(t *testing.T) {
	raw := &countingConn{}
	c, err := NewClientConn(raw, Config{PSK: []byte(benchPSK), MaxPadding: 256, MTU: DefaultMTU})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Write(benchPayload(32 * 1024)); err != nil {
		t.Fatal(err)
	}

	frames := len(frameSizes(t, raw.bytes(), c))
	// One call per full batch, plus the partial one at the end.
	want := frames/framesPerBatch + 1
	if raw.writes > want {
		t.Errorf("a 32 KiB write took %d write calls for %d frames, want at most %d",
			raw.writes, frames, want)
	}
	t.Logf("32 KiB: %d frames in %d write calls", frames, raw.writes)
}

// TestSegmentedWritesSurviveTheRoundTrip checks the obvious thing the gate
// above does not: the peer still gets exactly the bytes that were written,
// in order, across frame boundaries the caller never asked for.
func TestSegmentedWritesSurviveTheRoundTrip(t *testing.T) {
	client, server := allocPair(t)

	payload := benchPayload(1 << 20)
	got := make([]byte, len(payload))

	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, got)
		readErr <- err
	}()

	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := <-readErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("the bytes that came back are not the bytes that went in")
	}
}

// TestBuffersAreSizedByTheMTU records what a connection costs in memory. The
// write buffer used to be built for a 65535-byte payload - 65.8 KiB per
// connection - whatever the MTU said.
func TestBuffersAreSizedByTheMTU(t *testing.T) {
	raw := &countingConn{}
	nc, err := NewClientConn(raw, Config{PSK: []byte(benchPSK), MaxPadding: 256, MTU: DefaultMTU})
	if err != nil {
		t.Fatal(err)
	}
	c := nc.(*conn)

	// The write buffer used to be built for a 65535-byte payload whatever
	// the MTU said, and the read buffer was 2*MTU. The gate is half of that,
	// which is what the batch sizes were chosen to fit; the rest of the
	// saving went into keeping the throughput, since a batch that goes to the
	// kernel in one piece is what a segmented write costs the least.
	const wasWrite = 4 + 12 + (2 + 65535 + 2 + 256 + 16)
	const wasRead = 2 * DefaultMTU
	budget := (wasWrite + wasRead) / 2

	total := len(c.writeBuf) + len(c.readBuf)
	if total > budget {
		t.Errorf("a connection holds %d bytes of frame buffers, budget is %d (it used to hold %d)",
			total, budget, wasWrite+wasRead)
	}
	t.Logf("write buffer %d bytes, read buffer %d bytes", len(c.writeBuf), len(c.readBuf))
}
