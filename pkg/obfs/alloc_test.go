package obfs

import (
	"io"
	"net"
	"testing"
)

// TestHotPathIsAllocationFree is the CI gate that makes the CLAUDE.md rule
// "check buffer changes with benchmarks" enforceable instead of advisory.
//
// It is deliberately written against allocations and not against nanoseconds:
// allocation counts are identical on a laptop and on a CI runner, so the gate
// catches a real regression without failing because the runner was busy.
func TestHotPathIsAllocationFree(t *testing.T) {
	client, server := allocPair(t)
	payload := make([]byte, DefaultMTU-100)
	sink := make([]byte, len(payload))

	writes := testing.AllocsPerRun(200, func() {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(server, sink); err != nil {
			t.Fatal(err)
		}
	})

	if writes > 0 {
		t.Errorf("write+read of a %d-byte payload allocates %.1f times per operation, want 0",
			len(payload), writes)
	}
}

// TestARelaySizedWriteIsAllocationFree is the same gate as above, applied to
// the size the relay actually hands over: io.CopyBuffer passes 32 KiB, which
// is far more than the MTU.
//
// This used to be a test that recorded a known cost. A 32 KiB write became a
// 32 KiB frame, which did not fit the 2*MTU read buffer, so the reader
// allocated a fresh buffer for every frame. Segmenting by MTU (plan task
// Ф4-2) removed the oversized frame, and with it the allocation.
func TestARelaySizedWriteIsAllocationFree(t *testing.T) {
	client, server := allocPair(t)
	payload := make([]byte, 32*1024)
	sink := make([]byte, len(payload))

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(server, sink); err != nil {
			t.Fatal(err)
		}
	})

	if allocs > 0 {
		t.Errorf("write+read of a %d-byte payload allocates %.1f times per operation, want 0",
			len(payload), allocs)
	}
}

// TestSmallReadsDoNotAllocate covers the UDP multiplexer's access pattern: it
// reads a 2-byte length and then the datagram, so every frame is consumed in
// several short Reads. The leftover buffer used to lose its capacity as it
// drained, which turned each of those into an allocation.
func TestSmallReadsDoNotAllocate(t *testing.T) {
	client, server := allocPair(t)
	payload := make([]byte, 1024)
	small := make([]byte, 16)

	allocs := testing.AllocsPerRun(50, func() {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		for got := 0; got < len(payload); {
			n, err := io.ReadFull(server, small)
			if err != nil {
				t.Fatal(err)
			}
			got += n
		}
	})
	if allocs > 0 {
		t.Errorf("64 short reads of a 1 KiB payload allocate %.1f times, want 0", allocs)
	}
}

func allocPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptCh <- accepted{c, err}
	}()

	rawClient, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	got := <-acceptCh
	if got.err != nil {
		t.Fatal(got.err)
	}

	cfg := Config{PSK: []byte(benchPSK), MaxPadding: 256, MTU: DefaultMTU}
	client, err = NewClientConn(rawClient, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewServerConn(got.conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// TestFramingOverheadRatio is the second half of the gate: it bounds what
// obfuscation costs on top of the cipher itself.
//
// It compares two numbers measured in the same process on the same machine,
// so it stays meaningful on a busy CI runner where absolute nanoseconds do
// not. A regression that doubles the framing cost - an extra copy, a lost
// buffer reuse - shows up here; a slow runner does not.
func TestFramingOverheadRatio(t *testing.T) {
	if testing.Short() {
		t.Skip("timing ratio; skipped under -short")
	}

	const budget = 4.0
	payload := make([]byte, 1400)

	cipherOnly := testing.Benchmark(func(b *testing.B) {
		c, err := NewClientConn(discardConn{}, Config{
			PSK: []byte(benchPSK), MaxPadding: 0, MTU: DefaultMTU,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for range b.N {
			if _, err := c.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
	})

	withPadding := testing.Benchmark(func(b *testing.B) {
		c, err := NewClientConn(discardConn{}, Config{
			PSK: []byte(benchPSK), MaxPadding: 256, MTU: DefaultMTU,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for range b.N {
			if _, err := c.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
	})

	if cipherOnly.NsPerOp() == 0 {
		t.Skip("benchmark produced no timing")
	}

	ratio := float64(withPadding.NsPerOp()) / float64(cipherOnly.NsPerOp())
	t.Logf("framing without padding %d ns/op, with 256 bytes of padding %d ns/op, ratio %.2f",
		cipherOnly.NsPerOp(), withPadding.NsPerOp(), ratio)

	if ratio > budget {
		t.Errorf("padding now costs %.2fx the unpadded frame, budget is %.1fx: "+
			"something on the write path stopped reusing its buffers", ratio, budget)
	}
}
