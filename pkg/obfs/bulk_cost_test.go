package obfs

import (
	"fmt"
	"testing"
)

type bulkCountConn struct {
	discardConn
	wireBytes uint64
}

func (c *bulkCountConn) Write(p []byte) (int, error) {
	c.wireBytes += uint64(len(p))
	return len(p), nil
}

func BenchmarkBulkWireCost(b *testing.B) {
	for _, size := range []int{4096, 32768, 1 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			raw := &bulkCountConn{}
			c, err := NewClientConn(raw, Config{PSK: []byte(benchPSK), MTU: DefaultMTU, MaxPadding: 256})
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := c.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(raw.wireBytes)/float64(b.N), "wire-B/op")
			b.ReportMetric(100*(float64(raw.wireBytes)/float64(b.N*size)-1), "wire-extra-%")
		})
	}
}

func TestBulkFramingPreservesPayloadWithoutPaddingInducedExtraFrames(t *testing.T) {
	raw := &countingConn{}
	c, err := NewClientConn(raw, Config{PSK: []byte(benchPSK), MTU: DefaultMTU, MaxPadding: 256})
	if err != nil {
		t.Fatal(err)
	}
	const size = 32768
	if _, err := c.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	frames := frameSizes(t, raw.bytes(), c)
	want := (size + (DefaultMTU - frameOverhead) - 1) / (DefaultMTU - frameOverhead)
	if len(frames) != want {
		t.Fatalf("padding added frames: got %d want %d", len(frames), want)
	}
	wireBytes := 0
	for _, frame := range frames {
		wireBytes += frame
	}
	if wireBytes > size*105/100 {
		t.Fatalf("bulk wire overhead too high: %d for %d", wireBytes, size)
	}
}
