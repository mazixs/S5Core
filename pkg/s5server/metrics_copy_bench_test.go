package s5server

import (
	"io"
	"net"
	"testing"
)

// plainConn hides ReadFrom and WriteTo, so that io.CopyBuffer falls back to
// the plain Read/Write loop. It is the comparison this benchmark exists for:
// metricsConn implements both, and the question is whether implementing them
// buys anything over what the relay's own loop already does.
type plainConn struct{ net.Conn }

// sink is a writer with no ReadFrom, so the destination never decides how the
// copy is done. io.Discard has a ReadFrom with an 8 KiB buffer of its own,
// which is enough to make the two cases below differ for a reason that has
// nothing to do with what is being measured.
type sink struct{ n int64 }

func (s *sink) Write(b []byte) (int, error) {
	s.n += int64(len(b))
	return len(b), nil
}

// copyThrough moves n bytes through conn and back, the way a relay half does.
func copyThrough(b *testing.B, wrap func(net.Conn) net.Conn, payload []byte) {
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		client, server := net.Pipe()
		buf := make([]byte, 32*1024)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.CopyBuffer(&sink{}, wrap(server), buf)
		}()
		b.StartTimer()
		if _, err := client.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		_ = client.Close()
		<-done
		b.StopTimer()
		_ = server.Close()
		b.StartTimer()
	}
}

func BenchmarkMeteredCopy(b *testing.B) {
	payload := make([]byte, 256*1024)

	b.Run("with ReadFrom and WriteTo", func(b *testing.B) {
		copyThrough(b, func(c net.Conn) net.Conn {
			return &metricsConn{Conn: c, transportName: TransportPlain}
		}, payload)
	})

	b.Run("without them", func(b *testing.B) {
		copyThrough(b, func(c net.Conn) net.Conn {
			return plainConn{&metricsConn{Conn: c, transportName: TransportPlain}}
		}, payload)
	})
}
