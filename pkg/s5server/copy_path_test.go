package s5server

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// The relay copies with io.CopyBuffer wherever it keeps no counter of its
// own, and io.CopyBuffer hands the work to the destination's ReadFrom or the
// source's WriteTo whenever one exists - the buffer it was given is then not
// used at all. metricsConn has both, and they are worth about 9% on that path
// (BenchmarkMeteredCopy), because they copy through a pooled 32 KiB buffer
// instead of one allocated per copy.
//
// The audit read this as a plain-mode-only optimisation, on the grounds that
// obfs.Conn has no ReadFrom or WriteTo to pass it down to. It does not, and it
// cannot: a frame is not a byte range, so there is nothing to splice. But the
// optimisation never needed it, because metricsConn is the outermost wrapper
// on every transport - Accept applies countAccepted last, after the shaper,
// the limiter, the deadlines and the obfuscation. This test pins that order
// down: it is what makes the audit's claim false, and it is exactly what a
// future wrapper added above metricsConn would break silently (plan task
// Ф6-5).
func TestAcceptedConnectionsKeepTheCopyFastPath(t *testing.T) {
	obfsCfg := obfs.Config{PSK: []byte(testPSK), MaxPadding: 256, MTU: 1400}

	cases := []struct {
		name  string
		build func(net.Listener) *listenerPipeline
	}{
		{
			name: TransportPlain,
			build: func(l net.Listener) *listenerPipeline {
				return newListenerPipeline(l, TransportPlain, Config{}, nil, nil, session.NewRegistry(nil))
			},
		},
		{
			name: TransportObfs,
			build: func(l net.Listener) *listenerPipeline {
				return newListenerPipeline(l, TransportObfs, Config{}, nil, nil, session.NewRegistry(nil)).
					withObfs(obfsCfg)
			},
		},
		{
			// The WebSocket listener differs from the obfuscated one by the
			// shaper, which only wraps a *ws.Conn and passes anything else
			// through. A TCP socket here therefore exercises the same stages
			// in the same order; what is under test is the order, not the
			// WebSocket framing, which ws_integration_test.go covers.
			name: TransportWS,
			build: func(l net.Listener) *listenerPipeline {
				return newListenerPipeline(l, TransportWS, Config{}, nil, nil, session.NewRegistry(nil)).
					withShaper(256, 1200, 0).
					withObfs(obfsCfg)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			pipeline := tc.build(ln)

			dialed := make(chan net.Conn, 1)
			go func() {
				if tc.name == TransportPlain {
					c, derr := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
					if derr != nil {
						dialed <- nil
						return
					}
					dialed <- c
					return
				}
				c, derr := dialObfs(t, ln.Addr().String())
				if derr != nil {
					dialed <- nil
					return
				}
				// The server side of the obfuscated handshake reads the
				// prologue, which only arrives with the first frame.
				_, _ = c.Write([]byte("hello"))
				dialed <- c
			}()

			conn, err := pipeline.Accept()
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if client := <-dialed; client != nil {
				defer func() { _ = client.Close() }()
			}

			if _, ok := conn.(io.WriterTo); !ok {
				t.Errorf("a %s connection has no WriteTo: io.CopyBuffer will allocate its own buffer", tc.name)
			}
			if _, ok := conn.(io.ReaderFrom); !ok {
				t.Errorf("a %s connection has no ReadFrom: io.CopyBuffer will allocate its own buffer", tc.name)
			}
			if _, ok := conn.(closeWriter); !ok {
				t.Errorf("a %s connection cannot half-close", tc.name)
			}
			if _, ok := conn.(*metricsConn); !ok {
				t.Errorf("the outermost wrapper of a %s connection is %T, want *metricsConn", tc.name, conn)
			}
		})
	}
}

// countingConn counts what actually reaches the socket, so that the test can
// tell a copy that went through metricsConn from one that went around it.
type countingConn struct {
	net.Conn
	read    atomic.Int64
	written atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, err
}

// The fast path must not be a way around the meter. Bytes copied through
// WriteTo and ReadFrom are counted exactly like bytes copied through Read and
// Write - otherwise a deployment's traffic numbers would depend on which copy
// path io.CopyBuffer happened to pick, which is not a thing an operator can
// see or control.
func TestTheCopyFastPathStillCountsBytes(t *testing.T) {
	payload := make([]byte, 96*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	t.Run("WriteTo", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
		if err != nil {
			t.Fatalf("InitTelemetry: %v", err)
		}
		client, server := net.Pipe()
		counted := &countingConn{Conn: server}
		mc := &metricsConn{Conn: counted, telemetry: telemetry, transportName: TransportPlain}

		go func() {
			_, _ = client.Write(payload)
			_ = client.Close()
		}()
		var into sink
		n, err := mc.WriteTo(&into)
		if err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		if n != int64(len(payload)) {
			t.Fatalf("WriteTo moved %d bytes, want %d", n, len(payload))
		}
		if got := counted.read.Load(); got != int64(len(payload)) {
			t.Fatalf("the socket saw %d bytes read, want %d", got, len(payload))
		}
		if got := counterValue(t, reader, "s5core_traffic_bytes_in"); got != int64(len(payload)) {
			t.Fatalf("the meter counted %d bytes in, want %d", got, len(payload))
		}
	})

	t.Run("ReadFrom", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
		if err != nil {
			t.Fatalf("InitTelemetry: %v", err)
		}
		client, server := net.Pipe()
		counted := &countingConn{Conn: server}
		mc := &metricsConn{Conn: counted, telemetry: telemetry, transportName: TransportPlain}

		drained := make(chan int64, 1)
		go func() {
			var out sink
			n, _ := io.Copy(&out, client)
			drained <- n
		}()
		n, err := mc.ReadFrom(&sourceOnly{data: payload})
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if n != int64(len(payload)) {
			t.Fatalf("ReadFrom moved %d bytes, want %d", n, len(payload))
		}
		_ = server.Close()
		if got := <-drained; got != int64(len(payload)) {
			t.Fatalf("the peer received %d bytes, want %d", got, len(payload))
		}
		if got := counted.written.Load(); got != int64(len(payload)) {
			t.Fatalf("the socket saw %d bytes written, want %d", got, len(payload))
		}
		if got := counterValue(t, reader, "s5core_traffic_bytes_out"); got != int64(len(payload)) {
			t.Fatalf("the meter counted %d bytes out, want %d", got, len(payload))
		}
	})
}

// sourceOnly is a reader with no WriteTo, so ReadFrom has to do the copying
// itself rather than handing it back.
type sourceOnly struct {
	data []byte
	pos  int
}

func (s *sourceOnly) Read(b []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(b, s.data[s.pos:])
	s.pos += n
	return n, nil
}

// counterValue sums one Int64 counter across its data points.
func counterValue(t *testing.T, reader sdkmetric.Reader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}
