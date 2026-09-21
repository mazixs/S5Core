package s5server

import (
	"bytes"
	"context"
	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"io"
	"net"
	"testing"
	"time"
)

type observerMemoryConn struct{ bytes.Buffer }

func (c *observerMemoryConn) Close() error                     { return nil }
func (c *observerMemoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *observerMemoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *observerMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *observerMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *observerMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkFrameObserver(b *testing.B) {
	for _, mode := range []string{"bare", "state-only", "noop-telemetry", "sdk-telemetry"} {
		b.Run(mode, func(b *testing.B) {
			var tel *Telemetry
			var err error
			if mode == "noop-telemetry" {
				tel, err = InitTelemetry(noop.NewMeterProvider())
			}
			if mode == "sdk-telemetry" {
				provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
				b.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
				tel, err = InitTelemetry(provider)
			}
			if err != nil {
				b.Fatal(err)
			}
			raw := &observerMemoryConn{}
			raw.Grow(128 << 10)
			cfg := obfs.Config{PSK: []byte("01234567890123456789012345678901"), MaxPadding: 256, MTU: 1400}
			client, err := obfs.NewClientConn(raw, cfg)
			if err != nil {
				b.Fatal(err)
			}
			if mode != "bare" {
				cfg.OnFrameState = frameHook(session.NewRegistry(sessionTransitionObserver(tel)).Open("obfs", true, session.SLA{}))
			}
			server, err := obfs.NewServerConn(raw, cfg)
			if err != nil {
				b.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0x57}, 32768)
			out := make([]byte, len(payload))
			if _, err = client.Write(payload); err != nil {
				b.Fatal(err)
			}
			if _, err = io.ReadFull(server, out); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				if _, err = client.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err = io.ReadFull(server, out); err != nil {
					b.Fatal(err)
				}
			}
			if !bytes.Equal(out, payload) {
				b.Fatal("payload mismatch")
			}
		})
	}
}

func TestFrameTransitionObserverDoesNotAllocate(t *testing.T) {
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	defer provider.Shutdown(context.Background())
	tel, err := InitTelemetry(provider)
	if err != nil {
		t.Fatal(err)
	}
	observe := sessionTransitionObserver(tel)
	tr := session.Transition{Transport: "obfs", Region: session.RegionFrames, From: 1, To: 2}
	if n := testing.AllocsPerRun(1000, func() { observe(tr) }); n != 0 {
		t.Fatalf("allocations per transition: %v", n)
	}
}
