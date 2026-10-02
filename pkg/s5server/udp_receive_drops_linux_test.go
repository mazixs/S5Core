package s5server

import (
	"context"
	"net"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/sys/unix"
)

// The count comes from the kernel, not from traffic, so it is one series
// without labels, and a datagram dropped on a full buffer shows in it.
func TestTheReceiveDropsAreOneSeriesWithoutLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	if _, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))); err != nil {
		t.Fatal(err)
	}
	before := receiveDrops(t, reader)
	overflowASocket(t)
	if after := receiveDrops(t, reader); after <= before {
		t.Fatalf("an overflow left the count at %d", after)
	}
}

func receiveDrops(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_udp_receive_buffer_drops_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic || len(sum.DataPoints) != 1 {
				t.Fatalf("want one monotonic series, got %#v", m.Data)
			}
			if n := sum.DataPoints[0].Attributes.Len(); n != 0 {
				t.Fatalf("the series has %d labels", n)
			}
			return sum.DataPoints[0].Value
		}
	}
	t.Fatal("s5core_udp_receive_buffer_drops_total is not exported")
	return 0
}

func overflowASocket(t *testing.T) {
	t.Helper()
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rx.Close() }()
	raw, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) { _ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1) })
	tx, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Close() }()
	for range 200 {
		if _, err := tx.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
}
