package s5server

import (
	"context"
	"testing"

	"github.com/mazixs/S5Core/internal/socks5"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestUDPDropMetricsCountOnlyFixedReasons(t *testing.T) {
	if udpDropHook(nil) != nil {
		t.Fatal("disabled telemetry installed a drop hook")
	}
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	drop := udpDropHook(tel)
	drop(socks5.UDPDropDNSPending)
	drop(socks5.UDPDropDNSPending)
	drop(socks5.UDPDropFrameOversize)
	drop("unexpected target address")
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_udp_drops_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic || len(sum.DataPoints) != len(socks5.UDPDropReasons()) {
				t.Fatalf("drop metric: %T %+v", m.Data, m.Data)
			}
			for _, p := range sum.DataPoints {
				reason, ok := p.Attributes.Value("reason")
				want := map[string]int64{socks5.UDPDropDNSPending: 2, socks5.UDPDropFrameOversize: 1}
				known := false
				for _, r := range socks5.UDPDropReasons() {
					known = known || r == reason.AsString()
				}
				if !ok || !known || p.Attributes.Len() != 1 || want[reason.AsString()] != p.Value {
					t.Fatalf("drop labels or count: %+v", p)
				}
			}
			return
		}
	}
	t.Fatal("UDP drops were not exported")
}
