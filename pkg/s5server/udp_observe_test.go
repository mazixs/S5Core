package s5server

import (
	"context"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestUDPRelayMetricsExposeOnlyFourStagesIncludingZero(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	counters := new(socks5.UDPRelayCounters)
	counters.ClientIn.Add(12)
	counters.TargetOut.Add(9)
	reg, err := registerUDPRelayMetrics(tel, counters)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Unregister()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "s5core_udp_relay_datagrams_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic || len(sum.DataPoints) != 4 {
				t.Fatalf("stages: %+v", m.Data)
			}
			want := map[string]int64{"client_in": 12, "target_out": 9, "target_in": 0, "client_out": 0}
			for _, p := range sum.DataPoints {
				v, ok := p.Attributes.Value("stage")
				expected, known := want[v.AsString()]
				if !ok || !known || p.Attributes.Len() != 1 || p.Value != expected {
					t.Fatalf("unexpected stage: %+v", p)
				}
				delete(want, v.AsString())
			}
			return
		}
	}
	t.Fatal("UDP relay metric missing")
}

func TestUDPDiagnosticsIntervalIsExplicitAndBounded(t *testing.T) {
	for _, interval := range []time.Duration{-time.Second, time.Nanosecond, time.Millisecond * 999} {
		cfg := DefaultConfig()
		cfg.UDPDiagnosticsInterval = interval
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("invalid interval %s accepted", interval)
		}
	}
	for _, interval := range []time.Duration{0, time.Second, 5 * time.Second} {
		cfg := DefaultConfig()
		cfg.UDPDiagnosticsInterval = interval
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("interval %s: %v", interval, err)
		}
	}
}
