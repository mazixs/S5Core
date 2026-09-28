package s5server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func associationEnds(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	ends := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_udp_associations_ended_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: %T", m.Name, m.Data)
			}
			for _, p := range sum.DataPoints {
				kind, _ := p.Attributes.Value("kind")
				reason, _ := p.Attributes.Value("reason")
				if p.Attributes.Len() != 2 {
					t.Fatalf("%s: labels %v", m.Name, p.Attributes.ToSlice())
				}
				ends[kind.AsString()+"/"+reason.AsString()] += p.Value
			}
		}
	}
	return ends
}

// Every UDP association is counted once as it ends, by its kind and by what
// ended it, and every pair of the closed sets is a series from the start.
func TestTheEndOfAUDPAssociationIsCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	port := reservePort(t)
	startServer(t, Config{Port: port, ListenIP: "127.0.0.1", RequireAuth: false,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, Telemetry: telemetry})

	ends := associationEnds(t, reader)
	if want := len(socks5.AssociationKinds()) * len(socks5.AssociationEnds()); len(ends) != want {
		t.Fatalf("%d series before any association, want %d: %v", len(ends), want, ends)
	}
	for series, n := range ends {
		if n != 0 {
			t.Fatalf("%s is %d before any association", series, n)
		}
	}

	for _, command := range []byte{socks5.AssociateCommand, socks5.UDPTunnelCommand} {
		c, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		if code := socksOver(t, c, command, []byte{0x01, 0, 0, 0, 0, 0, 0}); code != 0 {
			t.Fatalf("command 0x%02x refused: %d", command, code)
		}
		_ = c.Close()
	}
	want := map[string]int64{"associate/client": 1, "tunnel/client": 1}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ends = associationEnds(t, reader)
		if ends["associate/client"] == 1 && ends["tunnel/client"] == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for series, n := range ends {
		if n != want[series] {
			t.Errorf("%s = %d, want %d", series, n, want[series])
		}
	}
}
