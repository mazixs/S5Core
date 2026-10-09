package s5server

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func registerUDPRelayMetrics(t *Telemetry, c *socks5.UDPRelayCounters) (metric.Registration, error) {
	if t == nil {
		return nil, nil
	}
	stages := []struct {
		name  string
		count *atomic.Uint64
	}{
		{"client_in", &c.ClientIn}, {"target_out", &c.TargetOut},
		{"target_in", &c.TargetIn}, {"client_out", &c.ClientOut},
	}
	return t.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for _, stage := range stages {
			o.ObserveInt64(t.UDPRelayDatagrams, int64(stage.count.Load()), metric.WithAttributes(attribute.String("stage", stage.name)))
		}
		return nil
	}, t.UDPRelayDatagrams)
}

func udpReportHook(logger *slog.Logger, interval time.Duration) func(net.Conn, socks5.UDPRelaySnapshot, socks5.UDPRelaySnapshot) {
	if interval == 0 {
		return nil
	}
	return func(conn net.Conn, now, delta socks5.UDPRelaySnapshot) {
		logger.Debug("UDP relay running", "conn", obfs.LogIDOf(conn), "period", interval.String(),
			"client_in", now.ClientIn, "target_out", now.TargetOut, "target_in", now.TargetIn,
			"client_out", now.ClientOut, "udp_drops", now.Drops, "target_write_errors", now.TargetWriteErrors,
			"client_in_period", delta.ClientIn, "target_out_period", delta.TargetOut,
			"target_in_period", delta.TargetIn, "client_out_period", delta.ClientOut,
			"udp_drops_period", delta.Drops, "target_write_errors_period", delta.TargetWriteErrors)
	}
}
