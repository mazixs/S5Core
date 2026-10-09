package s5server

import (
	"context"
	"github.com/mazixs/S5Core/internal/socks5"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func udpDropHook(t *Telemetry) func(string) {
	if t == nil {
		return nil
	}
	options := make(map[string]metric.AddOption)
	for _, reason := range socks5.UDPDropReasons() {
		options[reason] = metric.WithAttributes(attribute.String("reason", reason))
		t.UDPDrops.Add(context.Background(), 0, options[reason])
	}
	return func(reason string) {
		if option, ok := options[reason]; ok {
			t.UDPDrops.Add(context.Background(), 1, option)
		}
	}
}
