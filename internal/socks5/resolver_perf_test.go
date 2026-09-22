package socks5

import (
	"context"
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

func TestPerformanceDNS(t *testing.T) {
	name := os.Getenv("S5_PERF_DNS_NAME")
	if name == "" {
		t.Skip("set S5_PERF_DNS_NAME to the controlled origin's DNS name")
	}
	var samples []time.Duration
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		_, ips, e := (DNSResolver{}).ResolveAll(ctx, name)
		elapsed := time.Since(start)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if len(ips) == 0 || ips[0].Equal(net.IP{}) {
			t.Fatal("no addresses")
		}
		samples = append(samples, elapsed)
	}
	cold := samples[0]
	slices.Sort(samples)
	t.Logf("first=%s p50=%s p95=%s p99=%s n=%d; LookupIP exposes no TTL", cold, samples[49], samples[94], samples[98], len(samples))
}
