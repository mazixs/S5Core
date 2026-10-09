package s5server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/internal/netnstest"
	"github.com/mazixs/S5Core/internal/tcptune"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/sys/unix"
)

// The obfs listener accepts data in a SYN only with ObfsTFO, and a sysctl
// that would make the option do nothing is said at startup.
func TestTheObfsListenerTakesFastOpenOnlyWhenAsked(t *testing.T) {
	mode, _ := tcptune.FastOpenMode()
	for _, tc := range []struct {
		name string
		on   bool
		want int
	}{
		{"on", true, 256},
		{"off", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs lockedBuffer
			cfg := DefaultConfig()
			cfg.ObfsTFO = tc.on
			cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			srv, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			l, err := srv.listenObfs("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			raw, err := l.(*net.TCPListener).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var gerr error
			_ = raw.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN) })
			if gerr != nil {
				t.Fatal(gerr)
			}
			if got != tc.want {
				t.Fatalf("TCP_FASTOPEN = %d, want %d", got, tc.want)
			}
			warned := strings.Contains(logs.String(), "OBFS_TFO is on")
			if want := tc.on && mode&tcptune.FastOpenServer == 0; warned != want {
				t.Fatalf("tcp_fastopen=%d: warned %v, want %v:\n%s", mode, warned, want, logs.String())
			}
		})
	}
}

// The count comes from the kernel, so it is one series without labels, and a
// connection with data in its SYN moves it.
func TestTheFastOpenCountIsOneSeriesWithoutLabels(t *testing.T) {
	if !netnstest.FastOpen(t) {
		return
	}
	reader := sdkmetric.NewManualReader()
	if _, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))); err != nil {
		t.Fatal(err)
	}
	before := fastOpenPassive(t, reader)
	l, err := (&net.ListenConfig{Control: tcptune.ListenFastOpen(nil)}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d := net.Dialer{Control: tcptune.DialFastOpen(nil)}
	for range 2 {
		c, err := d.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		_ = s.Close()
	}
	if after := fastOpenPassive(t, reader); after <= before {
		t.Fatalf("a connection with data in its SYN left the count at %d", after)
	}
}

func fastOpenPassive(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_tcp_fastopen_passive_total" {
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
	t.Fatal("s5core_tcp_fastopen_passive_total is not exported")
	return 0
}
