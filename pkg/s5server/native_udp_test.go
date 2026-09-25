package s5server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestNativeUDPAndTCPFallbackShareAnAssociation(t *testing.T) {
	plainPort, obfsPort := reservePort(t), reservePort(t)
	srv := startServer(t, Config{
		Port: plainPort, ListenIP: "127.0.0.1", RequireAuth: false,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: obfsPort, ObfsPSK: testPSK,
		ObfsMaxPadding: 32, ObfsMTU: 1400, UDPPort: "0",
	})
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var b [2048]byte
		for {
			n, peer, err := echo.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(b[:n], peer)
		}
	}()

	stream, err := dialObfs(t, "127.0.0.1:"+obfsPort)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if code := socksOver(t, stream, socks5.UDPNativeCommand, []byte{1, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("native reply code %d", code)
	}
	_ = stream.SetDeadline(time.Time{})
	keys, err := obfs.DatagramKeysOf(stream)
	if err != nil {
		t.Fatal(err)
	}
	client := nativeudp.NewSession(keys)
	hub := srv.nativeHub.Load()
	if hub == nil {
		t.Fatal("native hub missing")
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	wire, err := client.Seal(nil, nativeudp.KindProbe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	var b [2048]byte
	n, err := udp.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err := client.Open(b[:n])
	if err != nil || p.Kind != nativeudp.KindProbeAck {
		t.Fatalf("probe: %v %+v", err, p)
	}
	body := socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("game tick"))
	wire, err = client.Seal(nil, nativeudp.KindData, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	n, err = udp.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err = client.Open(b[:n])
	if err != nil || p.Kind != nativeudp.KindData || !bytes.HasSuffix(p.Data, []byte("game tick")) {
		t.Fatalf("native response: %v %+v", err, p)
	}
	// A TCP frame on the same association moves the reply back to TCP.
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(body)))
	copy(frame[2:], body)
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		t.Fatalf("TCP fallback reply: %v", err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, answer); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(answer, []byte("game tick")) {
		t.Fatalf("fallback response %x", answer)
	}
}

func TestNativeUDPMetricsHaveOnlyFixedOutcomes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	hub, err := nativeudp.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registration, err := registerNativeMetrics(tel, hub)
	if err != nil {
		t.Fatal(err)
	}
	defer registration.Unregister()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "s5core_native_udp_packets_total":
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok || len(sum.DataPoints) != 4 {
					t.Fatalf("packet metric: %T %+v", m.Data, m.Data)
				}
				for _, p := range sum.DataPoints {
					if p.Attributes.Len() != 1 || p.Value != 0 {
						t.Fatalf("packet labels or value: %+v", p)
					}
					value, ok := p.Attributes.Value("outcome")
					if !ok {
						t.Fatalf("missing outcome: %+v", p)
					}
					seen[value.AsString()] = true
				}
			case "s5core_native_udp_sessions":
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				if !ok || len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Attributes.Len() != 0 {
					t.Fatalf("sessions metric: %T %+v", m.Data, m.Data)
				}
			}
		}
	}
	for _, label := range []string{"accepted", "tag", "replay", "auth"} {
		if !seen[label] {
			t.Fatalf("outcome %q missing: %+v", label, seen)
		}
	}
}
