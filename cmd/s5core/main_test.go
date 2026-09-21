package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const envTestPSK = "01234567890123456789012345678901" // 32 bytes

// startEcho starts a TCP echo server for the destination side of the tunnel.
func startEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return l.Addr().String()
}

// TestServerFromEnv_WSSEndToEnd is the acceptance check for plan task Ф1-4:
// the binary must be configurable for the stealth transport through the
// environment alone, and the metrics must say which transports are live.
func TestServerFromEnv_WSSEndToEnd(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	echoAddr := startEcho(t)

	t.Setenv("PROXY_PORT", "19083")
	t.Setenv("PROXY_LISTEN_IP", "127.0.0.1")
	t.Setenv("REQUIRE_AUTH", "false")
	t.Setenv("OBFS_ENABLED", "true")
	t.Setenv("OBFS_PORT", "19444")
	t.Setenv("OBFS_PSK", envTestPSK)
	t.Setenv("OBFS_MAX_PADDING", "32")
	t.Setenv("WS_ENABLED", "true")
	t.Setenv("WS_ADDR", "127.0.0.1:0")
	t.Setenv("WS_CERT_FILE", certFile)
	t.Setenv("WS_KEY_FILE", keyFile)

	var cfg params
	if err := env.Parse(&cfg); err != nil {
		t.Fatalf("env.Parse: %v", err)
	}
	if !cfg.WSEnabled {
		t.Fatal("WS_ENABLED is not read by the binary")
	}

	reader := sdkmetric.NewManualReader()
	telemetry, err := s5server.InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	srv, err := setupServer(cfg, telemetry, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("setupServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.Stop()
	})
	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("server error: %v", err)
		}
	}()

	wsAddr := waitWSAddr(t, srv)

	// Полный стелс-стек: TLS -> WebSocket -> obfs -> SOCKS5.
	wsConn, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + wsAddr + cfg.WSPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // самоподписанный сертификат теста
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = wsConn.Close() }()

	shaped := ws.NewShapedConn(wsConn, cfg.WSMinFrame, cfg.WSMaxFrame, time.Duration(cfg.WSMaxJitterMs)*time.Millisecond)
	tunnel, err := obfs.NewClientConn(shaped, obfs.Config{
		PSK:        []byte(cfg.ObfsPSK),
		MaxPadding: cfg.ObfsMaxPadding,
		MTU:        cfg.ObfsMTU,
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	if err := socks5ConnectNoAuth(tunnel, echoAddr); err != nil {
		t.Fatalf("socks5 through wss: %v", err)
	}

	msg := []byte("hello from the environment")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(tunnel, back); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(back) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", back, msg)
	}

	assertTransportsVisible(t, reader)
}

// assertTransportsVisible checks the other half of the task: from the metrics
// alone, an operator can tell which transports the process runs and which one
// the traffic came in on.
func assertTransportsVisible(t *testing.T, reader sdkmetric.Reader) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	buildLabels := map[string]string{}
	connByTransport := map[string]int64{}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				switch m.Name {
				case "s5core_build_info":
					iter := dp.Attributes.Iter()
					for iter.Next() {
						kv := iter.Attribute()
						buildLabels[string(kv.Key)] = kv.Value.Emit()
					}
				case "s5core_connections_total":
					if v, ok := dp.Attributes.Value("transport"); ok {
						connByTransport[v.Emit()] += dp.Value
					}
				}
			}
		}
	}

	if got := buildLabels["transports"]; got != "plain,obfs,ws" {
		t.Errorf("build_info transports = %q, want %q", got, "plain,obfs,ws")
	}
	if buildLabels["version"] == "" || buildLabels["version"] == "unknown" {
		t.Errorf("build_info version = %q, want a usable build identity", buildLabels["version"])
	}
	if buildLabels["go_version"] == "" {
		t.Error("build_info is missing go_version")
	}
	if connByTransport["ws"] < 1 {
		t.Errorf("no connection counted on the ws transport: %v", connByTransport)
	}
}

func waitWSAddr(t *testing.T, srv *s5server.Server) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := srv.WSAddr(); addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("WS listener not ready after 3s")
	return ""
}

// socks5ConnectNoAuth performs greeting and CONNECT over an already
// established tunnel.
func socks5ConnectNoAuth(conn net.Conn, targetAddr string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return errors.New("server refused the no-auth method")
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return errors.New("test target must be IPv4")
	}

	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return errors.New("CONNECT rejected with code " + string(rune('0'+reply[1])))
	}
	return nil
}
