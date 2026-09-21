package s5server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// startClosingTarget answers once and then closes, which is what makes the
// proxy try to half-close the client side.
func startClosingTarget(t *testing.T) string {
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
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()
	return l.Addr().String()
}

// TestHalfCloseWorksTheSameOnBothTransports is the acceptance check for plan
// task Ф4-9: a protocol that ends its request by closing its write half has to
// behave the same whether the tunnel runs over plain TCP or over WSS.
//
// It used to be the acceptance check for Ф1-5, and it asserted the opposite:
// a WebSocket has no half-close, the attempt failed, and the metric counted
// how often it bit. The signal moved into the obfuscation format as a frame
// kind, so both transports now carry it and the counter stays at zero - the
// counter itself is still checked, by TestATransportWithoutHalfCloseIsCounted.
func TestHalfCloseWorksTheSameOnBothTransports(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	targetAddr := startClosingTarget(t)

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	const obfsPort = "19445"
	srv := startServer(t, Config{
		Port:           "19084",
		ListenIP:       "127.0.0.1",
		RequireAuth:    false,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 32,
		ObfsMTU:        1400,
		WSEnabled:      true,
		WSAddr:         "127.0.0.1:0",
		WSCertFile:     certFile,
		WSKeyFile:      keyFile,
		Telemetry:      telemetry,
	})

	wsAddr := ""
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && wsAddr == "" {
		wsAddr = srv.WSAddr()
		time.Sleep(10 * time.Millisecond)
	}
	if wsAddr == "" {
		t.Fatal("WS listener not ready")
	}

	// Over plain TCP.
	plainTCP, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial obfs: %v", err)
	}
	roundTrip(t, plainTCP, targetAddr)

	// Over WSS. The same sequence, and the same ending is what the task asks
	// for: not "it does not hang" but the same end of stream, from the same
	// frame, at the same point.
	wsConn, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + wsAddr + "/ws",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // самоподписанный сертификат теста
	})
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	roundTrip(t, wsConn, targetAddr)

	failures := collectHalfCloseFailures(t, reader)
	for _, key := range []string{SideClient + "/" + TransportObfs, SideClient + "/" + TransportWS} {
		if got := failures[key]; got != 0 {
			t.Errorf("half-close on %s should succeed, got %d failures: %v", key, got, failures)
		}
	}
}

// roundTrip runs the SOCKS5 handshake over an already established tunnel,
// exchanges one message and waits for the destination to close.
func roundTrip(t *testing.T, transport net.Conn, targetAddr string) {
	t.Helper()
	t.Cleanup(func() { _ = transport.Close() })
	_ = transport.SetDeadline(time.Now().Add(5 * time.Second))

	tunnel, err := obfs.NewClientConn(transport, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 32,
		MTU:        1400,
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}

	if _, err := tunnel.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(tunnel, greeting[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := net.LookupPort("tcp", portStr)
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP(host).To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := tunnel.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(tunnel, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT rejected: %d", reply[1])
	}

	if _, err := tunnel.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	back := make([]byte, 4)
	if _, err := io.ReadFull(tunnel, back); err != nil {
		t.Fatalf("read: %v", err)
	}

	// The destination has closed, so the server half-closes our side. What
	// the caller checks is that this arrives as an end of stream rather than
	// as the read deadline below: a transport where the signal does not cross
	// leaves the client waiting for a stream that has already ended.
	_ = transport.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = tunnel.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("tunnel ended with %v, want io.EOF", err)
	}

	// And the other direction is still ours to close, which is what makes it
	// a half-close rather than a close.
	if cw, ok := tunnel.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite on the client side: %v", err)
		}
	} else {
		t.Fatal("the tunnel does not offer CloseWrite")
	}
}

// collectHalfCloseFailures reads the counter once the relays have had time to
// finish. There is nothing to wait for any more - the assertion is that the
// counter stays empty - so a short settle beats a poll loop that would return
// on the first empty read.
func collectHalfCloseFailures(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	time.Sleep(200 * time.Millisecond)

	failures := map[string]int64{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_half_close_failures_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				side, _ := dp.Attributes.Value("side")
				transport, _ := dp.Attributes.Value("transport")
				if dp.Attributes.Len() != 2 {
					t.Errorf("%s: expected exactly 2 labels, got %d", m.Name, dp.Attributes.Len())
				}
				failures[side.Emit()+"/"+transport.Emit()] += dp.Value
			}
		}
	}
	return failures
}

// TestATransportWithoutHalfCloseIsCounted keeps the Ф1-5 counter honest now
// that no transport in the codebase trips it. The day one does - a transport
// added without the frame kind, or one where the FIN cannot be sent - the
// metric is how an operator finds out, so it is worth a test of its own.
func TestATransportWithoutHalfCloseIsCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	// net.Pipe offers no CloseWrite, which is exactly the case being counted.
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	conn := countAccepted(left, nil, telemetry, TransportWS)
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("an accepted connection does not offer CloseWrite")
	}
	if err := cw.CloseWrite(); err == nil {
		t.Fatal("CloseWrite on a transport that cannot half-close returned no error")
	}

	failures := collectHalfCloseFailures(t, reader)
	if got := failures[SideClient+"/"+TransportWS]; got != 1 {
		t.Fatalf("half-close failures = %d, want 1: %v", got, failures)
	}
}
