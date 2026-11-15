package s5server

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/diagnostics"
	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// startLatency turns the latency recorder on for the test and waits until
// it selects a socket.
func startLatency(t *testing.T) {
	t.Helper()
	t.Setenv("S5_DIAGNOSTICS_DIR", t.TempDir()+"/diag")
	t.Cleanup(diagnostics.StartLatency())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		observed := diagnostics.ObserveConn(c, "probe", "tcp")
		_ = observed.Close()
		if observed != c {
			return
		}
	}
	t.Fatal("the latency recorder did not start")
}

// layers walks c down as tcptune.Socket does and names every layer.
func layers(c net.Conn) []string {
	var names []string
	for c != nil && len(names) < 20 {
		names = append(names, fmt.Sprintf("%T", c))
		switch v := c.(type) {
		case *net.TCPConn:
			return names
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		case interface{ Unwrap() net.Conn }:
			c = v.Unwrap()
		default:
			return names
		}
	}
	return names
}

// The deepest stack the server builds - metering, obfuscation, deadlines,
// the limit, the latency recorder's wrapper, WebSocket shaping, the early
// data and TLS - still lets the walks reach the socket: the tuning of a
// 0x83 tunnel, and the kernel's counters at its close.
func TestTheLatencyWrapperKeepsTheDeepestStackWalkable(t *testing.T) {
	var mu sync.Mutex
	var tuned []net.Conn
	orig := udpTunnelTuner
	udpTunnelTuner = func(*slog.Logger) func(net.Conn) {
		return func(c net.Conn) {
			mu.Lock()
			tuned = append(tuned, c)
			mu.Unlock()
		}
	}
	t.Cleanup(func() { udpTunnelTuner = orig })
	startLatency(t)

	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, Config{
		ListenIP: "127.0.0.1", Port: anyPort, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: anyPort, ObfsPSK: testPSK, ObfsMaxPadding: 64, ObfsMTU: 1400,
		WSEnabled: true, WSAddr: "127.0.0.1:0", WSCertFile: certFile, WSKeyFile: keyFile, WSPath: "/ws",
		WSEarlyData: WSEarlyDataAuto, WSMinFrame: 256, WSMaxFrame: 4096, MaxConnections: 16,
	})
	for deadline := time.Now().Add(3 * time.Second); srv.WSAddr() == "" && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	w, err := obfs.NewClientConn(dialEarlyWS(t, "wss://"+srv.WSAddr()+"/ws"), obfs.Config{PSK: []byte(testPSK), MaxPadding: 64, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socksOver(t, w, socks5.UDPTunnelCommand, []byte{0x01, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("0x83 refused: %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tuned) != 1 {
		t.Fatalf("%d tunnels", len(tuned))
	}
	chain := layers(tuned[0])
	t.Logf("%d layers: %s", len(chain), strings.Join(chain, " > "))
	if !strings.Contains(strings.Join(chain, " "), "diagnostics.observed") {
		t.Fatal("the recorder did not wrap the tunnel")
	}
	if _, err := tcptune.Socket(tuned[0]); err != nil {
		t.Fatalf("the walk does not reach the socket: %v", err)
	}
}
