package s5server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// thinTimeouts reads the option the tuning sets first; a socket that has it
// went through tcptune.
func thinTimeouts(t *testing.T, c net.Conn) int {
	t.Helper()
	sc, err := tcptune.Socket(c)
	if err != nil {
		t.Fatalf("no socket under %T: %v", c, err)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_THIN_LINEAR_TIMEOUTS)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

type tunedConns struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (tc *tunedConns) hook(t *testing.T) {
	orig := udpTunnelTuner
	udpTunnelTuner = func(l *slog.Logger) func(net.Conn) {
		tune := orig(l)
		return func(c net.Conn) {
			tune(c)
			tc.mu.Lock()
			tc.conns = append(tc.conns, c)
			tc.mu.Unlock()
		}
	}
	t.Cleanup(func() { udpTunnelTuner = orig })
}

func (tc *tunedConns) all() []net.Conn {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return append([]net.Conn(nil), tc.conns...)
}

// socksOver runs the no-auth greeting and one request over c and returns the
// reply code.
func socksOver(t *testing.T, c net.Conn, command byte, addr []byte) byte {
	t.Helper()
	if _, err := c.Write(append([]byte{0x05, 0x01, 0x00, 0x05, command, 0x00}, addr...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 12)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply[3]
}

// The socket under a 0x83 tunnel gets the options on the server, through
// every wrapper the server stacks on either transport: metering, deadlines,
// obfuscation, and for wss the WebSocket and TLS as well. A CONNECT relay on
// the same listener does not.
func TestTheServerTunesTheSocketOfEveryUDPTunnel(t *testing.T) {
	var tuned tunedConns
	tuned.hook(t)
	dir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	echoAddr := startEchoServer(t)
	const obfsPort = "19471"
	srv := startServer(t, Config{
		Port: "19470", ListenIP: "127.0.0.1", ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: obfsPort, ObfsPSK: testPSK, ObfsMaxPadding: 32, ObfsMTU: 1400,
		WSEnabled: true, WSAddr: "127.0.0.1:0", WSCertFile: certFile, WSKeyFile: keyFile, WSPath: "/ws",
		// cmd/s5core always has a limit, and its wrapper sits between the
		// tunnel and the socket.
		MaxConnections: 16,
	})
	var wsAddr string
	for range 300 {
		if wsAddr = srv.WSAddr(); wsAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wsAddr == "" {
		t.Fatal("WS listener not ready")
	}

	anyAddr := []byte{0x01, 0, 0, 0, 0, 0, 0}
	echo := echoAddr
	host, port, _ := net.SplitHostPort(echo)
	ip := net.ParseIP(host).To4()
	p, _ := net.LookupPort("tcp", port)
	connectAddr := []byte{0x01, ip[0], ip[1], ip[2], ip[3], byte(p >> 8), byte(p)}

	c, err := dialObfs(t, "127.0.0.1:"+obfsPort)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if code := socksOver(t, c, socks5.ConnectCommand, connectAddr); code != 0 {
		t.Fatalf("CONNECT refused: %d", code)
	}
	if n := len(tuned.all()); n != 0 {
		t.Fatalf("a CONNECT relay was tuned (%d connections)", n)
	}

	u, err := dialObfs(t, "127.0.0.1:"+obfsPort)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if code := socksOver(t, u, socks5.UDPTunnelCommand, anyAddr); code != 0 {
		t.Fatalf("0x83 over obfs refused: %d", code)
	}

	wsConn, err := ws.Dial(ws.DialOpts{URL: "wss://" + wsAddr + "/ws", TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer wsConn.Close()
	w, err := obfs.NewClientConn(ws.NewShapedConn(wsConn, ws.DefaultMinFrame, ws.DefaultMaxFrame, 0), obfs.Config{PSK: []byte(testPSK), MaxPadding: 32, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socksOver(t, w, socks5.UDPTunnelCommand, anyAddr); code != 0 {
		t.Fatalf("0x83 over wss refused: %d", code)
	}

	got := tuned.all()
	if len(got) != 2 {
		t.Fatalf("%d connections were tuned, want the two tunnels", len(got))
	}
	for i, conn := range got {
		if v := thinTimeouts(t, conn); v != 1 {
			t.Fatalf("tunnel %d (%T): thin linear timeouts = %d, want 1", i, conn, v)
		}
	}
	// The client end of the wss tunnel reaches its socket as well, which is
	// what s5client relies on.
	if _, err := tcptune.Socket(w); err != nil {
		t.Fatalf("the client's wss tunnel hides its socket: %v", err)
	}
}

func TestTheSwitchLeavesTheKernelTimer(t *testing.T) {
	var tuned tunedConns
	tuned.hook(t)
	const obfsPort = "19473"
	startServer(t, Config{
		Port: "19472", ListenIP: "127.0.0.1", ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: obfsPort, ObfsPSK: testPSK, ObfsMaxPadding: 32, ObfsMTU: 1400,
		UDPTunnelTCPTuningOff: true,
	})
	u, err := dialObfs(t, "127.0.0.1:"+obfsPort)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if code := socksOver(t, u, socks5.UDPTunnelCommand, []byte{0x01, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("0x83 refused: %d", code)
	}
	if n := len(tuned.all()); n != 0 {
		t.Fatalf("%d tunnels were tuned with the switch off", n)
	}
}
