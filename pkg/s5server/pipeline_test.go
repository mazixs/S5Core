package s5server

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// dialObfs opens a connection to the obfuscated port and wraps it, the way a
// real client does.
func dialObfs(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	conn, err := obfs.NewClientConn(raw, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 256,
		MTU:        1400,
	})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return conn, nil
}

// MAX_CONNECTIONS used to be netutil.LimitListener wrapped around the plain
// listener and nothing else, so the port a real deployment serves - the
// obfuscated one - accepted connections without limit. The limit is also one
// counter for the whole server, not one per listener: three listeners with
// their own counters would let through three times the number configured.
func TestTheConnectionLimitCoversTheObfuscatedPort(t *testing.T) {
	echoAddr := startEchoServer(t)

	const plainPort = "19092"
	const obfsPort = "19446"
	obfsAddr := "127.0.0.1:" + obfsPort

	startServer(t, Config{
		Port:           plainPort,
		ListenIP:       "127.0.0.1",
		RequireAuth:    false,
		MaxConnections: 2,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 256,
		ObfsMTU:        1400,
	})

	// Two connections fill the server.
	held := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		conn, err := dialObfs(t, obfsAddr)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := socks5ConnectNoAuth(conn, echoAddr); err != nil {
			t.Fatalf("connection %d handshake: %v", i+1, err)
		}
		// Prove it is really established, so the slot is really taken.
		if err := echoThrough(conn, "one"); err != nil {
			t.Fatalf("connection %d echo: %v", i+1, err)
		}
		held = append(held, conn)
	}

	// The third is refused on arrival: the server closes it instead of
	// serving it, so the handshake cannot complete.
	third, err := dialObfs(t, obfsAddr)
	if err == nil {
		err = socks5ConnectNoAuth(third, echoAddr)
		_ = third.Close()
	}
	if err == nil {
		t.Fatal("a third connection was served although the limit is 2")
	}
	t.Logf("third connection refused as expected: %v", err)

	// Freeing a slot lets the next one in - the limit is a ceiling, not a
	// one-way door.
	_ = held[0].Close()

	var served bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := dialObfs(t, obfsAddr)
		if err == nil {
			err = socks5ConnectNoAuth(conn, echoAddr)
			if err == nil {
				t.Cleanup(func() { _ = conn.Close() })
				served = true
				break
			}
			_ = conn.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !served {
		t.Fatal("no connection was served after a slot was freed")
	}
}

// UpdateWhitelist used to reach the plain listener only, so an SDK caller who
// narrowed access at runtime narrowed it on one port out of three and was
// told nothing about the other two.
func TestUpdateWhitelistReachesEveryListener(t *testing.T) {
	tmpDir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(tmpDir)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	const plainPort = "19093"
	const obfsPort = "19447"
	plainAddr := "127.0.0.1:" + plainPort
	obfsAddr := "127.0.0.1:" + obfsPort

	srv := startServer(t, Config{
		Port:           plainPort,
		ListenIP:       "127.0.0.1",
		RequireAuth:    false,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 256,
		ObfsMTU:        1400,
		WSEnabled:      true,
		WSAddr:         "127.0.0.1:0",
		WSCertFile:     certFile,
		WSKeyFile:      keyFile,
		WSPath:         "/ws",
	})

	wsAddr := waitForWSAddr(t, srv)

	if got := len(srv.allPipelines()); got != 3 {
		t.Fatalf("expected three listeners, got %d", got)
	}

	// A whitelist that does not contain the loopback address: every listener
	// must now refuse this machine.
	if err := srv.UpdateWhitelist([]string{"198.51.100.7"}); err != nil {
		t.Fatalf("UpdateWhitelist: %v", err)
	}

	t.Run("plain", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", plainAddr, 2*time.Second)
		if err != nil {
			return // refused at connect is also a refusal
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := socks5ConnectNoAuth(conn, "127.0.0.1:1"); err == nil {
			t.Error("the plain listener served an address outside the whitelist")
		}
	})

	t.Run("obfs", func(t *testing.T) {
		conn, err := dialObfs(t, obfsAddr)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := socks5ConnectNoAuth(conn, "127.0.0.1:1"); err == nil {
			t.Error("the obfuscated listener served an address outside the whitelist")
		}
	})

	t.Run("ws", func(t *testing.T) {
		// The whitelist applies to the tunnel, not to the decoy: the decoy
		// site keeps answering everyone on purpose, because a site that
		// answers only whitelisted addresses is itself a signature. What must
		// not happen is that the tunnel carries traffic.
		resp, err := decoyClient().Get("https://" + wsAddr + "/")
		if err != nil {
			t.Fatalf("the decoy stopped answering: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("decoy status %d, want 200", resp.StatusCode)
		}
		resp.Body.Close()

		wsConn, err := ws.Dial(ws.DialOpts{
			URL:       "wss://" + wsAddr + "/ws",
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			return // refused during the upgrade is a refusal
		}
		defer wsConn.Close()
		_ = wsConn.SetDeadline(time.Now().Add(2 * time.Second))

		obfsConn, err := obfs.NewClientConn(wsConn, obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: 32,
			MTU:        1400,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		if err := socks5ConnectNoAuth(obfsConn, "127.0.0.1:1"); err == nil {
			t.Error("the WebSocket listener served an address outside the whitelist")
		}
	})

	// Restoring the empty whitelist restores service, on the same listeners.
	if err := srv.UpdateWhitelist(nil); err != nil {
		t.Fatalf("UpdateWhitelist(nil): %v", err)
	}

	echoAddr := startEchoServer(t)
	conn, err := dialObfs(t, obfsAddr)
	if err != nil {
		t.Fatalf("dial after restore: %v", err)
	}
	defer conn.Close()
	if err := socks5ConnectNoAuth(conn, echoAddr); err != nil {
		t.Fatalf("handshake after restore: %v", err)
	}
	if err := echoThrough(conn, "back"); err != nil {
		t.Fatalf("echo after restore: %v", err)
	}
}

// decoyClient talks to the decoy site over TLS without checking the test
// certificate.
func decoyClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * time.Second,
	}
}

func waitForWSAddr(t *testing.T, srv *Server) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := srv.WSAddr(); addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("WS listener never became ready")
	return ""
}

// socks5ConnectNoAuth performs the handshake for a server with RequireAuth
// off: no-auth method, then CONNECT to addr.
func socks5ConnectNoAuth(conn net.Conn, addr string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return errors.New("server did not accept the no-auth method")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return errors.New("connect refused by the server")
	}
	var rest int
	switch head[3] {
	case 0x01:
		rest = 4 + 2
	case 0x04:
		rest = 16 + 2
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		rest = int(lenByte[0]) + 2
	default:
		return errors.New("unknown address type in reply")
	}
	if _, err := io.ReadFull(conn, make([]byte, rest)); err != nil {
		return err
	}
	return nil
}

// echoThrough proves the tunnel carries traffic, which is what makes the
// connection an occupied slot rather than an open socket.
func echoThrough(conn net.Conn, msg string) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return errors.New("echo mismatch: " + string(buf))
	}
	return nil
}

// A WS_PATH that net/http cannot register used to take the server down at
// startup with a panic about mux patterns. The SDK's own validation is where
// that has to be caught, because that is what an embedding application calls.
func TestValidateConfigRejectsAnUnusableWSPath(t *testing.T) {
	base := Config{
		Port:       "0",
		WSEnabled:  true,
		WSCertFile: "cert.pem",
		WSKeyFile:  "key.pem",
	}

	for _, path := range []string{"/", "ws", "/ws/", "/favicon.ico"} {
		cfg := base
		cfg.WSPath = path
		if err := ValidateConfig(cfg); err == nil {
			t.Errorf("WS_PATH %q was accepted", path)
		}
	}

	// Empty is not a mistake: it means "use the default".
	cfg := base
	cfg.WSPath = ""
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("an empty WS_PATH was rejected: %v", err)
	}
}
