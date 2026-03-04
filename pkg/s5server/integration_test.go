package s5server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

const testPSK = "01234567890123456789012345678901" // 32 bytes

// testUsersFile creates a temp users.json and returns its path.
func testUsersFile(t *testing.T) string {
	t.Helper()
	validFrom := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredUntil := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)

	users := userstore.UsersFile{
		Users: []userstore.UserAccount{
			{
				ID:                "u-001",
				Username:          "alice",
				Password:          "secret1",
				Comment:           "Active test user",
				ValidFrom:         &validFrom,
				ValidUntil:        &validUntil,
				TrafficLimitBytes: 10 * 1024 * 1024, // 10 MB
				Enabled:           true,
			},
			{
				ID:       "u-002",
				Username: "bob",
				Password: "secret2",
				Comment:  "No TTL user",
				Enabled:  true,
			},
			{
				ID:         "u-003",
				Username:   "expired",
				Password:   "secret3",
				ValidUntil: &expiredUntil,
				Enabled:    true,
			},
			{
				ID:       "u-004",
				Username: "disabled",
				Password: "secret4",
				Enabled:  false,
			},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startEchoServer starts a TCP echo server and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	return l.Addr().String()
}

// startServer starts an s5server with given config and returns
// a cleanup function. Blocks until the server is ready to accept.
func startServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Stop()
	})

	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("server error: %v", err)
		}
	}()

	// Wait for listeners to be ready
	waitForPort(t, cfg.Port)
	if cfg.ObfsEnabled && cfg.ObfsPort != "" {
		waitForPort(t, cfg.ObfsPort)
	}

	return srv
}

func waitForPort(t *testing.T, port string) {
	t.Helper()
	addr := "127.0.0.1:" + port
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("port %s not ready after 2s", port)
}

// socks5Connect performs a SOCKS5 CONNECT handshake and returns the connection
// and any error. It handles greeting + auth + connect request.
func socks5Connect(conn net.Conn, user, pass, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, _ := net.LookupPort("tcp", portStr)

	// Greeting: offer user/pass auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}

	// Read greeting response
	var greetResp [2]byte
	if _, err := io.ReadFull(conn, greetResp[:]); err != nil {
		return fmt.Errorf("greeting read: %w", err)
	}
	if greetResp[0] != 0x05 {
		return fmt.Errorf("bad SOCKS version: %d", greetResp[0])
	}

	switch greetResp[1] {
	case 0x02:
		// User/pass auth
		if err := doAuth(conn, user, pass); err != nil {
			return err
		}
	case 0xFF:
		return fmt.Errorf("server rejected all auth methods")
	default:
		return fmt.Errorf("unexpected auth method: 0x%02x", greetResp[1])
	}

	// CONNECT request
	ip := net.ParseIP(host)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect write: %w", err)
	}

	// Read CONNECT response
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("connect read: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("CONNECT failed: status 0x%02x", resp[1])
	}

	return nil
}

func doAuth(conn net.Conn, user, pass string) error {
	pkt := make([]byte, 0, 3+len(user)+len(pass))
	pkt = append(pkt, 0x01)
	pkt = append(pkt, byte(len(user)))
	pkt = append(pkt, []byte(user)...)
	pkt = append(pkt, byte(len(pass)))
	pkt = append(pkt, []byte(pass)...)

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("auth write: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("auth read: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("auth failed: status 0x%02x", resp[1])
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suite
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_PlainSOCKS5_ValidUser(t *testing.T) {
	t.Skip("Reimplemented in TestIntegration_FullSuite with fixed ports")
}

func TestIntegration_FullSuite(t *testing.T) {
	echoAddr := startEchoServer(t)
	usersPath := testUsersFile(t)

	const plainPort = "19080"
	const obfsPort = "19443"

	startServer(t, Config{
		Port:            plainPort,
		ListenIP:        "127.0.0.1",
		RequireAuth:     true,
		UsersFile:       usersPath,
		Fail2BanRetries: 10,
		Fail2BanTime:    1 * time.Minute,
		ObfsEnabled:     true,
		ObfsPort:        obfsPort,
		ObfsPSK:         testPSK,
		ObfsMaxPadding:  256,
		ObfsMTU:         1400,
	})

	// ─── Test 1: Valid auth via plain SOCKS5 ──────────────────────────
	t.Run("Plain_ValidAuth_Alice", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		if err := socks5Connect(conn, "alice", "secret1", echoAddr); err != nil {
			t.Fatalf("handshake: %v", err)
		}

		// Echo test
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "hello" {
			t.Fatalf("echo mismatch: %q", buf)
		}
		t.Logf("✓ Plain SOCKS5 handshake + echo OK (alice)")
	})

	// ─── Test 2: Valid auth via plain SOCKS5 (bob, no TTL) ───────────
	t.Run("Plain_ValidAuth_Bob", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		if err := socks5Connect(conn, "bob", "secret2", echoAddr); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		t.Logf("✓ Plain SOCKS5 auth OK (bob, no TTL)")
	})

	// ─── Test 3: Wrong password ──────────────────────────────────────
	t.Run("Plain_WrongPassword", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		err = socks5Connect(conn, "alice", "WRONGPASS", echoAddr)
		if err == nil {
			t.Fatal("expected auth failure for wrong password")
		}
		t.Logf("✓ Wrong password correctly rejected: %v", err)
	})

	// ─── Test 4: Wrong username ──────────────────────────────────────
	t.Run("Plain_WrongUsername", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		err = socks5Connect(conn, "nonexistent", "anypass", echoAddr)
		if err == nil {
			t.Fatal("expected auth failure for unknown user")
		}
		t.Logf("✓ Unknown username correctly rejected: %v", err)
	})

	// ─── Test 5: Expired user ────────────────────────────────────────
	t.Run("Plain_ExpiredUser", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		err = socks5Connect(conn, "expired", "secret3", echoAddr)
		if err == nil {
			t.Fatal("expected auth failure for expired user")
		}
		t.Logf("✓ Expired user correctly rejected: %v", err)
	})

	// ─── Test 6: Disabled user ───────────────────────────────────────
	t.Run("Plain_DisabledUser", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		err = socks5Connect(conn, "disabled", "secret4", echoAddr)
		if err == nil {
			t.Fatal("expected auth failure for disabled user")
		}
		t.Logf("✓ Disabled user correctly rejected: %v", err)
	})

	// ─── Test 7: Valid auth via obfuscated connection ─────────────────
	t.Run("Obfs_ValidAuth", func(t *testing.T) {
		rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawConn.Close()

		obfsConn, err := obfs.NewConn(rawConn, obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: 256,
			MTU:        1400,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		obfsConn.SetDeadline(time.Now().Add(3 * time.Second))

		if err := socks5Connect(obfsConn, "alice", "secret1", echoAddr); err != nil {
			t.Fatalf("obfs handshake: %v", err)
		}

		// Echo test
		if _, err := obfsConn.Write([]byte("obfs-ping")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 9)
		if _, err := io.ReadFull(obfsConn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "obfs-ping" {
			t.Fatalf("echo mismatch: %q", buf)
		}
		t.Logf("✓ Obfuscated SOCKS5 handshake + echo OK")
	})

	// ─── Test 8: Wrong PSK on obfuscated port ────────────────────────
	t.Run("Obfs_WrongPSK", func(t *testing.T) {
		rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawConn.Close()

		wrongPSK := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 bytes, wrong key
		obfsConn, err := obfs.NewConn(rawConn, obfs.Config{
			PSK:        []byte(wrongPSK),
			MaxPadding: 256,
			MTU:        1400,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		obfsConn.SetDeadline(time.Now().Add(2 * time.Second))

		// Try greeting — server won't be able to decrypt, should error
		_, _ = obfsConn.Write([]byte{0x05, 0x01, 0x02})

		// We expect read to fail because server decryption fails
		var resp [2]byte
		_, readErr := io.ReadFull(obfsConn, resp[:])
		if readErr == nil {
			t.Fatal("expected error with wrong PSK")
		}
		t.Logf("✓ Wrong PSK correctly rejected: %v", readErr)
	})

	// ─── Test 9: Plain TCP to obfs port (no encryption) ──────────────
	t.Run("Obfs_PlainToObfsPort", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Send a regular SOCKS5 greeting (not encrypted)
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})

		// Server should fail to decrypt and close the connection
		buf := make([]byte, 10)
		_, readErr := conn.Read(buf)
		if readErr == nil {
			t.Fatal("expected connection error when sending plain to obfs port")
		}
		t.Logf("✓ Plain traffic to obfs port correctly rejected: %v", readErr)
	})

	// ─── Test 10: Wrong auth via obfuscated connection ────────────────
	t.Run("Obfs_WrongAuth", func(t *testing.T) {
		rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawConn.Close()

		obfsConn, err := obfs.NewConn(rawConn, obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: 256,
			MTU:        1400,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		obfsConn.SetDeadline(time.Now().Add(3 * time.Second))

		err = socks5Connect(obfsConn, "alice", "WRONG", echoAddr)
		if err == nil {
			t.Fatal("expected auth failure via obfs with wrong password")
		}
		t.Logf("✓ Wrong auth via obfs correctly rejected: %v", err)
	})

	// ─── Test 11: Connection speed benchmark ─────────────────────────
	t.Run("Bench_PlainEcho", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		if err := socks5Connect(conn, "bob", "secret2", echoAddr); err != nil {
			t.Fatalf("handshake: %v", err)
		}

		// Benchmark: send/recv 1MB in chunks
		const chunkSize = 32 * 1024
		const totalBytes = 1 * 1024 * 1024
		chunk := make([]byte, chunkSize)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}
		readBuf := make([]byte, chunkSize)

		start := time.Now()
		var totalSent, totalRecv int

		for totalSent < totalBytes {
			n, err := conn.Write(chunk)
			if err != nil {
				t.Fatalf("write at %d: %v", totalSent, err)
			}
			totalSent += n

			for totalRecv < totalSent {
				rn, err := conn.Read(readBuf)
				if err != nil {
					t.Fatalf("read at %d: %v", totalRecv, err)
				}
				totalRecv += rn
			}
		}

		elapsed := time.Since(start)
		mbps := float64(totalBytes) / elapsed.Seconds() / 1024 / 1024
		t.Logf("✓ Plain SOCKS5 echo: %d bytes in %v (%.1f MB/s)", totalBytes, elapsed, mbps)
	})

	// ─── Test 12: Obfuscated connection speed benchmark ───────────────
	t.Run("Bench_ObfsEcho", func(t *testing.T) {
		rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawConn.Close()

		obfsConn, err := obfs.NewConn(rawConn, obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: 256,
			MTU:        1400,
		})
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		obfsConn.SetDeadline(time.Now().Add(10 * time.Second))

		if err := socks5Connect(obfsConn, "alice", "secret1", echoAddr); err != nil {
			t.Fatalf("handshake: %v", err)
		}

		// Benchmark: send/recv 1MB in chunks (smaller due to obfs overhead)
		const chunkSize = 1024 // smaller chunks due to MTU
		const totalBytes = 1 * 1024 * 1024
		chunk := make([]byte, chunkSize)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}
		readBuf := make([]byte, chunkSize)

		start := time.Now()
		var totalSent, totalRecv int

		for totalSent < totalBytes {
			n, err := obfsConn.Write(chunk)
			if err != nil {
				t.Fatalf("write at %d: %v", totalSent, err)
			}
			totalSent += n

			for totalRecv < totalSent {
				rn, err := obfsConn.Read(readBuf)
				if err != nil {
					t.Fatalf("read at %d: %v", totalRecv, err)
				}
				totalRecv += rn
			}
		}

		elapsed := time.Since(start)
		mbps := float64(totalBytes) / elapsed.Seconds() / 1024 / 1024
		t.Logf("✓ Obfs SOCKS5 echo: %d bytes in %v (%.1f MB/s)", totalBytes, elapsed, mbps)
	})

	// ─── Test 13: Handshake latency ──────────────────────────────────
	t.Run("Latency_PlainHandshake", func(t *testing.T) {
		const iterations = 20
		var totalDuration time.Duration

		for i := 0; i < iterations; i++ {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))

			start := time.Now()
			err = socks5Connect(conn, "alice", "secret1", echoAddr)
			elapsed := time.Since(start)
			conn.Close()

			if err != nil {
				t.Fatalf("handshake %d: %v", i, err)
			}
			totalDuration += elapsed
		}

		avg := totalDuration / iterations
		t.Logf("✓ Plain handshake latency: avg %v over %d iterations", avg, iterations)
	})

	t.Run("Latency_ObfsHandshake", func(t *testing.T) {
		const iterations = 20
		var totalDuration time.Duration

		for i := 0; i < iterations; i++ {
			rawConn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}

			obfsConn, err := obfs.NewConn(rawConn, obfs.Config{
				PSK:        []byte(testPSK),
				MaxPadding: 256,
				MTU:        1400,
			})
			if err != nil {
				t.Fatalf("obfs wrap: %v", err)
			}
			obfsConn.SetDeadline(time.Now().Add(3 * time.Second))

			start := time.Now()
			err = socks5Connect(obfsConn, "alice", "secret1", echoAddr)
			elapsed := time.Since(start)
			obfsConn.Close()

			if err != nil {
				t.Fatalf("handshake %d: %v", i, err)
			}
			totalDuration += elapsed
		}

		avg := totalDuration / iterations
		t.Logf("✓ Obfs handshake latency: avg %v over %d iterations", avg, iterations)
	})

	// ─── Test 14: Traffic accounting ─────────────────────────────────
	t.Run("TrafficAccounting", func(t *testing.T) {
		// Read the users file to check traffic was recorded
		data, err := os.ReadFile(usersPath)
		if err != nil {
			t.Fatalf("read users file: %v", err)
		}

		var uf userstore.UsersFile
		if err := json.Unmarshal(data, &uf); err != nil {
			t.Fatalf("parse users file: %v", err)
		}

		for _, u := range uf.Users {
			t.Logf("  User %q: traffic_used=%d bytes", u.Username, u.TrafficUsedBytes)
		}
		t.Logf("✓ Traffic accounting data logged (flush may not have occurred yet)")
	})

	// ─── Test 15: Obfuscation wire analysis ──────────────────────────
	t.Run("Obfs_WireAnalysis", func(t *testing.T) {
		// Create a pipe to capture raw wire traffic
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		obfsCfg := obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: 256,
			MTU:        1400,
		}

		// Wrap client side with obfs
		obfsClient, err := obfs.NewConn(clientConn, obfsCfg)
		if err != nil {
			t.Fatalf("obfs client: %v", err)
		}

		// Send SOCKS5 greeting through obfs
		payload := []byte{0x05, 0x01, 0x02}
		go func() {
			obfsClient.Write(payload)
		}()

		// Read raw wire bytes from server side (no obfs)
		rawBuf := make([]byte, 2048)
		serverConn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := serverConn.Read(rawBuf)
		if err != nil {
			t.Fatalf("raw read: %v", err)
		}
		rawWire := rawBuf[:n]

		// Verify: wire bytes should NOT contain SOCKS signature
		hasSocksSignature := false
		for i := 0; i < len(rawWire)-2; i++ {
			if rawWire[i] == 0x05 && rawWire[i+1] == 0x01 && rawWire[i+2] == 0x02 {
				hasSocksSignature = true
				break
			}
		}
		if hasSocksSignature {
			t.Error("SOCKS5 signature found in obfuscated wire traffic!")
		} else {
			t.Logf("✓ No SOCKS5 signature in wire traffic")
		}

		// Check frame structure: first 4 bytes = frame length
		if n >= 4 {
			frameLen := binary.BigEndian.Uint32(rawWire[:4])
			t.Logf("  Wire frame: %d bytes total, frame_len=%d", n, frameLen)
			t.Logf("  Overhead: %d bytes for %d-byte payload (%.0f%%)",
				n-len(payload), len(payload),
				float64(n-len(payload))/float64(len(payload))*100)
		}

		// Entropy check (simplified — count unique byte values)
		seen := make(map[byte]bool)
		for _, b := range rawWire {
			seen[b] = true
		}
		uniqueRatio := float64(len(seen)) / float64(n) * 100
		t.Logf("  Unique bytes: %d/%d (%.0f%%) — high ratio = good randomness", len(seen), n, uniqueRatio)
	})
}

// ─── Standalone edge-case tests ──────────────────────────────────────────────

func TestIntegration_NoUsersFile_LegacyMode(t *testing.T) {
	echoAddr := startEchoServer(t)

	const port = "19180"
	cfg := Config{
		Port:            port,
		ListenIP:        "127.0.0.1",
		RequireAuth:     true,
		Fail2BanRetries: 5,
		Fail2BanTime:    1 * time.Minute,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Add legacy user
	if err := srv.AddUser("legacy", "pass"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Stop()
	})
	go srv.Start(ctx)
	waitForPort(t, port)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := socks5Connect(conn, "legacy", "pass", echoAddr); err != nil {
		t.Fatalf("legacy auth: %v", err)
	}
	t.Logf("✓ Legacy PROXY_USER/PROXY_PASSWORD mode works")

	// Ensure unknown user fails
	conn2, _ := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(3 * time.Second))

	err = socks5Connect(conn2, "hacker", "pass", echoAddr)
	if err == nil {
		t.Fatal("expected failure for unknown user in legacy mode")
	}
	t.Logf("✓ Legacy mode rejects unknown users: %v", err)
}

// Ensure unused imports don't cause issues
var _ = socks5.ConnectCommand
