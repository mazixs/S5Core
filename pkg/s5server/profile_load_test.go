//go:build loadtest

// Ф2-6: where the allocations on the relay path actually come from.
//
// The hypothesis under test, stated in the plan: the obfs read buffer is two
// MTUs (2800 bytes), while every relay in the process copies through a 32 KiB
// buffer, so each large frame misses the pre-allocated buffer and takes the
// make([]byte, frameSize) branch plus a tail copy. If that is what the profile
// says, the "zero-allocation" claim fails on a combination of sizes rather
// than on the algorithm - and it is fixed by agreeing the sizes (Ф4-2), not by
// changing the frame format.
//
//	go test -tags loadtest -run TestObfsRelayProfile -v -timeout 10m ./pkg/s5server/
//	go tool pprof -top -sample_index=alloc_space bench/profiles/obfs-relay.alloc
//	go tool pprof -top bench/profiles/obfs-relay.cpu
//
// Knobs: PROFILE_CONNS (default 4), PROFILE_MB (default 64, per connection).

package s5server

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// startSinkServer serves a fixed number of bytes to every connection and then
// closes it. A download is the direction where the relay reads large blocks,
// which is the case the hypothesis is about.
func startSinkServer(t *testing.T, perConn int64) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		payload := make([]byte, 64*1024)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				left := perConn
				for left > 0 {
					chunk := payload
					if int64(len(chunk)) > left {
						chunk = chunk[:left]
					}
					n, err := c.Write(chunk)
					if err != nil {
						return
					}
					left -= int64(n)
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

// socks5ConnectNoAuth lives in pipeline_test.go: the handshake is the same
// one the pipeline tests do, and having it twice broke the build under
// -tags loadtest.

func TestObfsRelayProfile(t *testing.T) {
	conns := envInt("PROFILE_CONNS", 4)
	perConnMB := envInt("PROFILE_MB", 64)
	perConn := int64(perConnMB) * 1024 * 1024

	sinkAddr := startSinkServer(t, perConn)

	plainPort := freePort(t)
	obfsPort := freePort(t)
	cfg := DefaultConfig()
	cfg.Port = plainPort
	cfg.ListenIP = "127.0.0.1"
	cfg.RequireAuth = false
	cfg.ObfsEnabled = true
	cfg.ObfsPort = obfsPort
	cfg.ObfsPSK = testPSK
	cfg.ObfsMaxPadding = 32
	cfg.ObfsMTU = 1400
	startServer(t, cfg)

	dialObfs := func() (net.Conn, error) {
		raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", obfsPort), 5*time.Second)
		if err != nil {
			return nil, err
		}
		oc, err := obfs.NewClientConn(raw, obfs.Config{
			PSK:        []byte(testPSK),
			MaxPadding: cfg.ObfsMaxPadding,
			MTU:        cfg.ObfsMTU,
		})
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		return oc, nil
	}

	// Warm-up: pools filled, listeners hot, so the profile shows steady state.
	warm, err := dialObfs()
	if err != nil {
		t.Fatalf("warm-up dial: %v", err)
	}
	if err := socks5ConnectNoAuth(warm, sinkAddr); err != nil {
		t.Fatalf("warm-up connect: %v", err)
	}
	if _, err := io.CopyN(io.Discard, warm, 1<<20); err != nil {
		t.Fatalf("warm-up read: %v", err)
	}
	_ = warm.Close()

	dir := filepath.Join("..", "..", "bench", "profiles")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	cpuPath := filepath.Join(dir, "obfs-relay.cpu")
	allocPath := filepath.Join(dir, "obfs-relay.alloc")

	cpuFile, err := os.Create(cpuPath)
	if err != nil {
		t.Fatalf("create cpu profile: %v", err)
	}
	defer func() { _ = cpuFile.Close() }()

	runtime.GC()
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		t.Fatalf("start cpu profile: %v", err)
	}

	var transferred atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := dialObfs()
			if err != nil {
				t.Errorf("conn %d dial: %v", i, err)
				return
			}
			defer func() { _ = c.Close() }()
			if err := socks5ConnectNoAuth(c, sinkAddr); err != nil {
				t.Errorf("conn %d connect: %v", i, err)
				return
			}
			n, err := io.Copy(io.Discard, c)
			transferred.Add(n)
			if err != nil {
				t.Errorf("conn %d copy: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	pprof.StopCPUProfile()

	allocFile, err := os.Create(allocPath)
	if err != nil {
		t.Fatalf("create alloc profile: %v", err)
	}
	defer func() { _ = allocFile.Close() }()
	if err := pprof.Lookup("allocs").WriteTo(allocFile, 0); err != nil {
		t.Fatalf("write alloc profile: %v", err)
	}

	total := transferred.Load()
	mb := float64(total) / (1024 * 1024)
	t.Logf("relayed %.0f MiB over %d connections in %s (%.1f MiB/s in-process)",
		mb, conns, elapsed.Round(time.Millisecond), mb/elapsed.Seconds())
	t.Logf("profiles: %s %s", cpuPath, allocPath)

	if total < int64(conns)*perConn {
		t.Fatalf("short transfer: got %d bytes, want %d", total, int64(conns)*perConn)
	}
}
