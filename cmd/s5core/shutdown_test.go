package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/logging"
	"github.com/mazixs/S5Core/internal/userstore"
)

// maxShutdown is how long SIGTERM to "everything has stopped" may take.
const maxShutdown = 3 * time.Second

// oneUserFile writes a users.json with a single account and no traffic used.
func oneUserFile(t *testing.T) string {
	t.Helper()
	users := userstore.UsersFile{
		Users: []userstore.UserAccount{{
			ID:       "u-001",
			Username: "alice",
			Password: "secret1",
			Enabled:  true,
		}},
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func trafficUsed(t *testing.T, path, username string) int64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	var file userstore.UsersFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse users file: %v", err)
	}
	for _, u := range file.Users {
		if u.Username == username {
			return u.TrafficUsedBytes
		}
	}
	t.Fatalf("user %q is not in the file", username)
	return 0
}

// The binary used to return from Start on SIGTERM and exit, never calling
// Stop. Two things followed: the traffic accumulated since the last periodic
// flush - up to TRAFFIC_FLUSH_INTERVAL of it - was lost on every restart, and
// the process left with its connection handlers still running.
//
// The flush interval here is an hour, so nothing but the shutdown itself can
// write the file.
func TestSIGTERMFlushesTrafficAndStopsEveryGoroutine(t *testing.T) {
	usersPath := oneUserFile(t)
	echoAddr := startEcho(t)

	t.Setenv("PROXY_PORT", "19088")
	t.Setenv("PROXY_LISTEN_IP", "127.0.0.1")
	t.Setenv("REQUIRE_AUTH", "true")
	t.Setenv("USERS_FILE", usersPath)
	t.Setenv("TRAFFIC_FLUSH_INTERVAL", "1h")
	t.Setenv("MAX_CONNECTIONS", "100")

	var cfg params
	if err := env.Parse(&cfg); err != nil {
		t.Fatalf("env.Parse: %v", err)
	}

	logger, _ := logging.Setup(io.Discard)
	srv, err := setupServer(cfg, nil, logger)
	if err != nil {
		t.Fatalf("setupServer: %v", err)
	}

	// The handler has to exist before the signal is sent, or SIGTERM kills the
	// test binary instead of being delivered to it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	started := make(chan error, 1)
	go func() { started <- srv.Start(ctx) }()

	// A live, authenticated session with traffic on it: this is the traffic
	// that has to survive the shutdown.
	conn := waitForProxy(t, "127.0.0.1:19088")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5ConnectAuth(conn, "alice", "secret1", echoAddr); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	payload := strings.Repeat("x", 4096)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if used := trafficUsed(t, usersPath, "alice"); used != 0 {
		t.Fatalf("the file already holds %d bytes; the test cannot tell who wrote them", used)
	}

	// A second connection that says nothing: its handler is parked in the
	// first read of the handshake, where no proxy loop and no context
	// watcher can reach it. Only the handshake budget would, in fifteen
	// seconds. Shutdown has to close it.
	silent := waitForProxy(t, "127.0.0.1:19088")
	defer silent.Close()

	// The check below is only worth anything if there is something to leak.
	if live := countServerGoroutines(); live == 0 {
		t.Fatal("no server goroutines are running while a session is live; the leak check would pass on an empty process")
	}

	// The real signal, delivered to this process.
	shutdownStart := time.Now()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case err := <-started:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after SIGTERM")
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Shutdown has to be prompt. A connection parked in the handshake is
	// released by its budget eventually, so a server that does not close its
	// connections still stops - fifteen seconds later, with the process
	// hanging around in exactly the window an orchestrator counts as a failed
	// stop.
	if elapsed := time.Since(shutdownStart); elapsed > maxShutdown {
		t.Errorf("shutdown took %v, want under %v", elapsed.Round(time.Millisecond), maxShutdown)
	}

	if used := trafficUsed(t, usersPath, "alice"); used < int64(len(payload)) {
		t.Errorf("users.json holds %d bytes, want at least %d: the last interval was lost", used, len(payload))
	}

	// goleak in the shape this repo can afford: the count has to come back
	// down on its own. Handlers that were serving live connections are the
	// ones that used to stay behind.
	if leaked := waitForNoServerGoroutines(); leaked > 0 {
		t.Errorf("%d server goroutines outlived the shutdown:\n%s", leaked, goroutineDump())
	}
}

// waitForProxy dials the proxy until it answers, so the test does not race
// the listener coming up.
func waitForProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the proxy never accepted a connection on %s", addr)
	return nil
}

// serverPackages are the frames that identify a goroutine as belonging to the
// proxy rather than to the test or the runtime. Counting these instead of
// comparing runtime.NumGoroutine to a baseline matters: the baseline moves on
// its own - signal.NotifyContext, for one, retires its own goroutine when the
// signal arrives - and a moving baseline hides exactly one leaked goroutine.
var serverPackages = []string{
	"S5Core/internal/socks5.",
	"S5Core/pkg/s5server.",
}

// countServerGoroutines counts the goroutines currently inside the proxy.
func countServerGoroutines() int {
	var n int
	for _, g := range strings.Split(goroutineDump(), "\n\n") {
		for _, pkg := range serverPackages {
			if strings.Contains(g, pkg) {
				n++
				break
			}
		}
	}
	return n
}

// waitForNoServerGoroutines gives the runtime a moment to finish what the
// shutdown started, then reports how many proxy goroutines are still running.
func waitForNoServerGoroutines() int {
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.Gosched()
		left := countServerGoroutines()
		if left == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func goroutineDump() string {
	buf := make([]byte, 1<<16)
	return string(buf[:runtime.Stack(buf, true)])
}

// socks5ConnectAuth performs a username/password handshake and a CONNECT.
func socks5ConnectAuth(conn net.Conn, user, pass, addr string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x02 {
		return errUnexpected("the server did not select username/password auth")
	}

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errUnexpected("authentication was refused")
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
	head := make([]byte, 10) // IPv4 reply: the destination is an address here
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return errUnexpected("connect was refused")
	}
	return nil
}

type errUnexpected string

func (e errUnexpected) Error() string { return string(e) }
