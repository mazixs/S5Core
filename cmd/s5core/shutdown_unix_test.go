//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/logging"
)

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

	port := reserveTestPort(t)
	t.Setenv("PROXY_PORT", port)
	t.Setenv("PROXY_LISTEN_IP", "127.0.0.1")
	t.Setenv("REQUIRE_AUTH", "true")
	t.Setenv("ALLOW_PRIVATE_DEST", "true")
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
	conn := waitForProxy(t, "127.0.0.1:"+port)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(answerWithin))
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
	silent := waitForProxy(t, "127.0.0.1:"+port)
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
