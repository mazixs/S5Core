package s5server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// A server that cannot open all of its listeners opens none. Start used to
// return the failure and leave whatever it had already opened running: the
// plain SOCKS5 port went on accepting traffic after "failed to listen obfs
// on :1443" was logged and the operator had concluded the node was down.
// Traffic served in that state is served without obfuscation and without
// anybody watching it.
func TestAFailedStartLeavesNothingListening(t *testing.T) {
	// Somebody else already holds the obfuscated port - the ordinary way a
	// start fails in the field is a port still held by the previous process.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = blocker.Close() }()
	_, obfsPort, err := net.SplitHostPort(blocker.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	const plainPort = "19311"
	srv, err := NewServer(Config{
		Port:           plainPort,
		ListenIP:       "127.0.0.1",
		RequireAuth:    false,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 32,
		ObfsMTU:        1400,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := srv.Start(context.Background())
	if startErr == nil {
		t.Fatal("Start succeeded although the obfuscated port was taken")
	}
	if !strings.Contains(startErr.Error(), "obfs") {
		t.Fatalf("Start failed with %v, want the obfuscated listener named", startErr)
	}

	// The plain port is not accepting: the rollback ran before Start
	// returned, so there is no window where a caller that has already seen
	// the error is still being served.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("the plain SOCKS5 port is still accepting connections after Start failed")
	}

	// And the port is free, so a corrected configuration can start straight
	// away rather than after a TIME_WAIT-shaped wait for the goroutine that
	// still owns the socket.
	again, err := net.Listen("tcp", "127.0.0.1:"+plainPort)
	if err != nil {
		t.Fatalf("the plain port is still held after a failed start: %v", err)
	}
	_ = again.Close()
}

// The rollback is not only for a failed listen. A serving goroutine that
// reports a failure ends Start too, and the other listeners must go with it:
// one dead listener is a reason to stop the server, not a reason to keep two
// of the three running with nobody expecting them to.
func TestStartStopsEveryListenerWhenOneFails(t *testing.T) {
	const plainPort = "19312"
	const obfsPort = "19313"

	srv, err := NewServer(Config{
		Port:           plainPort,
		ListenIP:       "127.0.0.1",
		RequireAuth:    false,
		ObfsEnabled:    true,
		ObfsPort:       obfsPort,
		ObfsPSK:        testPSK,
		ObfsMaxPadding: 32,
		ObfsMTU:        1400,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	waitForPort(t, plainPort)
	waitForPort(t, obfsPort)

	// Kill one listener under the server, which is what its serving
	// goroutine reports as a failure.
	srv.mu.Lock()
	obfs := srv.obfsListen
	srv.mu.Unlock()
	if obfs == nil {
		t.Fatal("the obfuscated listener was never recorded")
	}
	_ = obfs.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after one of its listeners died")
	}

	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+plainPort, 2*time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("the plain port is still accepting after Start returned")
	}
}
