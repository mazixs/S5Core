package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/signals"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// Ф5-7 promises the fleet can be moved between transports with one edit and
// one signal. It could not: SIGHUP re-parsed the environment of a process
// already running, which nothing outside that process can change, so the
// reload applied the value the server started with (audit finding F19). The
// test that names the defect is therefore the whole path - write the file,
// send the signal, open a connection, read what the server now advises.

// reserveTestPort returns a port nothing is listening on. The binary takes
// its ports from the environment, so the test has to name one.
func reserveTestPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", l.Addr(), err)
	}
	return port
}

// adviceOn opens one tunnel and returns what the server advised on it. A
// server that advises nothing returns the zero advice, which is a value the
// test can compare like any other.
func adviceOn(t *testing.T, port, echo string) obfs.Advice {
	t.Helper()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 3*time.Second)
	if err != nil {
		t.Fatalf("dial the obfuscated port: %v", err)
	}
	defer func() { _ = raw.Close() }()

	got := make(chan obfs.Advice, 1)
	tunnel, err := obfs.NewClientConn(raw, obfs.Config{
		PSK:      []byte(envTestPSK),
		MTU:      1400,
		OnAdvice: func(a obfs.Advice) { got <- a },
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	defer func() { _ = tunnel.Close() }()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks5ConnectNoAuth(tunnel, echo); err != nil {
		t.Fatalf("connect through the tunnel: %v", err)
	}
	select {
	case a := <-got:
		return a
	case <-time.After(time.Second):
		// The advice rides in the server's first record, so by the time
		// CONNECT has been answered it has either arrived or does not exist.
		return obfs.Advice{}
	}
}

// waitForAdvice opens tunnels until the server advises want, or gives up. The
// reload happens on the signal goroutine, so the change is not instant; what
// the test asserts is that it happens at all, and on a connection accepted
// after the signal.
func waitForAdvice(t *testing.T, port, echo string, want obfs.Advice) obfs.Advice {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last obfs.Advice
	for time.Now().Before(deadline) {
		last = adviceOn(t, port, echo)
		if last == want {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last
}

// startAdvisingServer boots the binary's own configuration path - env.Parse,
// resolveTransportAdvice, setupServer - and its SIGHUP handler.
func startAdvisingServer(t *testing.T, adviceFile string) (port, echo string) {
	t.Helper()
	echo = startEcho(t)
	port = reserveTestPort(t)

	t.Setenv("PROXY_LISTEN_IP", "127.0.0.1")
	t.Setenv("PROXY_PORT", reserveTestPort(t))
	t.Setenv("REQUIRE_AUTH", "false")
	t.Setenv("OBFS_ENABLED", "true")
	t.Setenv("OBFS_PORT", port)
	t.Setenv("OBFS_PSK", envTestPSK)
	t.Setenv("TRANSPORT_ADVICE_FILE", adviceFile)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("the server would not start with this advice file: %v", err)
	}

	srv, err := setupServer(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	setupHotReload(ctx, srv)
	waitForListener(t, port)
	return port, echo
}

func waitForListener(t *testing.T, port string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the obfuscated listener never came up on port %s", port)
}

func hangUp(t *testing.T) {
	t.Helper()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find this process: %v", err)
	}
	if err := p.Signal(signals.Reload[0]); err != nil {
		t.Fatalf("send the reload signal: %v", err)
	}
}

func TestTheAdviceFileIsWhatTheReloadSignalRereads(t *testing.T) {
	if len(signals.Reload) == 0 {
		t.Skip("this platform has no reload signal, so there is nothing to re-read")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "advice")
	if err := os.WriteFile(file, []byte("obfs padding=32\n"), 0o600); err != nil {
		t.Fatalf("write the advice file: %v", err)
	}

	port, echo := startAdvisingServer(t, file)

	first := obfs.Advice{Transport: "obfs", MaxPadding: 32}
	if got := adviceOn(t, port, echo); got != first {
		t.Fatalf("the server advised %+v at startup, want the file's %+v", got, first)
	}

	// The edit an operator makes, and the signal they send after it.
	if err := os.WriteFile(file, []byte("obfs padding=48 keepalive=10s-20s\n"), 0o600); err != nil {
		t.Fatalf("rewrite the advice file: %v", err)
	}
	hangUp(t)

	second := obfs.Advice{Transport: "obfs", MaxPadding: 48, KeepaliveMin: 10 * time.Second, KeepaliveMax: 20 * time.Second}
	if got := waitForAdvice(t, port, echo, second); got != second {
		t.Fatalf("after the edit and the signal the server still advises %+v, want %+v", got, second)
	}

	// An unreadable file leaves the fleet where it is rather than quietly
	// withdrawing the recommendation: a reload that cannot read its source
	// knows nothing, and knowing nothing is not the same as being told to
	// advise nothing.
	if err := os.WriteFile(file, []byte("obfs padding=48\nobfs padding=64\n"), 0o600); err != nil {
		t.Fatalf("rewrite the advice file: %v", err)
	}
	hangUp(t)
	time.Sleep(300 * time.Millisecond)
	if got := adviceOn(t, port, echo); got != second {
		t.Fatalf("a broken advice file changed the advice to %+v, want the previous %+v", got, second)
	}

	// Removing the file is how a recommendation is withdrawn, and that is a
	// decision rather than a failure: it reaches the clients.
	if err := os.Remove(file); err != nil {
		t.Fatalf("remove the advice file: %v", err)
	}
	hangUp(t)
	if got := waitForAdvice(t, port, echo, obfs.Advice{}); got != (obfs.Advice{}) {
		t.Fatalf("after the file was removed the server still advises %+v", got)
	}
}

func TestTheAdviceFileWinsOverTheVariable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "advice")
	if err := os.WriteFile(file, []byte("obfs padding=48"), 0o600); err != nil {
		t.Fatalf("write the advice file: %v", err)
	}
	t.Setenv("TRANSPORT_ADVICE", "obfs padding=32")

	port, echo := startAdvisingServer(t, file)

	want := obfs.Advice{Transport: "obfs", MaxPadding: 48}
	if got := adviceOn(t, port, echo); got != want {
		t.Fatalf("the server advised %+v, want the file's %+v - the variable won", got, want)
	}
}

// The file is validated exactly like the variable, because it is the same
// setting: a server that starts and quietly advises nothing leaves the
// operator believing the fleet is moving.
func TestAnAdviceFileIsHeldToTheSameRulesAsTheVariable(t *testing.T) {
	t.Setenv("OBFS_ENABLED", "true")
	t.Setenv("OBFS_PSK", envTestPSK)
	t.Setenv("REQUIRE_AUTH", "false")

	dir := t.TempDir()

	t.Run("a typo in the file stops the server and is named", func(t *testing.T) {
		file := filepath.Join(dir, "typo")
		if err := os.WriteFile(file, []byte("obfs paddng=64"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Setenv("TRANSPORT_ADVICE_FILE", file)

		cfg := parseWithAdviceFile(t)
		cfg.Port = "0"
		_, err := setupServer(cfg, nil, nil)
		if err == nil {
			t.Fatal("the server started with an unparsable advice in the file")
		}
		if !errorMentions(err, "paddng") {
			t.Fatalf("the error does not name the typo: %v", err)
		}
	})

	t.Run("a transport the server does not run is refused", func(t *testing.T) {
		file := filepath.Join(dir, "ws")
		if err := os.WriteFile(file, []byte("ws"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Setenv("TRANSPORT_ADVICE_FILE", file)

		cfg := parseWithAdviceFile(t)
		cfg.Port = "0"
		_, err := setupServer(cfg, nil, nil)
		if err == nil || !errorMentions(err, "WS_ENABLED") {
			t.Fatalf("an advice to a disabled listener was accepted or the error does not say why: %v", err)
		}
	})

	t.Run("two lines are two recommendations and neither is taken", func(t *testing.T) {
		file := filepath.Join(dir, "twolines")
		if err := os.WriteFile(file, []byte("obfs padding=32\nobfs padding=64\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		var cfg params
		cfg.TransportAdviceFile = file
		err := resolveTransportAdvice(&cfg)
		if err == nil {
			t.Fatalf("two lines were accepted as %q", cfg.TransportAdvice)
		}
		if !errorMentions(err, "TRANSPORT_ADVICE_FILE") {
			t.Fatalf("the error does not name the variable that points at the file: %v", err)
		}
	})

	t.Run("a file too large to be an advice is refused, not read", func(t *testing.T) {
		file := filepath.Join(dir, "huge")
		if err := os.WriteFile(file, make([]byte, maxAdviceFileBytes+1), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		var cfg params
		cfg.TransportAdviceFile = file
		if err := resolveTransportAdvice(&cfg); err == nil {
			t.Fatal("a file larger than any advice was read as one")
		}
	})

	t.Run("a missing file means no advice, not an error", func(t *testing.T) {
		var cfg params
		cfg.TransportAdvice = "obfs padding=32"
		cfg.TransportAdviceFile = filepath.Join(dir, "not-there")
		if err := resolveTransportAdvice(&cfg); err != nil {
			t.Fatalf("a missing advice file was an error: %v", err)
		}
		if cfg.TransportAdvice != "" {
			t.Fatalf("a missing file left the advice at %q, want none: the file is the source, and it says nothing",
				cfg.TransportAdvice)
		}
	})
}

func parseWithAdviceFile(t *testing.T) params {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func errorMentions(err error, what string) bool {
	return err != nil && strings.Contains(err.Error(), what)
}
