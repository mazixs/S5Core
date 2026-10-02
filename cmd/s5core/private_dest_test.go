package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The binary refuses destinations on its own machine and network unless the
// operator sets ALLOW_PRIVATE_DEST (Ч-27); the SDK default of the same field
// is the opposite, so the setting has to be tested where it is turned on.
func TestTheBinaryRefusesThePrivateNetworkUnlessAllowed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow string
		want  string
	}{
		{"by default", "", "code 2"},
		{"when allowed", "true", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echo := startEcho(t)
			port := reserveTestPort(t)
			t.Setenv("PROXY_LISTEN_IP", "127.0.0.1")
			t.Setenv("PROXY_PORT", port)
			t.Setenv("REQUIRE_AUTH", "false")
			t.Setenv("ALLOW_PRIVATE_DEST", tc.allow)
			if tc.allow == "" {
				_ = os.Unsetenv("ALLOW_PRIVATE_DEST")
			}
			cfg, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			srv, err := setupServer(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
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
			waitForListener(t, port)

			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			err = socks5ConnectNoAuth(conn, echo)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("a destination on the machine was refused although it is allowed: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("CONNECT to the loopback answered %v, want a refusal with %q", err, tc.want)
			}
		})
	}
}
