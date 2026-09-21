package s5server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/session"
	"github.com/mazixs/S5Core/internal/socks5"
)

type slowCredentials struct{}

func (slowCredentials) Valid(string, string) bool {
	time.Sleep(time.Second)
	return true
}

// Deterministically reproduce the CI failure: correct credentials finish
// after the handshake budget, so only the server can explain the peer's EOF.
func TestAuthReplyTimeoutHasServerSideClassification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		srv, err := socks5.New(&socks5.Config{
			Credentials: slowCredentials{},
			Logger:      slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		})
		if err != nil {
			t.Fatal(err)
		}
		client, raw := net.Pipe()
		defer client.Close()
		sess := session.NewRegistry(nil).Open(TransportPlain, false, session.SLA{Handshake: 500 * time.Millisecond})
		conn := &metricsConn{Conn: &timeoutConn{Conn: raw, sess: sess}, sess: sess}
		done := make(chan error, 1)
		go func() { done <- srv.ServeConnContext(context.Background(), conn) }()
		if _, err := client.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		var reply [2]byte
		if _, err := io.ReadFull(client, reply[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{1, 1, 'u', 1, 'p'}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, reply[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("client: %v", err)
		}
		err = <-done
		var ce *socks5.ConnError
		var ne net.Error
		if !errors.As(err, &ce) || ce.Stage != "auth" || ce.Op != "result_write" || ce.Kind != socks5.FailureTimeout {
			t.Fatalf("server lost timeout cause: %v", err)
		}
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("lost net.Error: %v", err)
		}
		for _, want := range []string{"stage=auth", "operation=result_write", "kind=timeout", "transport=plain", "handshake_budget=500ms"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("missing %s: %s", want, &logs)
			}
		}
		if strings.Contains(logs.String(), "write pipe") {
			t.Fatalf("raw transport error leaked: %s", &logs)
		}
	})
}
