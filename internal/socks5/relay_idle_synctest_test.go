package socks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

func auditRelaySession(sla session.SLA) *session.Session {
	sess := session.NewRegistry(nil).Open("plain", false, sla)
	sess.Enter(session.Handshake)
	sess.Enter(session.Dialing)
	sess.Become(session.Stream)
	return sess
}

func TestHalfClosedSilentTargetEndsAtReadIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, serverSide := net.Pipe()
		defer client.Close()
		targetSide, peer := net.Pipe()
		defer peer.Close()
		target := &drainDest{Conn: targetSide, closed: make(chan struct{})}
		server, err := New(&Config{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- server.relayConnect(ctx, serverSide, &Request{
				bufConn: bytes.NewReader(nil), session: auditRelaySession(session.SLA{ReadIdle: 3 * time.Second}),
			}, target)
		}()
		defer func() { cancel(); <-done }()
		synctest.Wait()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			if err == nil {
				t.Error("silent target ended without a timeout")
			}
			done <- err
		default:
			t.Fatal("silent half-closed target retains the connection past its idle budget")
		}
	})
}

func TestHalfClosedTargetActivityRefreshesItsReadIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, serverSide := net.Pipe()
		defer client.Close()
		targetSide, peer := net.Pipe()
		defer peer.Close()
		target := &drainDest{Conn: targetSide, closed: make(chan struct{})}
		server, err := New(&Config{})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			defer serverSide.Close()
			done <- server.relayConnect(context.Background(), serverSide, &Request{
				bufConn: bytes.NewReader(nil), session: auditRelaySession(session.SLA{ReadIdle: 3 * time.Second}),
			}, target)
		}()
		got := make(chan []byte, 1)
		go func() { p, _ := io.ReadAll(client); got <- p }()
		synctest.Wait()
		for range 5 {
			time.Sleep(2 * time.Second)
			if _, err := peer.Write([]byte("reply")); err != nil {
				t.Fatal(err)
			}
		}
		peer.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if p := <-got; string(p) != "replyreplyreplyreplyreply" {
			t.Fatalf("truncated reply %q", p)
		}
	})
}

func TestIdleTCPAccountRevocationDoesNotWaitForBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status SessionStatus
	}{
		{"disabled", SessionExpired}, {"deleted", SessionExpired},
		{"expired", SessionExpired}, {"quota", SessionQuotaExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, serverSide := net.Pipe()
				defer client.Close()
				targetSide, peer := net.Pipe()
				defer peer.Close()
				var revoked atomic.Bool
				server, err := New(&Config{SessionStatus: func(string) SessionStatus {
					if revoked.Load() {
						return tc.status
					}
					return SessionAllowed
				}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() {
					done <- server.relayConnect(ctx, serverSide, &Request{
						bufConn: serverSide, AuthContext: &AuthContext{Payload: map[string]string{"Username": "member"}},
						session: auditRelaySession(session.SLA{ReadIdle: time.Hour, Grace: 2 * time.Second}),
					}, &drainDest{Conn: targetSide, closed: make(chan struct{})})
				}()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				revoked.Store(true)
				time.Sleep(4 * time.Second)
				synctest.Wait()
				select {
				case err := <-done:
					if err == nil {
						t.Error("revoked account ended without refusal")
					}
					done <- err
				default:
					t.Fatal("idle TCP remains alive after account revocation and grace")
				}
			})
		})
	}
}
