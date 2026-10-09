package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Plan task R4-1 (docs/plan/v2.4-rc4.md, decision 1): under OPTIMISTIC_CONNECT
// the application hears success before the tunnel exists, and its bytes go
// into the tunnel without waiting for the server's reply. These tests pin the
// order of events on net.Pipe inside a synctest bubble.

func optimisticParams() clientParams {
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	return cfg
}

// pipeServer makes dialServer hand back one end of a pipe and gives the
// other end to the test.
func pipeServer(t *testing.T) <-chan net.Conn {
	t.Helper()
	original := dialServer
	t.Cleanup(func() { dialServer = original })
	side := make(chan net.Conn, 2)
	dialServer = func(clientParams) (net.Conn, error) {
		local, remote := net.Pipe()
		t.Cleanup(func() {
			_ = local.Close()
			_ = remote.Close()
		})
		side <- remote
		return local, nil
	}
	return side
}

// openApp starts handleClient and does the local greeting and CONNECT, the
// way an application does.
func openApp(t *testing.T, cfg clientParams) (net.Conn, <-chan struct{}) {
	t.Helper()
	app, client := net.Pipe()
	t.Cleanup(func() { _ = app.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(client, cfg, nil)
	}()
	writeErr := make(chan error, 1)
	go func() {
		_, err := app.Write(append([]byte{0x05, 0x01, 0x00}, connectRequest()...))
		writeErr <- err
	}()
	var greetResp [2]byte
	if _, err := io.ReadFull(app, greetResp[:]); err != nil {
		t.Fatalf("greeting response: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("application write: %v", err)
	}
	return app, done
}

func readReply(t *testing.T, app net.Conn) []byte {
	t.Helper()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(app, reply); err != nil {
		t.Fatalf("the application got no reply: %v", err)
	}
	return reply
}

// serverReadsRequest takes the opening, the greeting and CONNECT off the
// server end.
func serverReadsRequest(t *testing.T, raw net.Conn, cfg clientParams) net.Conn {
	t.Helper()
	server := obfsServerSide(t, raw, cfg)
	if _, err := io.ReadFull(server, make([]byte, 3+len(connectRequest()))); err != nil {
		t.Fatalf("server read of greeting and CONNECT: %v", err)
	}
	return server
}

// The success comes before the dial, and the application's first bytes reach
// the server before the server has said anything at all - not even the reply
// to the greeting. That is the round trip saved.
func TestAnOptimisticConnectSendsTheApplicationsBytesBeforeTheReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := optimisticParams()
		logs := captureLogs(t)

		original := dialServer
		t.Cleanup(func() { dialServer = original })
		gate := make(chan struct{})
		side := make(chan net.Conn, 2)
		dialServer = func(clientParams) (net.Conn, error) {
			<-gate
			local, remote := net.Pipe()
			t.Cleanup(func() {
				_ = local.Close()
				_ = remote.Close()
			})
			side <- remote
			return local, nil
		}

		app, done := openApp(t, cfg)
		if got := readReply(t, app); !bytes.Equal(got, successReply) {
			t.Fatalf("the application got %v before the dial, want %v", got, successReply)
		}
		close(gate)

		request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		go func() { _, _ = app.Write(request) }()

		server := serverReadsRequest(t, <-side, cfg)
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("the server did not get the application's bytes before its reply: %v", err)
		}
		if !bytes.Equal(got, request) {
			t.Fatalf("the server got %q, want %q", got, request)
		}

		response := "HTTP/1.1 204 No Content\r\n\r\n"
		if _, err := server.Write(append(append([]byte{0x05, 0x00}, successReply...), response...)); err != nil {
			t.Fatalf("server replies: %v", err)
		}
		back := make([]byte, len(response))
		if _, err := io.ReadFull(app, back); err != nil {
			t.Fatalf("the application got no response: %v", err)
		}
		if string(back) != response {
			t.Fatalf("the application got %q after the reply, want %q", back, response)
		}

		_ = server.Close()
		_ = app.Close()
		<-done
		out := logs.String()
		for _, want := range []string{"TCP Tunnel closed", fmt.Sprintf("up=%d", len(request)), fmt.Sprintf("down=%d", len(response))} {
			if !strings.Contains(out, want) {
				t.Fatalf("the log does not say %s:\n%s", want, out)
			}
		}
	})
}

// A refusal arrives after the application was told success, so it can only
// be the end of the connection; the log still names the code. Without
// OPTIMISTIC_CONNECT the application gets the code itself, as before.
func TestARefusalAfterAnOptimisticSuccessClosesTheApplication(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code       byte
		optimistic bool
	}{
		{"connection refused", 0x05, true},
		{"not allowed", 0x02, true},
		{"connection refused without optimism", 0x05, false},
		{"not allowed without optimism", 0x02, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := testClientParams()
				cfg.OptimisticConnect = tc.optimistic
				logs := captureLogs(t)
				side := pipeServer(t)
				closedBefore := minutes.closed[1].Load()
				failedBefore := minutes.failed.Load()

				app, done := openApp(t, cfg)
				var early []byte
				if tc.optimistic {
					early = readReply(t, app)
					if !bytes.Equal(early, successReply) {
						t.Fatalf("the application got %v, want an early success", early)
					}
					go func() { _, _ = app.Write([]byte("hello")) }()
				}

				server := serverReadsRequest(t, <-side, cfg)
				if tc.optimistic {
					if _, err := io.ReadFull(server, make([]byte, len("hello"))); err != nil {
						t.Fatalf("server read of the early bytes: %v", err)
					}
				}
				refusal := []byte{0x05, tc.code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
				if _, err := server.Write(append([]byte{0x05, 0x00}, refusal...)); err != nil {
					t.Fatalf("server refusal: %v", err)
				}

				if tc.optimistic {
					n, err := app.Read(make([]byte, 16))
					if n != 0 || err == nil {
						t.Fatalf("after a refusal the application read %d bytes, err %v; want the connection closed", n, err)
					}
				} else if got := readReply(t, app); !bytes.Equal(got, refusal) {
					t.Fatalf("the application got %v, want the refusal %v", got, refusal)
				}

				_ = server.Close()
				<-done
				out := logs.String()
				for _, want := range []string{"closed_by=server", fmt.Sprintf("reply=%d", tc.code)} {
					if !strings.Contains(out, want) {
						t.Fatalf("the log does not say %s:\n%s", want, out)
					}
				}
				if got := minutes.closed[1].Load() - closedBefore; got != 1 {
					t.Fatalf("the minute counted %d connections closed by the server, want 1", got)
				}
				if got := minutes.failed.Load() - failedBefore; got != 0 {
					t.Fatalf("a refusal was counted as %d failed setups", got)
				}
			})
		})
	}
}

// SSH and SMTP wait for the server to speak. Nothing in the optimistic path
// waits for the application, so such a protocol works.
func TestAServerFirstProtocolWorksOptimistically(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := optimisticParams()
		side := pipeServer(t)

		app, done := openApp(t, cfg)
		readReply(t, app)

		server := serverReadsRequest(t, <-side, cfg)
		banner := "220 mail.example.com ESMTP\r\n"
		if _, err := server.Write(append(append([]byte{0x05, 0x00}, successReply...), banner...)); err != nil {
			t.Fatalf("server reply and banner: %v", err)
		}
		got := make([]byte, len(banner))
		if _, err := io.ReadFull(app, got); err != nil {
			t.Fatalf("the application got no banner: %v", err)
		}
		if string(got) != banner {
			t.Fatalf("the application got %q, want %q", got, banner)
		}

		go func() { _, _ = app.Write([]byte("QUIT\r\n")) }()
		quit := make([]byte, len("QUIT\r\n"))
		if _, err := io.ReadFull(server, quit); err != nil {
			t.Fatalf("the server got no answer to its banner: %v", err)
		}

		_ = server.Close()
		_ = app.Close()
		<-done
	})
}

// The handshake deadline still bounds the setup: a server that never answers
// ends the application's connection exactly at HANDSHAKE_TIMEOUT, the log
// names the silent phase, and the policy hears of it as before.
func TestASilentServerEndsAnOptimisticConnectAtTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		silentServer(t)
		logs := captureLogs(t)
		cfg := optimisticParams()
		cfg.WSUrl = "wss://cdn.example/ws"
		cfg.TransportCooldown = 5 * time.Minute
		p, _ := policyFor(t, cfg)
		cfg.policy = p
		if first := cfg.attempt().transport; first != transportWS {
			t.Fatalf("unexpected first transport: %s", first)
		}

		app, done := openApp(t, cfg)
		readReply(t, app)
		go func() { _, _ = app.Write([]byte("hello")) }()

		start := time.Now()
		n, err := app.Read(make([]byte, 16))
		waited := time.Since(start)
		<-done
		if n != 0 || err == nil {
			t.Fatalf("the application read %d bytes, err %v; want the connection closed", n, err)
		}
		if waited != cfg.HandshakeTimeout {
			t.Fatalf("the application waited %v, want exactly %v", waited, cfg.HandshakeTimeout)
		}

		out := logs.String()
		for _, want := range []string{"level=WARN", "Tunnel setup timed out", "phase=" + string(phaseGreeting), "dest=example.com"} {
			if !strings.Contains(out, want) {
				t.Fatalf("the log does not say %s:\n%s", want, out)
			}
		}
		if next := cfg.attempt().transport; next != transportObfs {
			t.Fatalf("a silent server left the next connection on %s", next)
		}
	})
}

// A dial that fails after the early success closes the application's
// connection and is logged as a failed setup.
func TestAFailedDialEndsAnOptimisticConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		original := dialServer
		t.Cleanup(func() { dialServer = original })
		dialServer = func(clientParams) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}

		app, done := openApp(t, optimisticParams())
		readReply(t, app)
		n, err := app.Read(make([]byte, 16))
		<-done
		if n != 0 || err == nil {
			t.Fatalf("the application read %d bytes, err %v; want the connection closed", n, err)
		}
		if out := logs.String(); !strings.Contains(out, "Tunnel setup failed") || !strings.Contains(out, "phase="+string(phaseDial)) {
			t.Fatalf("the log does not name the failed dial:\n%s", out)
		}
	})
}

// The upstream writes under the handshake deadline until the reply comes.
// The reply must clear it for both directions: an established tunnel idle for
// longer than the setup budget is not a stalled one.
func TestAnOptimisticTunnelDoesNotInheritTheSetupDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := optimisticParams()
		side := pipeServer(t)

		app, done := openApp(t, cfg)
		readReply(t, app)
		server := serverReadsRequest(t, <-side, cfg)
		if _, err := server.Write(append([]byte{0x05, 0x00}, successReply...)); err != nil {
			t.Fatalf("server replies: %v", err)
		}
		synctest.Wait()

		time.Sleep(10 * cfg.HandshakeTimeout)
		synctest.Wait()

		go func() { _, _ = app.Write([]byte("late up")) }()
		up := make([]byte, len("late up"))
		if _, err := io.ReadFull(server, up); err != nil {
			t.Fatalf("the idle tunnel lost its upstream: %v", err)
		}
		if _, err := server.Write([]byte("late down")); err != nil {
			t.Fatalf("server write after a long idle period: %v", err)
		}
		down := make([]byte, len("late down"))
		if _, err := io.ReadFull(app, down); err != nil {
			t.Fatalf("the idle tunnel lost its downstream: %v", err)
		}

		_ = server.Close()
		_ = app.Close()
		<-done
	})
}
