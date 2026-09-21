package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// flushWindow is the largest amount of traffic the relay can account for in one
// step, and therefore the largest amount a session can transfer after it has
// used up its quota. It mirrors flushThreshold in proxyWithTraffic.
const flushWindow = 64 * 1024

// streamingDestination answers every connection with an endless stream, so the
// only thing that can stop a transfer is the proxy itself.
func streamingDestination(t *testing.T) *net.TCPAddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("destination listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				block := make([]byte, 32*1024)
				for {
					if _, err := c.Write(block); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr)
}

// quotaProxy starts a SOCKS5 server that meters traffic into counter. With
// enforce set it also ends a session once the counter reaches limit, which is
// the shape of a userstore quota; without it, the quota is only checked at
// login, the way it used to be.
func quotaProxy(t *testing.T, counter *atomic.Int64, limit int64, enforce bool) net.Addr {
	t.Helper()

	conf := &Config{
		AuthMethods: []Authenticator{UserPassAuthenticator{
			Credentials: StaticCredentials{"metered": "secret"},
		}},
		Logger:         slog.Default(),
		TrafficCounter: func(string) *atomic.Int64 { return counter },
	}
	if enforce {
		conf.SessionStatus = func(string) SessionStatus {
			if counter.Load() < limit {
				return SessionAllowed
			}
			return SessionQuotaExceeded
		}
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serv.ServeContext(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		<-done
	})
	return l.Addr()
}

// connectThrough performs the handshake and the CONNECT, and returns a
// connection positioned at the first byte of relayed data.
func connectThrough(t *testing.T, proxy net.Addr, dest *net.TCPAddr) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", proxy.String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req := []byte{5, 1, UserPassAuth, userAuthVersion, byte(len("metered"))}
	req = append(req, "metered"...)
	req = append(req, byte(len("secret")))
	req = append(req, "secret"...)
	req = append(req, 5, ConnectCommand, 0, ipv4Address)
	req = append(req, dest.IP.To4()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(dest.Port))
	req = append(req, port...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	// Method selection, then the auth status, then the CONNECT reply with a
	// bound IPv4 address: 2 + 2 + 10 bytes before the tunnel starts.
	head := make([]byte, 14)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if head[3] != authSuccess {
		t.Fatalf("authentication failed: % x", head[:4])
	}
	if head[5] != successReply {
		t.Fatalf("connect refused: % x", head[4:])
	}
	return conn
}

// drain reads until the proxy stops the session, and reports how much arrived.
func drain(t *testing.T, conn net.Conn, limit int64) (int64, error) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	// Reading past any sane bound is how a session that ignores its quota
	// ends this test instead of running until the deadline.
	received, err := io.CopyN(io.Discard, conn, limit)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return received, err
}

// A quota used to be checked once, at login. A session that started one byte
// under its limit then ran for as long as the client wanted, and the account
// file said the user was out of traffic while the user was still downloading.
func TestASessionEndsWithinOneFlushWindowOfItsQuota(t *testing.T) {
	const quota = 512 * 1024

	dest := streamingDestination(t)
	var counter atomic.Int64
	proxy := quotaProxy(t, &counter, quota, true)

	received, err := drain(t, connectThrough(t, proxy, dest), 8*quota)
	if err != nil && !endOfSession(err) {
		t.Fatalf("the relay ended with an unexpected error after %d bytes: %v", received, err)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the session was still running %d bytes into a %d byte quota", received, quota)
	}

	metered := counter.Load()
	if metered < quota {
		t.Fatalf("the session ended after %d bytes, before it had used its %d byte quota", metered, quota)
	}
	if over := metered - quota; over > flushWindow {
		t.Errorf("the session transferred %d bytes past its quota, want at most %d", over, flushWindow)
	}
	if received > quota+flushWindow {
		t.Errorf("the client received %d bytes against a %d byte quota", received, quota)
	}
}

// The control: the same transfer with the check unwired runs far past the
// quota. Without this, the test above would pass just as well on a proxy that
// closes every session early for some unrelated reason.
func TestWithoutTheCheckASessionRunsPastItsQuota(t *testing.T) {
	const quota = 512 * 1024

	dest := streamingDestination(t)
	var counter atomic.Int64
	proxy := quotaProxy(t, &counter, quota, false)

	want := int64(quota) + 4*flushWindow
	received, err := drain(t, connectThrough(t, proxy, dest), want)
	if err != nil {
		t.Fatalf("the relay stopped after %d bytes: %v", received, err)
	}
	if received != want {
		t.Fatalf("read %d bytes, want %d", received, want)
	}
}

// endOfSession reports whether the error is how a closed tunnel looks from the
// client side: a FIN if the socket drained, a reset if it did not.
func endOfSession(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// A user the store no longer knows resolves to a nil counter. The relay then
// runs unmetered rather than dereferencing it - the session is ended by the
// quota check, not by a crash.
func TestAnUnknownUserGetsAnUnmeteredRelayInsteadOfAPanic(t *testing.T) {
	dest := streamingDestination(t)

	conf := &Config{
		AuthMethods: []Authenticator{UserPassAuthenticator{
			Credentials: StaticCredentials{"metered": "secret"},
		}},
		Logger:         slog.Default(),
		TrafficCounter: func(string) *atomic.Int64 { return nil },
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serv.ServeContext(ctx, l)
	}()
	defer func() {
		cancel()
		_ = l.Close()
		<-done
	}()

	received, err := drain(t, connectThrough(t, l.Addr(), dest), 128*1024)
	if err != nil {
		t.Fatalf("the relay failed after %d bytes: %v", received, err)
	}
	if received != 128*1024 {
		t.Errorf("read %d bytes, want %d", received, 128*1024)
	}
}
