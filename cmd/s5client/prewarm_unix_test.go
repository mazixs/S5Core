//go:build unix

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

func pollUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

// waiting reports whether bytes are queued on the socket under c, unread.
func waiting(t *testing.T, c any) bool {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T has no socket", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = raw.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, _, _ = syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		return true
	})
	return n > 0
}

func TestASpareWithUnreadBytesIsNotHungUp(t *testing.T) {
	client, server := tcpPair(t)
	if hungUp(client) {
		t.Fatal("an open spare is reported as hung up")
	}
	if _, err := server.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, "the bytes never arrived", func() bool { return waiting(t, client) })
	if hungUp(client) {
		t.Fatal("a spare with unread bytes is reported as hung up")
	}
}

func TestASpareTheServerClosedIsHungUp(t *testing.T) {
	client, server := tcpPair(t)
	_ = server.Close()
	pollUntil(t, "a spare the server closed is not reported as hung up", func() bool { return hungUp(client) })
}

// The case a peek cannot see: a TLS server sends close_notify ahead of its
// FIN, so bytes are waiting in front of the close.
func TestASpareClosedBehindBytesIsHungUpWhereTheStateIsKnown(t *testing.T) {
	client, server := tcpPair(t)
	if _, ok := tcptune.InfoOf(client); !ok {
		t.Skip("the kernel does not report the TCP state here")
	}
	if _, err := server.Write([]byte("close_notify")); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	pollUntil(t, "a spare closed behind bytes is not reported as hung up", func() bool { return hungUp(client) })
}

func TestAHungUpSpareIsNotTaken(t *testing.T) {
	var mu sync.Mutex
	servers := map[net.Conn]net.Conn{}
	original := dialServer
	t.Cleanup(func() { dialServer = original })
	dialServer = func(clientParams) (net.Conn, error) {
		c, s := tcpPair(t)
		mu.Lock()
		servers[c] = s
		mu.Unlock()
		return c, nil
	}
	var p prewarmPool
	cfg := prewarmParams(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.start(ctx, cfg)

	for range 2 {
		c, _, err := p.take(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	var spare net.Conn
	pollUntil(t, "no spare", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.spare != nil {
			spare = p.spare.conn
		}
		return spare != nil
	})
	mu.Lock()
	_ = servers[spare].Close()
	mu.Unlock()
	pollUntil(t, "the closed spare is not seen as hung up", func() bool { return hungUp(spare) })

	c, onSpare, err := p.take(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if onSpare || c == spare {
		t.Fatal("a spare the server had closed was handed to a tunnel")
	}
	if _, err := spare.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the hung-up spare was not closed by the client: %v", err)
	}
}
