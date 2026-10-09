package main

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// A reset on a spare is repeated only when the kernel says the server
// acknowledged nothing of it since it was taken. These tests ask a real
// socket; on a pipe there is nothing to ask.

func socketPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("no connection accepted")
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func ackedAbove(c net.Conn, base uint64) func() bool {
	return func() bool {
		n, ok := bytesAcked(c)
		return ok && n > base
	}
}

func reset(t *testing.T, c *net.TCPConn) {
	t.Helper()
	if err := c.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestAResetAfterTheServerAcknowledgedTheRequestIsNotRepeated(t *testing.T) {
	client, server := socketPair(t)
	spare := newTakenSpare(client)
	if !spare.known {
		t.Fatal("the kernel gave no TCP_INFO for a live socket")
	}
	request := make([]byte, 100)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(server, request); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the request is acknowledged", ackedAbove(client, spare.acked))
	reset(t, server)

	_, readErr := client.Read(make([]byte, 1))
	if !errors.Is(readErr, syscall.ECONNRESET) {
		t.Fatalf("the read got %v, want a reset", readErr)
	}
	err := tunnelFail(phaseGreeting, "failed to read server greeting: %w", readErr)
	_ = spare.Close()
	markSpareFailure(err, endedUnanswered(err), spare)
	if mayRetry(err) {
		t.Fatal("a request the server acknowledged was repeated")
	}
	if countsAgainstThePath(err) {
		t.Fatal("a reset on a spare counted against the path")
	}
}

func TestAResetBeforeAnythingWasAcknowledgedIsRepeated(t *testing.T) {
	client, server := socketPair(t)
	spare := newTakenSpare(client)
	reset(t, server)
	waitFor(t, "the reset arrives", func() bool {
		info, ok := tcptune.InfoOf(client)
		return ok && info.State != tcptune.StateEstablished
	})

	_, writeErr := client.Write(make([]byte, 100))
	if !errors.Is(writeErr, syscall.ECONNRESET) && !errors.Is(writeErr, syscall.EPIPE) {
		t.Fatalf("the write got %v, want a reset", writeErr)
	}
	for _, closed := range []bool{false, true} {
		if closed {
			_ = spare.Close()
		}
		err := tunnelFail(phaseGreeting, "failed to send greeting: %w", writeErr)
		markSpareFailure(err, endedUnanswered(err), spare)
		if !mayRetry(err) {
			t.Fatalf("a request nothing of which was acknowledged was not repeated (spare closed: %v)", closed)
		}
	}
}

// The same through the tunnel: a spare the server reset after it took the
// request fails the tunnel, rests nothing and dials nothing.
func TestAResetSpareThatTookTheRequestFailsTheTunnel(t *testing.T) {
	client, server := socketPair(t)
	cfg := policyParams(t)

	var dials atomic.Int32
	original := dialServer
	t.Cleanup(func() { dialServer = original })
	dialServer = func(clientParams) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no fresh dial in this test")
	}
	base, _ := bytesAcked(client)
	spares.mu.Lock()
	spares.on = true
	spares.spare = &spareConn{
		conn:   client,
		key:    spareKey(cfg),
		born:   spares.stamp(),
		maxAge: time.Minute,
		expire: time.AfterFunc(time.Hour, func() {}),
	}
	spares.mu.Unlock()
	t.Cleanup(spares.stop)

	go func() {
		if _, err := server.Read(make([]byte, 1)); err != nil {
			return
		}
		acked := ackedAbove(client, base)
		for deadline := time.Now().Add(5 * time.Second); !acked() && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		_ = server.SetLinger(0)
		_ = server.Close()
	}()
	conn, _, err := dialAttempt(cfg, connectRequest())
	if err == nil {
		_ = conn.Close()
		t.Fatal("a tunnel on a reset spare succeeded")
	}
	if tunnelPhaseOf(err) != phaseGreeting || mayRetry(err) {
		t.Fatalf("the tunnel failed with %v, want an unrepeated failure in the greeting", err)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("%d fresh dials after a reset the server may have acted on", n)
	}
	if n := restedTransports(cfg.policy); n != 0 {
		t.Fatalf("a reset spare rested %d transports", n)
	}
}
