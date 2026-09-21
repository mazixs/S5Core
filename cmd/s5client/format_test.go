package main

import (
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs/legacy"
)

// Plan task Ф5-7: "the client chooses the protocol by an environment
// variable, the new one by default, with automatic fallback on refusal; two
// minor releases later the old mode is removed". The fallback is the part
// that keeps a fleet working while its servers are updated one by one.

func TestTheCurrentFormatIsTriedFirstAndThePreviousOneAfterARefusal(t *testing.T) {
	base := baseParams("")
	p, clock := policyFor(t, base)

	attempt := p.apply(base)
	if attempt.format != formatV1 {
		t.Fatalf("the first attempt spoke %s, want v1", attempt.format)
	}

	// The server accepted the connection and said nothing: from here that
	// is what an older server looks like. The next attempts speak the
	// previous format for the reprobe window.
	p.onFailure(attempt, phaseGreeting)
	attempt = p.apply(base)
	if attempt.format != formatLegacy {
		t.Fatalf("after a silent server the client stayed on %s", attempt.format)
	}
	p.onSuccess(attempt)
	clock.advance(base.FormatReprobe - time.Second)
	if got := p.apply(base); got.format != formatLegacy {
		t.Fatalf("the fallback ended early: %s", got.format)
	}

	// The window is over: the current format is probed again, so that an
	// updated server is noticed without anyone restarting the client.
	clock.advance(2 * time.Second)
	if got := p.apply(base); got.format != formatV1 {
		t.Fatalf("after the reprobe window the client did not try v1 again: %s", got.format)
	}

	// The previous format failing the same way sends the client straight
	// back to the current one: whichever the server speaks, the client
	// alternates until one answers.
	p.onFailure(p.apply(base), phaseGreeting)
	if got := p.apply(base); got.format != formatLegacy {
		t.Fatalf("a second silent v1 attempt did not bring the previous format back: %s", got.format)
	}
	p.onFailure(p.apply(base), phaseGreeting)
	if got := p.apply(base); got.format != formatV1 {
		t.Fatalf("after the previous format failed too the client stayed on %s", got.format)
	}

	// A dial that never connected says nothing about formats.
	p.onFailure(p.apply(base), phaseDial)
	if got := p.apply(base); got.format != formatV1 {
		t.Fatalf("a failed dial changed the format to %s", got.format)
	}

	// A success on v1 ends any fallback at once.
	p.onFailure(p.apply(base), phaseAuth)
	p.onSuccess(clientParams{format: formatV1, transport: transportObfs})
	if got := p.apply(base); got.format != formatV1 {
		t.Fatalf("a success on v1 did not end the fallback: %s", got.format)
	}
}

func TestAPinnedFormatNeverMoves(t *testing.T) {
	for _, pinned := range []formatKind{formatV1, formatLegacy} {
		base := baseParams("")
		base.Format = string(pinned)
		p, _ := policyFor(t, base)
		attempt := p.apply(base)
		if attempt.format != pinned {
			t.Fatalf("OBFS_FORMAT=%s gave %s", pinned, attempt.format)
		}
		p.onFailure(attempt, phaseGreeting)
		if got := p.apply(base); got.format != pinned {
			t.Fatalf("OBFS_FORMAT=%s moved to %s after a refusal", pinned, got.format)
		}
	}
}

// startLegacyServer is a server of the previous format: what a client meets
// when the server has not been updated. It answers SOCKS5 on every
// connection it can read, and closes the ones it cannot.
func startLegacyServer(t *testing.T, psk string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, err := legacy.NewConn(raw, legacy.Config{PSK: []byte(psk)})
				if err != nil {
					return
				}
				answerSocks(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestAClientReachesAServerThatHasNotBeenUpdated(t *testing.T) {
	const psk = "0123456789abcdef0123456789abcdef"
	addr := startLegacyServer(t, psk)

	cfg := baseParams("")
	cfg.ServerAddr = addr
	cfg.PSK = psk
	cfg.MTU = 1400
	// Bounds the one-in-thirty-thousand case where the old server reads the
	// v1 prologue as a frame length it is willing to wait for.
	cfg.HandshakeTimeout = 3 * time.Second
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy

	// The first connection speaks the current format. An old server reads
	// the prologue as a frame header, refuses it and closes: the client
	// sees a server that accepted the connection and then went quiet.
	_, used, err := dialTunnel(cfg, connectRequest())
	if err == nil {
		t.Fatal("an old server answered the current format")
	}
	if used.format != formatV1 {
		t.Fatalf("the first attempt spoke %s, want v1", used.format)
	}
	if phase := tunnelPhaseOf(err); phase != phaseGreeting {
		t.Fatalf("the failure was in phase %q, want greeting: %v", phase, err)
	}

	// The second speaks the previous format and gets through.
	conn, used, err := dialTunnel(cfg, connectRequest())
	if err != nil {
		t.Fatalf("the fallback to the previous format did not connect: %v", err)
	}
	defer conn.Close()
	if used.format != formatLegacy {
		t.Fatalf("the second attempt spoke %s, want legacy", used.format)
	}
	reply := make([]byte, 10)
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("CONNECT reply over the previous format: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("CONNECT reply %x", reply)
	}
}

func TestAPinnedLegacyClientSpeaksOnlyLegacy(t *testing.T) {
	const psk = "0123456789abcdef0123456789abcdef"
	addr := startLegacyServer(t, psk)

	cfg := baseParams("")
	cfg.ServerAddr = addr
	cfg.PSK = psk
	cfg.MTU = 1400
	cfg.Format = string(formatLegacy)
	cfg.HandshakeTimeout = 3 * time.Second
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy

	conn, used, err := dialTunnel(cfg, connectRequest())
	if err != nil {
		t.Fatalf("OBFS_FORMAT=legacy did not connect to an old server at the first attempt: %v", err)
	}
	defer conn.Close()
	if used.format != formatLegacy {
		t.Fatalf("spoke %s", used.format)
	}
}
