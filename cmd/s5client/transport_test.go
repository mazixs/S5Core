package main

import (
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/mazixs/S5Core/internal/buildinfo"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-7, the client's half: "the transport profile of a client in
// the field changes without replacing the binary". These tests pin the
// decision the policy makes before every dial - from the environment, from
// the server's advice, and from what has just failed - and then run one
// real tunnel to show the hello going up and the advice coming down.

// fakeClock lets a test move the policy's idea of time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// policyFor builds a policy from the configuration and puts it on a fake
// clock, so a cooldown can be waited out without waiting.
func policyFor(t *testing.T, cfg clientParams) (*clientPolicy, *fakeClock) {
	t.Helper()
	p, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatalf("newClientPolicy: %v", err)
	}
	clock := &fakeClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	p.now = clock.now
	return p, clock
}

// baseParams is a configuration with every shape setting at a recognisable
// value, so a test can see which ones an advice changed.
func baseParams(wsURL string) clientParams {
	return clientParams{
		ServerAddr:        "203.0.113.10:1443",
		WSUrl:             wsURL,
		MaxPadding:        256,
		WSMinFrame:        256,
		WSMaxFrame:        4096,
		WSMaxJitterMs:     0,
		KeepaliveMin:      10 * time.Second,
		KeepaliveMax:      20 * time.Second,
		TransportCooldown: 5 * time.Minute,
	}
}

func TestTheTransportPolicyIsReadFromTheEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		transport   string
		format      string
		wsURL       string
		wantErr     string
		wantPinned  transportKind
		wantDefault transportKind
	}{
		{name: "auto without WS_URL", transport: "auto", format: "auto", wantDefault: transportObfs},
		{name: "auto with WS_URL", transport: "auto", format: "auto", wsURL: "wss://cdn.example/ws", wantDefault: transportWS},
		{name: "empty is auto", wantDefault: transportObfs},
		{name: "obfs pinned beside WS_URL", transport: "obfs", wsURL: "wss://cdn.example/ws", wantPinned: transportObfs, wantDefault: transportWS},
		{name: "ws pinned", transport: "ws", wsURL: "wss://cdn.example/ws", wantPinned: transportWS, wantDefault: transportWS},
		{name: "ws pinned without WS_URL", transport: "ws", wantErr: "WS_URL"},
		{name: "a transport this build does not know", transport: "quic", wantErr: "TRANSPORT"},
		{name: "v1 is the current format", format: "v1", wantDefault: transportObfs},
		{name: "legacy was removed", format: "legacy", wantErr: "removed in 2.2"},
		{name: "a format this build does not know", format: "v3", wantErr: "OBFS_FORMAT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseParams(tt.wsURL)
			cfg.Transport, cfg.Format = tt.transport, tt.format
			p, err := newClientPolicy(cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %v, want an error naming %s", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if p.pinned != tt.wantPinned || p.configured() != tt.wantDefault {
				t.Fatalf("pinned=%q default=%q, want %q/%q", p.pinned, p.configured(), tt.wantPinned, tt.wantDefault)
			}
		})
	}
}

func TestTheClientSendsOnlyThePrintableOpening(t *testing.T) {
	for _, ok := range []string{"", "printable"} {
		if err := checkPrologue(ok); err != nil {
			t.Errorf("OBFS_PROLOGUE=%q refused: %v", ok, err)
		}
	}
	if err := checkPrologue("raw"); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Errorf("OBFS_PROLOGUE=raw: got %v, want the removal named", err)
	}
	if err := checkPrologue("base32"); err == nil {
		t.Error("an unknown encoding was accepted")
	}
}

func TestAnAutoClientFollowsTheServersAdvice(t *testing.T) {
	base := baseParams("wss://cdn.example/ws")
	p, _ := policyFor(t, base)

	// With no advice: the configured default, the configured shape.
	got := p.apply(base)
	if got.transport != transportWS || got.MaxPadding != 256 {
		t.Fatalf("before any advice: transport=%s padding=%d", got.transport, got.MaxPadding)
	}

	// The server would rather see obfs with less padding and a slower
	// keepalive. Everything it did not mention stays as configured.
	p.onAdvice(obfs.Advice{Transport: "obfs", MaxPadding: 64, KeepaliveMin: 12 * time.Second, KeepaliveMax: 24 * time.Second})
	got = p.apply(base)
	if got.transport != transportObfs {
		t.Fatalf("the advised transport was not followed: %s", got.transport)
	}
	if got.MaxPadding != 64 || got.KeepaliveMin != 12*time.Second || got.KeepaliveMax != 24*time.Second {
		t.Fatalf("the advised shape was not applied: padding=%d keepalive=%s-%s", got.MaxPadding, got.KeepaliveMin, got.KeepaliveMax)
	}
	if got.WSMinFrame != 256 || got.WSMaxFrame != 4096 {
		t.Fatalf("fields the advice left out were changed: frames %d-%d", got.WSMinFrame, got.WSMaxFrame)
	}

	// The next advice replaces the previous one whole: padding goes back
	// to the configured value because the new advice does not mention it.
	p.onAdvice(obfs.Advice{Transport: "ws", WSMinFrame: 512, WSMaxFrame: 2048, WSMaxJitterMs: 3})
	got = p.apply(base)
	if got.transport != transportWS || got.WSMinFrame != 512 || got.WSMaxFrame != 2048 || got.WSMaxJitterMs != 3 {
		t.Fatalf("the second advice was not applied: transport=%s frames=%d-%d jitter=%d", got.transport, got.WSMinFrame, got.WSMaxFrame, got.WSMaxJitterMs)
	}
	if got.MaxPadding != 256 {
		t.Fatalf("padding %d survived an advice that did not mention it", got.MaxPadding)
	}
}

func TestAnAdviceForATransportTheClientCannotReachIsNotFollowed(t *testing.T) {
	// No WS_URL: the client has nowhere to send a WebSocket, however much
	// the server would like one. The shape is still taken.
	base := baseParams("")
	p, _ := policyFor(t, base)
	p.onAdvice(obfs.Advice{Transport: "ws", MaxPadding: 32})
	got := p.apply(base)
	if got.transport != transportObfs {
		t.Fatalf("a client without WS_URL chose %s", got.transport)
	}
	if got.MaxPadding != 32 {
		t.Fatalf("the shape of an advice whose transport could not be followed was dropped: padding=%d", got.MaxPadding)
	}
}

func TestAPinnedTransportIgnoresTheAdvisedTransportButTakesTheShape(t *testing.T) {
	base := baseParams("wss://cdn.example/ws")
	base.Transport = "obfs"
	p, clock := policyFor(t, base)

	p.onAdvice(obfs.Advice{Transport: "ws", MaxPadding: 16})
	got := p.apply(base)
	if got.transport != transportObfs {
		t.Fatalf("TRANSPORT=obfs was overridden by advice: %s", got.transport)
	}
	if got.MaxPadding != 16 {
		t.Fatalf("a pinned client dropped the advised shape: padding=%d", got.MaxPadding)
	}

	// Nor does a failure move a pinned client: the operator chose.
	p.onFailure(got, phaseDial)
	clock.advance(time.Second)
	if got = p.apply(base); got.transport != transportObfs {
		t.Fatalf("a pinned transport was abandoned after a failure: %s", got.transport)
	}
}

func TestAFailedTransportRestsWhileTheOtherIsTried(t *testing.T) {
	base := baseParams("wss://cdn.example/ws")
	p, clock := policyFor(t, base)

	first := p.apply(base)
	if first.transport != transportWS {
		t.Fatalf("the configured default is ws, got %s", first.transport)
	}

	// The WebSocket port is blocked: the dial fails. The next connection
	// goes over obfs, and keeps going there for the cooldown.
	p.onFailure(first, phaseDial)
	if got := p.apply(base); got.transport != transportObfs {
		t.Fatalf("after a failed dial the client stayed on %s", got.transport)
	}
	clock.advance(base.TransportCooldown - time.Second)
	if got := p.apply(base); got.transport != transportObfs {
		t.Fatalf("the cooldown ended early: %s", got.transport)
	}
	clock.advance(2 * time.Second)
	if got := p.apply(base); got.transport != transportWS {
		t.Fatalf("after the cooldown the client did not go back to %s: %s", transportWS, got.transport)
	}

	// A destination that refuses the CONNECT says nothing about the path:
	// no rest.
	p.onFailure(p.apply(base), phaseConnectReply)
	if got := p.apply(base); got.transport != transportWS {
		t.Fatalf("a CONNECT failure moved the client to %s", got.transport)
	}

	// The server accepting the connection and never answering does count.
	p.onFailure(p.apply(base), phaseGreeting)
	if got := p.apply(base); got.transport != transportObfs {
		t.Fatalf("a silent server did not move the client: %s", got.transport)
	}

	// Both resting: the preferred one is tried anyway rather than nothing.
	p.onFailure(p.apply(base), phaseDial)
	if got := p.apply(base); got.transport != transportWS {
		t.Fatalf("with both transports resting the client chose %s, want the preferred %s", got.transport, transportWS)
	}

	// A success clears the record at once.
	p.onSuccess(clientParams{transport: transportWS})
	p.onSuccess(clientParams{transport: transportObfs})
	p.onFailure(clientParams{transport: transportWS}, phaseDial)
	if got := p.apply(base); got.transport != transportObfs {
		t.Fatalf("obfs was still resting after its success: %s", got.transport)
	}
}

func TestACooldownOfZeroTurnsTheSwitchOff(t *testing.T) {
	base := baseParams("wss://cdn.example/ws")
	base.TransportCooldown = 0
	p, _ := policyFor(t, base)
	p.onFailure(p.apply(base), phaseDial)
	if got := p.apply(base); got.transport != transportWS {
		t.Fatalf("TRANSPORT_COOLDOWN=0 still switched transports: %s", got.transport)
	}
}

func TestAnUnusableAdviceIsDroppedWhole(t *testing.T) {
	bad := []obfs.Advice{
		{Transport: "quic"},
		{WSMinFrame: 512},
		{WSMaxFrame: 512},
		{WSMinFrame: 2048, WSMaxFrame: 512},
		{KeepaliveMin: 10 * time.Second},
		{KeepaliveMin: 20 * time.Second, KeepaliveMax: 10 * time.Second},
		{KeepaliveMin: time.Second, KeepaliveMax: 2 * time.Hour},
		{MaxPadding: 5000},
		{WSMaxJitterMs: 90_000},
	}
	for _, a := range bad {
		if err := checkAdvice(a); err == nil {
			t.Errorf("advice %+v was accepted", a)
		}
	}

	base := baseParams("")
	p, _ := policyFor(t, base)
	p.onAdvice(obfs.Advice{Transport: "obfs", MaxPadding: 5000})
	if got := p.apply(base); got.MaxPadding != 256 {
		t.Fatalf("part of an unusable advice was applied: padding=%d", got.MaxPadding)
	}
}

// startAdvisingServer is a server end of the tunnel with the given control
// settings, answering the SOCKS5 greeting and CONNECT of every connection.
func startAdvisingServer(t *testing.T, psk string, serverCfg obfs.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serverCfg.PSK = []byte(psk)
	serverCfg.MTU = 1400
	if serverCfg.Scheme == nil {
		serverCfg.Scheme = &veil.Clocked{Accepts: everyCipher()}
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, err := obfs.NewServerConn(raw, serverCfg)
				if err != nil {
					return
				}
				answerSocks(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// answerSocks plays a server that accepts anything: greeting, then CONNECT.
func answerSocks(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if n <= 3 {
		// The CONNECT was not pipelined behind the greeting.
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	// Keep the tunnel until the client is done with it.
	_, _ = io.Copy(io.Discard, conn)
}

func TestTheHelloGoesUpAndTheAdviceComesDownOneRealTunnel(t *testing.T) {
	const psk = "0123456789abcdef0123456789abcdef"
	hellos := make(chan obfs.Hello, 4)
	addr := startAdvisingServer(t, psk, obfs.Config{
		OnHello: func(h obfs.Hello) { hellos <- h },
		Advice:  &obfs.Advice{Transport: "obfs", MaxPadding: 48, KeepaliveMin: 11 * time.Second, KeepaliveMax: 22 * time.Second},
	})

	cfg := baseParams("")
	cfg.ServerAddr = addr
	cfg.PSK = psk
	cfg.MTU = 1400
	cfg.HandshakeTimeout = 5 * time.Second
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy

	conn, used, err := dialTunnel(cfg, connectRequest())
	if err != nil {
		t.Fatalf("dialTunnel: %v", err)
	}
	defer conn.Close()

	// The connection that carried the advice was made as configured...
	if used.MaxPadding != 256 || used.transport != transportObfs {
		t.Fatalf("the first attempt used padding=%d transport=%s", used.MaxPadding, used.transport)
	}
	// ...and the server learnt which build it is talking to.
	select {
	case h := <-hellos:
		if h.Version != buildinfo.Version() || h.Transport != string(transportObfs) {
			t.Fatalf("the server saw %+v, want version %q on obfs", h, buildinfo.Version())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no hello reached the server")
	}

	// The next connection is shaped as the server asked.
	next := policy.apply(cfg)
	if next.MaxPadding != 48 || next.KeepaliveMin != 11*time.Second || next.KeepaliveMax != 22*time.Second {
		t.Fatalf("the advice did not reach the next attempt: padding=%d keepalive=%s-%s", next.MaxPadding, next.KeepaliveMin, next.KeepaliveMax)
	}
}

// TestClientDefaultsMatchTheLibraries is the drift check the plan asks for
// under "no shape constant in the code": the client's defaults are written
// in its environment tags, and this makes sure they are the same numbers the
// transport and obfuscation packages call their defaults.
func TestClientDefaultsMatchTheLibraries(t *testing.T) {
	var cfg clientParams
	if err := env.ParseWithOptions(&cfg, env.Options{Environment: map[string]string{}}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"WS_MIN_FRAME", cfg.WSMinFrame, ws.DefaultMinFrame},
		{"WS_MAX_FRAME", cfg.WSMaxFrame, ws.DefaultMaxFrame},
		{"OBFS_MTU", cfg.MTU, obfs.DefaultMTU},
		{"KEEPALIVE_MIN", cfg.KeepaliveMin, obfs.DefaultKeepaliveMin},
		{"KEEPALIVE_MAX", cfg.KeepaliveMax, obfs.DefaultKeepaliveMax},
		{"TRANSPORT", cfg.Transport, string(transportAuto)},
		{"OBFS_FORMAT", cfg.Format, "auto"},
		{"OBFS_PROLOGUE", cfg.Prologue, string(obfs.DefaultPrologueEncoding)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s defaults to %v, the library says %v", c.name, c.got, c.want)
		}
	}
}

// A rejected password is an answer, and an answer says the path worked. The
// client used to treat it as "the server did not understand this format":
// one typo moved every following connection onto the previous wire format
// for the whole reprobe window - a format the server no longer accepts - and
// the log blamed the PSK and the clock. The failure here must move nothing.
func TestARejectedPasswordDoesNotMoveTheTransport(t *testing.T) {
	base := baseParams("wss://cdn.example/ws")
	p, _ := policyFor(t, base)

	attempt := p.apply(base)
	if attempt.transport != transportWS {
		t.Fatalf("unexpected first attempt: %s", attempt.transport)
	}

	p.onFailure(attempt, phaseAuthRejected)

	next := p.apply(base)
	if next.transport != transportWS {
		t.Errorf("a rejected password moved the client to %s", next.transport)
	}

	// The silent case still counts: that one really can be a path or a
	// PSK that does not match.
	p.onFailure(next, phaseAuth)
	if got := p.apply(base); got.transport != transportObfs {
		t.Errorf("a silent server left the client on %s", got.transport)
	}
}

// The hint about the PSK, the node id and the clock exists for a server that
// goes quiet. A server that answers "wrong password" has ruled all three out,
// so naming them there sends the operator after the wrong thing.
func TestTheSilentServerHintIsNotPrintedForARejection(t *testing.T) {
	cfg := baseParams("")
	cfg.PSK = "0123456789abcdef0123456789abcdef"

	rejected := &tunnelError{phase: phaseAuthRejected, err: errAuthRejected}
	if hint := setupHint(rejected, cfg); hint != "" {
		t.Errorf("a rejection carried the silent-server hint: %s", hint)
	}

	silent := &tunnelError{phase: phaseAuth, err: os.ErrDeadlineExceeded}
	if hint := setupHint(silent, cfg); hint == "" {
		t.Error("a silent server carried no hint at all")
	}
}
