package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// throughClient is the client's accept loop for cp on a local port.
func throughClient(t *testing.T, cp clientParams) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); handleClient(c, cp, nil) }()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	return l.Addr().String()
}

func awaitTrue(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// gated answers the first upgrade with answer once the test opens the gate.
func gated(answer func(http.ResponseWriter, *http.Request)) (func(http.ResponseWriter, *http.Request), chan struct{}) {
	gate := make(chan struct{})
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		answer(w, r)
	}, gate
}

func forbidden(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }

// upgradedAndDeaf answers 101 and loses everything after it, as a front that
// does not pass early frames on.
func upgradedAndDeaf(w http.ResponseWriter, r *http.Request) {
	c, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
	_, _ = io.Copy(io.Discard, bufio.NewReader(c))
}

func optimisticBehind(t *testing.T, first func(http.ResponseWriter, *http.Request)) (clientParams, *clientPolicy, string, func() int32) {
	t.Helper()
	node, echo := earlyNode(t, "")
	cp, seen := front(t, node, first)
	cp.OptimisticConnect = true
	cp, policy := policed(t, cp)
	earlyData.Store(nativeKey(cp), time.Now())
	return cp, policy, echo, seen.Load
}

func noHint(t *testing.T, logs *syncBuffer) {
	t.Helper()
	if strings.Contains(logs.String(), "OBFS_PSK") {
		t.Fatalf("the early upgrade got the PSK hint:\n%s", logs)
	}
}

// An optimistic CONNECT whose early upgrade a front refuses is set up again
// the ordinary way behind the application's back: the server never upgraded,
// so it saw none of the request (markRetry).
func TestAnOptimisticConnectRefusedByAFrontReachesItsTarget(t *testing.T) {
	logs := captureLogs(t)
	answer, gate := gated(forbidden)
	cp, policy, echo, seen := optimisticBehind(t, answer)

	app, reply := socksConnect(t, throughClient(t, cp), echo, []byte("ping"))
	if !bytes.Equal(reply, successReply) {
		t.Fatalf("reply % x, want the early success", reply)
	}
	// The application's bytes are in the tunnel before the front refuses it.
	awaitTrue(t, "the early upgrade", func() bool { return seen() == 1 })
	time.Sleep(100 * time.Millisecond)
	close(gate)

	got := make([]byte, len("ping"))
	if _, err := io.ReadFull(app, got); err != nil || string(got) != "ping" {
		t.Fatalf("the application got %q, %v", got, err)
	}
	if _, err := app.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(app, got); err != nil || string(got) != "pong" {
		t.Fatalf("the relay after the repeat gave %q, %v", got, err)
	}
	if n := seen(); n != 2 {
		t.Fatalf("the front saw %d upgrades, want the refused one and its repeat", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the refusal moved the transport policy (%d failures)", n)
	}
	noHint(t, logs)
	if earlyDataKnown(cp) {
		t.Fatal("the node behind the refusing front is still dialled with early data")
	}
	if dialsEarly(t, cp) {
		t.Fatal("the next connection is dialled early")
	}
}

// A 101 is the front's as much as the server's, so silence after it proves
// nothing about the request: the application is reset rather than the
// request sent twice, and the policy does not hear of it.
func TestAnOptimisticConnectThatMeetsSilenceAfterTheUpgradeIsReset(t *testing.T) {
	logs := captureLogs(t)
	cp, policy, echo, seen := optimisticBehind(t, upgradedAndDeaf)
	cp.HandshakeTimeout = 500 * time.Millisecond

	app, reply := socksConnect(t, throughClient(t, cp), echo, []byte("ping"))
	if !bytes.Equal(reply, successReply) {
		t.Fatalf("reply % x, want the early success", reply)
	}
	_, err := app.Read(make([]byte, 16))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("the application saw %v, want a reset", err)
	}
	// The policy is told, if at all, before the failure is logged.
	awaitTrue(t, "the failure in the log", func() bool { return strings.Contains(logs.String(), "Tunnel setup") })
	if n := seen(); n != 1 {
		t.Fatalf("the front saw %d upgrades: silence after a 101 is not set up again", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the silence moved the transport policy (%d failures)", n)
	}
	noHint(t, logs)
	if !strings.Contains(logs.String(), "phase="+string(phaseEarlyUpgrade)) {
		t.Fatalf("the failure is not logged as %s:\n%s", phaseEarlyUpgrade, logs)
	}
	if earlyDataKnown(cp) {
		t.Fatal("the node behind the deaf front is still dialled with early data")
	}
}

// An upgrade cut without an answer may have reached the server, so it is
// not set up again either.
func TestAnOptimisticConnectWhoseUpgradeIsCutIsNotSetUpAgain(t *testing.T) {
	answer, gate := gated(func(w http.ResponseWriter, _ *http.Request) {
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
	})
	cp, policy, echo, seen := optimisticBehind(t, answer)

	app, reply := socksConnect(t, throughClient(t, cp), echo, []byte("ping"))
	if !bytes.Equal(reply, successReply) {
		t.Fatalf("reply % x, want the early success", reply)
	}
	awaitTrue(t, "the early upgrade", func() bool { return seen() == 1 })
	close(gate)
	_, err := app.Read(make([]byte, 16))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("the application saw %v, want a reset", err)
	}
	if n := seen(); n != 1 {
		t.Fatalf("the front saw %d upgrades: a cut upgrade is not set up again", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the cut early upgrade moved the transport policy (%d failures)", n)
	}
}

// udpRequestTo is a SOCKS5 UDP datagram for addr.
func udpRequestTo(addr *net.UDPAddr, payload string) []byte {
	d := append([]byte{0, 0, 0, addrIPv4}, addr.IP.To4()...)
	d = binary.BigEndian.AppendUint16(d, uint16(addr.Port))
	return append(d, payload...)
}

// The datagrams an association holds while its early upgrade is refused
// follow the request to the ordinary repeat (udpSetup.restart).
func TestAnAssociationRefusedByAFrontKeepsItsEarlyDatagrams(t *testing.T) {
	logs := captureLogs(t)
	answer, gate := gated(forbidden)
	cp, policy, _, seen := optimisticBehind(t, answer)
	echo := udpEcho(t).LocalAddr().(*net.UDPAddr)

	_, reply := associateThroughClient(t, cp)
	sender := appSocket(t)
	local := boundUDPPort(t, reply)
	awaitTrue(t, "the early upgrade", func() bool { return seen() == 1 })
	if _, err := sender.WriteToUDP(udpRequestTo(echo, "early"), local); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)

	_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sender.ReadFromUDP(buf)
	if err != nil || !bytes.HasSuffix(buf[:n], []byte("early")) {
		t.Fatalf("the early datagram was not answered: % x, %v", buf[:n], err)
	}
	if n := seen(); n != 2 {
		t.Fatalf("the front saw %d upgrades, want the refused one and its repeat", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the refusal moved the transport policy (%d failures)", n)
	}
	noHint(t, logs)
	if earlyDataKnown(cp) {
		t.Fatal("the node behind the refusing front is still dialled with early data")
	}
}

// An application that leaves before the 101 takes its association with it:
// the setup closed the tunnel, so nothing is set up again, nothing counts
// against the path, and the node keeps its early data.
func TestAnAssociationAbandonedBeforeTheUpgradeIsNotSetUpAgain(t *testing.T) {
	answer, gate := gated(forbidden)
	cp, policy, _, seen := optimisticBehind(t, answer)
	defer close(gate)

	app, client := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(client, cp, nil)
	}()
	_ = app.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := app.Write([]byte{socks5Ver, 1, socks5NoAuth}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(app, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte{socks5Ver, socks5.AssociateCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	readAppReply(t, app)
	awaitTrue(t, "the early upgrade", func() bool { return seen() == 1 })
	_ = app.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the association outlived its application")
	}
	if n := seen(); n != 1 {
		t.Fatalf("the front saw %d upgrades: an abandoned association is not set up again", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the abandoned setup moved the transport policy (%d failures)", n)
	}
	if !earlyDataKnown(cp) {
		t.Fatal("a close of our own made the client forget the node")
	}
}

// A spare has nothing to hurry: it is dialled the ordinary way even on a
// node that takes early data, so a spare that is taken is upgraded.
func TestAWSSSpareWaitsForTheUpgrade(t *testing.T) {
	node, _ := earlyNode(t, "")
	node.Prewarm = true
	earlyData.Store(nativeKey(node), time.Now())
	var p prewarmPool
	ctx, cancel := context.WithCancel(context.Background())
	p.start(ctx, node)
	t.Cleanup(func() { cancel(); p.stop() })

	for range 2 {
		c, _, err := p.take(node)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	var spare net.Conn
	awaitTrue(t, "the spare", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.spare != nil {
			spare = p.spare.conn
		}
		return spare != nil
	})
	if isEarly(spare) {
		t.Fatal("the spare was dialled early: it would be handed over before its upgrade is confirmed")
	}
}

// frontHolding refuses the first upgrade at once and holds every later one
// until hold is closed, then passes it to the node.
func frontHolding(t *testing.T, node clientParams, first func(http.ResponseWriter, *http.Request), hold chan struct{}) (clientParams, *atomic.Int32) {
	t.Helper()
	upstream := strings.TrimSuffix(strings.TrimPrefix(node.WSUrl, "wss://"), "/ws")
	var seen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) == 1 {
			first(w, r)
			return
		}
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
		up, err := tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = up.Close() }()
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		if err := r.Write(up); err != nil {
			return
		}
		go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		_, _ = io.Copy(up, brw.Reader)
	}))
	t.Cleanup(srv.Close)
	cp := node
	cp.WSUrl = "wss://" + srv.Listener.Addr().String() + "/ws"
	cp.rootCAs = x509.NewCertPool()
	cp.rootCAs.AddCert(srv.Certificate())
	freshEarlyData(t, cp)
	return cp, &seen
}

// A datagram that arrives while the repeat is being dialled is not written
// into the refused tunnel (udpSetup.restart): the association lives on after
// the repeat.
func TestADatagramDuringTheRepeatDoesNotEndTheAssociation(t *testing.T) {
	hold := make(chan struct{})
	node, _ := earlyNode(t, "")
	cp, seen := frontHolding(t, node, forbidden, hold)
	cp.OptimisticConnect = true
	earlyData.Store(nativeKey(cp), time.Now())
	echo := udpEcho(t).LocalAddr().(*net.UDPAddr)

	app, reply := associateThroughClient(t, cp)
	sender := appSocket(t)
	local := boundUDPPort(t, reply)
	awaitTrue(t, "the repeat", func() bool { return seen.Load() == 2 })
	if _, err := sender.WriteToUDP(udpRequestTo(echo, "during"), local); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	close(hold)

	buf := make([]byte, 2048)
	for _, p := range []string{"during", "after"} {
		if p == "after" {
			if _, err := sender.WriteToUDP(udpRequestTo(echo, p), local); err != nil {
				t.Fatal(err)
			}
		}
		_ = sender.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := sender.ReadFromUDP(buf)
		if err != nil || !bytes.HasSuffix(buf[:n], []byte(p)) {
			t.Fatalf("%s was not answered: % x, %v", p, buf[:n], err)
		}
	}
	_ = app.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := app.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Fatalf("the association ended: %v", err)
	}
}

// badAccept answers 101 with a wrong Sec-WebSocket-Accept: something upgraded
// on the path, so the early frames may have gone on.
func badAccept(w http.ResponseWriter, _ *http.Request) {
	c, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n")
	_, _ = io.Copy(io.Discard, bufio.NewReader(c))
}

// A 101 the client rejects is not a refusal: the path switched, and the
// request may have reached the server.
func TestA101WithABadAcceptIsNotSetUpAgain(t *testing.T) {
	cp, _, echo, seen := optimisticBehind(t, badAccept)
	app, reply := socksConnect(t, throughClient(t, cp), echo, []byte("ping"))
	if !bytes.Equal(reply, successReply) {
		t.Fatalf("reply % x, want the early success", reply)
	}
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(app)
	if n := seen(); n != 1 {
		t.Fatalf("the front saw %d upgrades: a 101 is not proof the request stayed behind", n)
	}
}

// A repeat of an early upgrade is not a spare's: the prewarm counters stay.
func TestAnEarlyRepeatCountsNoSpare(t *testing.T) {
	wasted, used := minutes.prewarmWasted.Load(), minutes.prewarmUsed.Load()
	answer, gate := gated(forbidden)
	close(gate)
	cp, _, echo, seen := optimisticBehind(t, answer)
	cp.OptimisticConnect = false
	app, _ := socksConnect(t, throughClient(t, cp), echo, []byte("ping"))
	buf := make([]byte, 4)
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(app, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("the application got %q, %v", buf, err)
	}
	if n := seen(); n != 2 {
		t.Fatalf("the front saw %d upgrades, want the refused one and its repeat", n)
	}
	if minutes.prewarmWasted.Load() != wasted || minutes.prewarmUsed.Load() != used {
		t.Fatal("an early repeat counted a spare")
	}
}

// A dead WSS spare on a node that takes early data is set up again waiting
// for the 101, as every repeat is.
func TestADeadWSSSpareIsRepeatedWaitingForTheUpgrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newCountingServer(t)
		var mu sync.Mutex
		var waited []bool
		counted := dialServer
		dialServer = func(cfg clientParams) (net.Conn, error) {
			mu.Lock()
			waited = append(waited, cfg.awaitUpgrade)
			mu.Unlock()
			return counted(cfg)
		}
		cfg := prewarmParams(true)
		cfg.Transport = "ws"
		cfg.WSUrl = "wss://198.51.100.3/ws"
		freshEarlyData(t, cfg)
		earlyData.Store(nativeKey(cfg), time.Now())
		spareFrom(t, server, cfg, readAllOnceAndHangUp)
		server.setServe(answer(t, cfg))

		mu.Lock()
		before := len(waited)
		mu.Unlock()
		conn, err := dialObfsTunnel(cfg, connectRequest())
		if err != nil {
			t.Fatalf("the tunnel on the dead spare was not set up again: %v", err)
		}
		_ = conn.Close()
		if !earlyDataKnown(cfg) {
			t.Fatal("a dead spare made the client forget the node")
		}
		mu.Lock()
		defer mu.Unlock()
		if len(waited) == before || !waited[before] {
			t.Fatalf("the repeat did not wait for the upgrade (dials since the spare: %v)", waited[before:])
		}
	})
}
