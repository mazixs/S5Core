package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// The application is told its port before the server answers, and what it
// sends meanwhile goes into the tunnel behind the request rather than waiting
// for the reply (docs/plan/draft.md, Ч-3; docs/veil-spec.md, 10.2).
func TestDatagramsBeforeTheServerReplyGoBehindTheRequest(t *testing.T) {
	app, tunnel, _ := startUDPAssociate(t)

	// The server has written nothing yet.
	reply := readAppReply(t, app)
	if reply[1] != 0x00 {
		t.Fatalf("the application was answered % x, want success", reply)
	}
	sender := appSocket(t)
	local := boundUDPPort(t, reply)
	early := []string{"first", "second"}
	for _, p := range early {
		if _, err := sender.WriteToUDP(datagram(p), local); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range early {
		expectFrame(t, tunnel, datagram(p))
	}

	if _, err := tunnel.Write(append(bytes.Clone(udpTunnelReply), tunnelFrame(datagram("answer"))...)); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, sender, datagram("answer"))

	// After the reply the reader sends by itself.
	if _, err := sender.WriteToUDP(datagram("later"), local); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, tunnel, datagram("later"))
}

// associateThroughClient runs an association the way the accept loop does
// and returns the application's connection and the reply it got.
func associateThroughClient(t *testing.T, cfg clientParams) (net.Conn, []byte) {
	t.Helper()
	app, client := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(client, cfg, nil)
	}()
	t.Cleanup(func() {
		_ = app.Close()
		<-done
	})
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
	reply := readAppReply(t, app)
	if reply[1] != 0x00 {
		t.Fatalf("the application was answered % x", reply)
	}
	return app, reply
}

// On the wire the first datagram follows the request in the same flight: the
// server reads it before it has written its method reply, so the client did
// not wait for that either.
func TestTheFirstDatagramFollowsTheRequestOnTheWire(t *testing.T) {
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	serverSide := pipeServer(t)
	_, reply := associateThroughClient(t, cfg)
	sender := appSocket(t)
	if _, err := sender.WriteToUDP(datagram("first"), boundUDPPort(t, reply)); err != nil {
		t.Fatal(err)
	}

	server := obfsServerSide(t, <-serverSide, cfg)
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	head := make([]byte, 3+10)
	if _, err := io.ReadFull(server, head); err != nil {
		t.Fatalf("the greeting and the request: %v", err)
	}
	if head[4] != socks5.UDPTunnelCommand {
		t.Fatalf("the request is % x, want 0x83", head[3:])
	}
	expectFrame(t, server, datagram("first"))

	if _, err := server.Write(append([]byte{socks5Ver, socks5NoAuth}, udpTunnelReply...)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(tunnelFrame(datagram("answer"))); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, sender, datagram("answer"))
}

// With a login the client waits for the server to choose the method, then
// sends the login and the request together, and the datagrams follow them.
func TestTheFirstDatagramFollowsTheLoginOnTheWire(t *testing.T) {
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	cfg.ProxyUser, cfg.ProxyPass = "alice", "secret"
	serverSide := pipeServer(t)
	_, reply := associateThroughClient(t, cfg)
	sender := appSocket(t)
	if _, err := sender.WriteToUDP(datagram("first"), boundUDPPort(t, reply)); err != nil {
		t.Fatal(err)
	}

	server := obfsServerSide(t, <-serverSide, cfg)
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	greeting := make([]byte, 4)
	if _, err := io.ReadFull(server, greeting); err != nil {
		t.Fatalf("the greeting: %v", err)
	}
	if _, err := server.Write([]byte{socks5Ver, socks5UserPassAuth}); err != nil {
		t.Fatal(err)
	}
	login := buildUserPassAuthPacket(cfg.ProxyUser, cfg.ProxyPass)
	got := make([]byte, len(login)+10)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("the login and the request: %v", err)
	}
	if !bytes.Equal(got[:len(login)], login) || got[len(login)+1] != socks5.UDPTunnelCommand {
		t.Fatalf("the server got % x, want the login and a 0x83 request", got)
	}
	expectFrame(t, server, datagram("first"))

	if _, err := server.Write(append([]byte{0x01, 0x00}, udpTunnelReply...)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(tunnelFrame(datagram("answer"))); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, sender, datagram("answer"))
}

// fakeTunnels opens a TCP pair per dial, writes the request and hands the
// server's end of each to the test in the order they were opened.
func fakeTunnels(t *testing.T) (tunnelDial, chan net.Conn) {
	servers := make(chan net.Conn, 4)
	return func(cfg clientParams, req []byte) (net.Conn, clientParams, error) {
		client, server := tcpPair(t)
		servers <- server
		if _, err := client.Write(req); err != nil {
			return nil, cfg, err
		}
		cfg.sentRequest(client)
		return client, cfg, nil
	}, servers
}

func nextTunnel(t *testing.T, servers chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-servers:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no tunnel was opened")
		return nil
	}
}

// A server that predates 0x84 refuses it and drops what followed the request,
// so the datagrams sent behind it go again behind the 0x83 that replaces it.
func TestARefusedNativeRequestHandsItsDatagramsToTheRetry(t *testing.T) {
	cfg := clientParams{ServerAddr: "198.51.100.84:1443", UDPNative: true, OptimisticConnect: true}
	t.Cleanup(func() { noNative.Delete(nativeKey(cfg)) })
	dial, servers := fakeTunnels(t)

	app, handlerSide := tcpPair(t)
	req := []byte{socks5Ver, socks5.UDPNativeCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	runUDPAssociate(t, handlerSide, "", cfg, req, dial)
	reply := readAppReply(t, app)
	sender := appSocket(t)
	local := boundUDPPort(t, reply)
	early := []string{"one", "two"}
	for _, p := range early {
		if _, err := sender.WriteToUDP(datagram(p), local); err != nil {
			t.Fatal(err)
		}
	}

	first := nextTunnel(t, servers)
	expectRequest(t, first, socks5.UDPNativeCommand)
	for _, p := range early {
		expectFrame(t, first, datagram(p))
	}
	// A 2.2 server: its command rule refuses what it does not know.
	if _, err := first.Write([]byte{socks5Ver, 0x02, 0, addrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}

	second := nextTunnel(t, servers)
	expectRequest(t, second, socks5.UDPTunnelCommand)
	for _, p := range early {
		expectFrame(t, second, datagram(p))
	}
	if _, err := second.Write(append(bytes.Clone(udpTunnelReply), tunnelFrame(datagram("answer"))...)); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, sender, datagram("answer"))
	if got := udpCommandFor(cfg); got != socks5.UDPTunnelCommand {
		t.Fatalf("the server that took 0x83 is asked %#x next, want 0x83", got)
	}
}

// What is held for a second connection is bounded. Past the bound a datagram
// still follows a request that is out, and is lost when the request it
// followed is refused or when no request is out yet.
func TestTheEarlyQueueIsBounded(t *testing.T) {
	t.Run("0x84", func(t *testing.T) {
		e := udpSetup{retry: true}
		for range earlyQueueDatagrams + 8 {
			e.add(datagram("x"))
		}
		client, server := tcpPair(t)
		e.attach(client)
		for range earlyQueueDatagrams {
			expectFrame(t, server, datagram("x"))
		}
		if fate := e.add(datagram("past the bound")); fate != earlyTaken {
			t.Fatalf("a datagram behind a request that is out: %v", fate)
		}
		expectFrame(t, server, datagram("past the bound"))
		e.detach()
		got := e.close()
		if got.taken != earlyQueueDatagrams+9 || got.lost != 9 {
			t.Fatalf("taken %d, lost %d; want %d and 9", got.taken, got.lost, earlyQueueDatagrams+9)
		}
		// Only what reached the next request counts as sent.
		if want := earlyQueueDatagrams * len(datagram("x")); got.sentBytes != want {
			t.Fatalf("sent %d bytes, want %d", got.sentBytes, want)
		}
	})
	t.Run("0x84 accepted", func(t *testing.T) {
		e := udpSetup{retry: true}
		e.add(datagram("x"))
		client, server := tcpPair(t)
		e.attach(client)
		expectFrame(t, server, datagram("x"))
		e.accepted()
		for range 2 * earlyQueueDatagrams {
			e.add(datagram("y"))
		}
		if len(e.queue) != 0 {
			t.Fatalf("%d datagrams held behind an accepted request", len(e.queue))
		}
		for range 2 * earlyQueueDatagrams {
			expectFrame(t, server, datagram("y"))
		}
	})
	t.Run("0x83", func(t *testing.T) {
		e := udpSetup{}
		for range earlyQueueDatagrams + 8 {
			e.add(datagram("x"))
		}
		client, server := tcpPair(t)
		e.attach(client)
		for range earlyQueueDatagrams {
			expectFrame(t, server, datagram("x"))
		}
		// There is no second request to keep them for.
		for range 2 * earlyQueueDatagrams {
			e.add(datagram("y"))
		}
		if len(e.queue) != 0 {
			t.Fatalf("%d datagrams held behind a 0x83 request", len(e.queue))
		}
		for range 2 * earlyQueueDatagrams {
			expectFrame(t, server, datagram("y"))
		}
		if got := e.close(); got.taken != 3*earlyQueueDatagrams+8 || got.lost != 8 {
			t.Fatalf("taken %d, lost %d; want %d and 8", got.taken, got.lost, 3*earlyQueueDatagrams+8)
		}
		if e.add(datagram("z")) != notEarly {
			t.Fatal("a closed setup took a datagram")
		}
	})
}

// Early datagrams are counted where the closing line counts the rest, and a
// write that fails is what the log names.
func TestAFailedEarlyWriteIsWhatTheLogNames(t *testing.T) {
	logs := captureLogs(t)
	dial := func(cfg clientParams, _ []byte) (net.Conn, clientParams, error) {
		c, s := tcpPair(t)
		failing := &failingWrites{Conn: c}
		cfg.sentRequest(failing)
		_ = s
		return failing, cfg, nil
	}
	app, handlerSide := tcpPair(t)
	done := runUDPAssociate(t, handlerSide, "example.com", clientParams{OptimisticConnect: true}, nil, dial)
	reply := readAppReply(t, app)
	if _, err := appSocket(t).WriteToUDP(datagram("first"), boundUDPPort(t, reply)); err != nil {
		t.Fatal(err)
	}
	associationEnded(t, app, done)
	if logged(logs, `msg="Tunnel setup failed"`, "writing a datagram behind the request", "broken pipe") != 1 {
		t.Fatalf("the failed write was logged as:\n%s", logs)
	}
}

// failingWrites refuses every write the way a reset connection does.
type failingWrites struct{ net.Conn }

func (c *failingWrites) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A datagram whose write fails after the server has accepted the request
// leaves a closed tunnel: the association ends there rather than starting
// on it and ending at once as closed by the tunnel.
func TestAWriteThatFailsAfterTheReplyEndsTheSetup(t *testing.T) {
	logs := captureLogs(t)
	replyRead := make(chan struct{})
	tunnel := &failsAfterReply{remaining: len(udpTunnelReply), read: replyRead, failed: make(chan struct{})}
	dial := func(cfg clientParams, _ []byte) (net.Conn, clientParams, error) {
		c, s := tcpPair(t)
		tunnel.Conn = c
		cfg.sentRequest(tunnel)
		if _, err := s.Write(udpTunnelReply); err != nil {
			t.Error(err)
		}
		return tunnel, cfg, nil
	}
	app, handlerSide := tcpPair(t)
	done := runUDPAssociate(t, handlerSide, "example.com", clientParams{OptimisticConnect: true}, nil, dial)
	local := boundUDPPort(t, readAppReply(t, app))
	<-replyRead
	if _, err := appSocket(t).WriteToUDP(datagram("first"), local); err != nil {
		t.Fatal(err)
	}
	associationEnded(t, app, done)
	if logged(logs, `msg="Tunnel setup failed"`, "writing a datagram behind the request", "broken pipe") != 1 {
		t.Fatalf("the failed write was logged as:\n%s", logs)
	}
	if strings.Contains(logs.String(), "UDP Tunnel established") {
		t.Fatalf("the association started on a closed tunnel:\n%s", logs)
	}
}

// failsAfterReply holds the read that completes the reply until a write has
// failed, which puts the failure between the reply and the end of setup.
type failsAfterReply struct {
	net.Conn
	remaining int
	read      chan struct{}
	failed    chan struct{}
	once      sync.Once
}

func (c *failsAfterReply) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.remaining -= n
	if c.remaining == 0 && c.read != nil {
		close(c.read)
		c.read = nil
		<-c.failed
	}
	return n, err
}

func (c *failsAfterReply) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.failed) })
	return 0, errors.New("broken pipe")
}

// The setup closes a tunnel for an application that left only while the
// setup lasts, and only a tunnel it closed is one the policy is not told of.
func TestOnlyATunnelTheSetupClosedIsExcused(t *testing.T) {
	t.Run("before the request", func(t *testing.T) {
		e := udpSetup{}
		e.abandon()
		if e.abandoned() {
			t.Fatal("a departure with no tunnel yet excuses the failure of the dial")
		}
		client, server := tcpPair(t)
		e.attach(client)
		if !e.abandoned() {
			t.Fatal("the tunnel of an application that left was not closed")
		}
		expectClosed(t, server)
	})
	t.Run("after the setup", func(t *testing.T) {
		e := udpSetup{}
		client, server := tcpPair(t)
		e.attach(client)
		e.close()
		e.abandon()
		if e.abandoned() {
			t.Fatal("a departure after the setup was taken for one during it")
		}
		_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var b [1]byte
		if _, err := server.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the setup closed a tunnel it no longer owned: %v", err)
		}
	})
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("the tunnel is open: %v", err)
	}
}

// A dial that fails before any request is out is a failure of the path even
// when the application has left meanwhile: a short association, a DNS query
// with a five second timeout, would otherwise hide a dead transport.
func TestADialThatFailsAfterTheApplicationLeftStillCounts(t *testing.T) {
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	cfg.TransportCooldown = time.Minute
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerAddr = closed.Addr().String()
	_ = closed.Close()
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy

	app, handlerSide := tcpPair(t)
	left := make(chan struct{})
	dial := func(cfg clientParams, req []byte) (net.Conn, clientParams, error) {
		<-left
		setup := cfg.setup.(*udpSetup)
		for deadline := time.Now().Add(5 * time.Second); !setup.hasLeft(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Error("the setup never saw the application leave")
				break
			}
		}
		return dialAttempt(cfg, req)
	}
	req := []byte{socks5Ver, socks5.UDPTunnelCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	done := runUDPAssociate(t, handlerSide, "example.com", cfg.attempt(), req, dial)
	readAppReply(t, app)
	_ = app.Close()
	close(left)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the association outlived its application")
	}
	policy.mu.Lock()
	failures := len(policy.failedAt)
	policy.mu.Unlock()
	if failures != 1 {
		t.Fatalf("the transport policy recorded %d failures, want 1", failures)
	}
}

// A tunnel that cannot be opened ends the association: the application's
// connection and its UDP port are closed and nothing of it keeps running.
func TestAFailedDialEndsTheAssociation(t *testing.T) {
	logs := captureLogs(t)
	dial := func(cfg clientParams, _ []byte) (net.Conn, clientParams, error) {
		return nil, cfg, &tunnelError{phase: phaseDial, err: errors.New("connection refused")}
	}
	app, handlerSide := tcpPair(t)
	done := runUDPAssociate(t, handlerSide, "example.com", clientParams{OptimisticConnect: true}, nil, dial)
	local := boundUDPPort(t, readAppReply(t, app))
	associationEnded(t, app, done)

	freed, err := net.ListenUDP("udp", local)
	if err != nil {
		t.Fatalf("the association's UDP port is still taken: %v", err)
	}
	_ = freed.Close()
	if logged(logs, `msg="Tunnel setup failed"`, "phase=dial") != 1 {
		t.Fatalf("the failure was logged as:\n%s", logs)
	}
	noGoroutineOf(t, "main.associateUDP")
}

// noGoroutineOf waits for every goroutine started by fn to end.
func noGoroutineOf(t *testing.T, fn string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for {
		stacks := string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(stacks, fn) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines of %s are still running:\n%s", fn, stacks)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An application that leaves while its tunnel is being set up takes the
// tunnel with it, and the transport is not blamed for the failure that
// follows: the server simply had not answered yet.
func TestAnApplicationThatLeavesDuringSetupClosesTheTunnel(t *testing.T) {
	logs := captureLogs(t)
	cfg := testClientParams()
	cfg.OptimisticConnect = true
	cfg.TransportCooldown = time.Minute
	policy, err := newClientPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.policy = policy
	serverSide := pipeServer(t)

	app, handlerSide := tcpPair(t)
	req := []byte{socks5Ver, socks5.UDPTunnelCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	done := runUDPAssociate(t, handlerSide, "example.com", cfg.attempt(), req, dialAttempt)
	readAppReply(t, app)
	server := obfsServerSide(t, <-serverSide, cfg)
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(server, make([]byte, 3+10)); err != nil {
		t.Fatalf("the greeting and the request: %v", err)
	}

	_ = app.Close()
	start := time.Now()
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("the tunnel carried something after the application left")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the tunnel was closed %v after the application left", waited)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the association outlived its application")
	}
	policy.mu.Lock()
	failures := len(policy.failedAt)
	policy.mu.Unlock()
	if failures != 0 {
		t.Fatalf("the transport policy recorded %d failures for an application that left", failures)
	}
	if strings.Contains(logs.String(), "Tunnel setup failed") {
		t.Fatalf("the departure was logged as a failure:\n%s", logs)
	}
}

// exclusiveWrites reports a second concurrent writer to the tunnel through
// the race detector: inWrite is deliberately unsynchronised.
type exclusiveWrites struct {
	net.Conn
	inWrite bool
}

func (c *exclusiveWrites) Write(b []byte) (int, error) {
	c.inWrite = true
	n, err := c.Conn.Write(b)
	c.inWrite = false
	return n, err
}

func (c *exclusiveWrites) NetConn() net.Conn { return c.Conn }

// A native association with datagrams flowing from before the request until
// after native is up: the reader writes behind the request during setup and
// hands over to the single writer of the tunnel after it, never both at once
// (run with -race).
func TestDatagramsFlowThroughTheEndOfSetup(t *testing.T) {
	logs := captureLogs(t)
	addr, srv := startTunnelServer(t, true)
	echo := udpEcho(t)
	cfg := nativeParams(addr, srv.ObfsPSK)
	t.Cleanup(func() { noNative.Delete(nativeKey(cfg)) })
	dial := func(cfg clientParams, req []byte) (net.Conn, clientParams, error) {
		// Long enough for the application to send before the request is out.
		time.Sleep(50 * time.Millisecond)
		handOver := cfg.requestSent
		var guarded *exclusiveWrites
		cfg.requestSent = func(c net.Conn) {
			guarded = &exclusiveWrites{Conn: c}
			handOver(guarded)
		}
		_, used, err := dialAttempt(cfg, req)
		if err != nil {
			return nil, used, err
		}
		return guarded, used, nil
	}
	app, handlerSide := tcpPair(t)
	req := []byte{socks5Ver, udpCommandFor(cfg), 0, addrIPv4, 0, 0, 0, 0, 0, 0}
	runUDPAssociate(t, handlerSide, "", cfg.attempt(), req, dial)
	local := boundUDPPort(t, readAppReply(t, app))
	sender := appSocket(t)

	var answers atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := sender.ReadFromUDP(buf); err != nil {
				return
			}
			answers.Add(1)
		}
	}()
	target := &socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}
	const sent = 400
	for i := range sent {
		if _, err := sender.WriteToUDP(socksDatagram(target, []byte{byte(i)}), local); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for answers.Load() < sent*9/10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := answers.Load(); n < sent*9/10 {
		t.Fatalf("%d answers to %d datagrams", n, sent)
	}
	if logged(logs, `msg="UDP Tunnel established"`, "early_datagrams=") != 1 {
		t.Fatalf("no datagram was sent before the reply:\n%s", logs)
	}
}

func expectRequest(t *testing.T, c net.Conn, command byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 10)
	if _, err := io.ReadFull(c, req); err != nil {
		t.Fatalf("the request: %v", err)
	}
	if req[1] != command {
		t.Fatalf("the request is % x, want command %#x", req, command)
	}
}

func expectFrame(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 2+len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("the frame of % x never came: %v", want, err)
	}
	if !bytes.Equal(got, tunnelFrame(want)) {
		t.Fatalf("the tunnel carried % x, want % x", got, tunnelFrame(want))
	}
}

func expectDatagram(t *testing.T, c *net.UDPConn, want []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the application got nothing: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("the application got % x, want % x", buf[:n], want)
	}
}

// With OPTIMISTIC_CONNECT off the association opens as before: the
// application hears nothing until the server has answered, and then gets
// the server's code.
func TestWithoutOptimismTheApplicationWaitsForTheServer(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		app, clientSide := tcpPair(t)
		tunnel, obfsSide := tcpPair(t)
		runUDPAssociate(t, clientSide, "example.com", clientParams{}, nil, dialled(obfsSide))
		_ = app.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, err := app.Read(make([]byte, 1)); err == nil {
			t.Fatalf("the application got %d bytes before the server answered", n)
		}
		if _, err := tunnel.Write(udpTunnelReply); err != nil {
			t.Fatal(err)
		}
		reply := readAppReply(t, app)
		if reply[1] != 0x00 {
			t.Fatalf("the application was answered % x", reply)
		}
		roundTrip(t, boundUDPPort(t, reply), tunnel)
	})
	t.Run("refused", func(t *testing.T) {
		app, clientSide := tcpPair(t)
		tunnel, obfsSide := tcpPair(t)
		done := runUDPAssociate(t, clientSide, "example.com", clientParams{}, nil, dialled(obfsSide))
		if _, err := tunnel.Write([]byte{socks5Ver, 0x02, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if reply := readAppReply(t, app); reply[1] != 0x02 {
			t.Fatalf("the application was answered % x, want the server's refusal", reply)
		}
		associationEnded(t, app, done)
	})
	t.Run("not dialled", func(t *testing.T) {
		dial := func(cfg clientParams, _ []byte) (net.Conn, clientParams, error) {
			return nil, cfg, &tunnelError{phase: phaseDial, err: errors.New("connection refused")}
		}
		app, clientSide := tcpPair(t)
		done := runUDPAssociate(t, clientSide, "example.com", clientParams{}, nil, dial)
		if reply := readAppReply(t, app); reply[1] != socks5GenFailure {
			t.Fatalf("the application was answered % x, want a general failure", reply)
		}
		associationEnded(t, app, done)
	})
}

// roundTrip sends one datagram from the application through the tunnel and
// brings the answer back to it.
func roundTrip(t *testing.T, local *net.UDPAddr, tunnel net.Conn) {
	t.Helper()
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	out := datagram("question")
	if _, err := sender.WriteToUDP(out, local); err != nil {
		t.Fatal(err)
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 2+len(out))
	if _, err := io.ReadFull(tunnel, got); err != nil {
		t.Fatalf("the datagram never reached the server: %v", err)
	}
	if !bytes.Equal(got, tunnelFrame(out)) {
		t.Fatalf("the server got % x", got)
	}
	in := datagram("answer")
	if _, err := tunnel.Write(tunnelFrame(in)); err != nil {
		t.Fatal(err)
	}
	_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sender.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], in) {
		t.Fatalf("the answer never reached the application: % x, %v", buf[:n], err)
	}
}
