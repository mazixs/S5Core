package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/mazixs/S5Core/pkg/veil"
)

func freeTCPPort(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// meteredConn counts the bytes of 0x83 frames on the association's control
// connection. Obfs keepalives never pass through it, so a datagram that went
// native leaves both counters where they were.
type meteredConn struct {
	net.Conn
	read, written atomic.Int64
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, err
}

func (c *meteredConn) NetConn() net.Conn { return c.Conn }

// startTunnelServer starts an obfs server on loopback, with native UDP when
// native is set, and returns the address of its obfs listener.
func startTunnelServer(t testing.TB, native bool) (string, s5server.Config) {
	t.Helper()
	return startTunnelServerWith(t, func(c *s5server.Config) {
		if native {
			c.UDPPort = strconv.Itoa(freeUDPPort(t))
		}
	})
}

func startTunnelServerWith(t testing.TB, adjust func(*s5server.Config)) (string, s5server.Config) {
	t.Helper()
	// A port found free can be taken before the server listens on it, by a
	// test of another package or by another freeTCPPort here. Start then
	// returns at once, and the server is started again on new ports.
	for attempt := 1; ; attempt++ {
		addr, cfg, err := tryTunnelServer(t, adjust)
		if err == nil {
			return addr, cfg
		}
		if !errors.Is(err, syscall.EADDRINUSE) || attempt == 3 {
			t.Fatal("server did not start:", err)
		}
	}
}

// tryTunnelServer returns once the server listens on each transport it was
// given, or with the error of a Start that ended before that. A CPU quota
// stretches a start, so it gets 10 s rather than the 2 s it once had.
func tryTunnelServer(t testing.TB, adjust func(*s5server.Config)) (string, s5server.Config, error) {
	t.Helper()
	plain, obfsPort := freeTCPPort(t), freeTCPPort(t)
	cfg := s5server.DefaultConfig()
	cfg.ListenIP, cfg.Port, cfg.ObfsPort = "127.0.0.1", plain, obfsPort
	cfg.RequireAuth = false
	cfg.ObfsEnabled = true
	cfg.ObfsPSK = "01234567890123456789012345678901"
	cfg.ObfsMTU = 1400
	adjust(&cfg)
	srv, err := s5server.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	addr := net.JoinHostPort("127.0.0.1", obfsPort)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		select {
		case err := <-done:
			cancel()
			_ = srv.Stop()
			return "", cfg, err
		default:
		}
		c, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if err == nil {
			_ = c.Close()
			if !cfg.WSEnabled || srv.WSAddr() != "" {
				t.Cleanup(func() { cancel(); _ = srv.Stop(); <-done })
				return addr, cfg, nil
			}
		}
		if time.Now().After(deadline) {
			cancel()
			_ = srv.Stop()
			<-done
			t.Fatal("server did not listen on each transport", err)
		}
	}
}

// udpEcho answers every datagram with itself.
func udpEcho(t testing.TB) *net.UDPConn {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		var b [2048]byte
		for {
			n, peer, err := echo.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(b[:n], peer)
		}
	}()
	return echo
}

// openNativeAssociation asks for 0x84 the way the client's accept loop does
// and hands the association to handleUDPAssociate. It returns the socket the
// application talks to, the client's UDP port and the metered control
// connection.
func openNativeAssociation(t testing.TB, addr string, psk string) (*net.UDPConn, *net.UDPAddr, *meteredConn) {
	t.Helper()
	return openAssociation(t, nativeParams(addr, psk))
}

func nativeParams(addr, psk string) clientParams {
	return clientParams{ServerAddr: addr, PSK: psk, MTU: 1400, MaxPadding: 32, Transport: "obfs", UDPNative: true, HandshakeTimeout: 3 * time.Second}
}

// openAssociation asks for the command the accept loop would, 0x84 unless the
// server is remembered to have no native UDP.
func openAssociation(t testing.TB, clientCfg clientParams) (*net.UDPConn, *net.UDPAddr, *meteredConn) {
	t.Helper()
	t.Cleanup(func() { noNative.Delete(nativeKey(clientCfg)) })
	req := []byte{5, udpCommandFor(clientCfg), 0, 1, 0, 0, 0, 0, 0, 0}
	stream, _, err := dialTunnel(clientCfg, req)
	if err != nil {
		t.Fatal(err)
	}
	metered := &meteredConn{Conn: stream}
	t.Cleanup(func() { _ = stream.Close() })
	app, handlerSide := tcpPair(t)
	runUDPAssociate(t, handlerSide, metered, "", clientCfg, req)
	reply := readAppReply(t, app)
	if reply[1] != 0 {
		t.Fatalf("application refused: %x", reply)
	}
	return appSocket(t), boundUDPPort(t, reply), metered
}

// rulesOf22 refuses what S5Core 2.2 did not know: its command rule stopped
// 0x84 before the dispatch, with "not allowed by ruleset".
type rulesOf22 struct{}

func (rulesOf22) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	return ctx, req.Command == socks5.ConnectCommand || req.Command == socks5.AssociateCommand || req.Command == socks5.UDPTunnelCommand
}

// refuseUDP is a 2.3 server whose rules refuse every UDP association.
type refuseUDP struct{}

func (refuseUDP) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	return ctx, req.Command == socks5.ConnectCommand
}

// startOldServer serves the obfs tunnel with the SOCKS5 core and no native
// UDP. With rulesOf22 it answers 0x84 as a 2.2 server does, with nil rules as
// a plain SOCKS5 server: command not supported. It counts the tunnels it
// accepts.
func startOldServer(t *testing.T, psk string, creds socks5.CredentialStore, rules socks5.RuleSet) (string, *atomic.Int64) {
	t.Helper()
	server, err := socks5.New(&socks5.Config{Credentials: creds, Rules: rules, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				conn, err := obfs.NewServerConn(raw, obfs.Config{PSK: []byte(psk), MTU: 1400, Scheme: &veil.Clocked{Accepts: everyCipher()}})
				if err != nil {
					_ = raw.Close()
					return
				}
				_ = server.ServeConnContext(context.Background(), conn)
			}()
		}
	}()
	return ln.Addr().String(), &accepted
}

// tick sends one datagram through the association and waits for its echo.
func tick(t *testing.T, sender *net.UDPConn, local *net.UDPAddr, echo *net.UDPConn, i int) {
	t.Helper()
	payload := socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("tick"))
	if _, err := sender.WriteToUDP(payload, local); err != nil {
		t.Fatal(err)
	}
	_ = sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [2048]byte
	n, _, err := sender.ReadFromUDP(b[:])
	if err != nil {
		t.Fatalf("tick %d: %v", i, err)
	}
	if !bytes.HasSuffix(b[:n], []byte("tick")) {
		t.Fatalf("tick %d response %x", i, b[:n])
	}
}

// Arriving is not the claim: 0x83 delivers the same ticks. Once the probe is
// answered, a tick and its echo must leave the control connection untouched
// in both directions.
func TestNativeCarriesTheTicksBothWays(t *testing.T) {
	addr, cfg := startTunnelServer(t, true)
	echo := udpEcho(t)
	sender, local, metered := openNativeAssociation(t, addr, cfg.ObfsPSK)

	// The first ticks may go by 0x83 while the probe is in flight.
	verified := false
	for i := 0; i < 50 && !verified; i++ {
		r, w := metered.read.Load(), metered.written.Load()
		tick(t, sender, local, echo, i)
		verified = metered.read.Load() == r && metered.written.Load() == w
		if !verified {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !verified {
		t.Fatalf("every tick crossed the control connection: read %d, written %d", metered.read.Load(), metered.written.Load())
	}
	r, w := metered.read.Load(), metered.written.Load()
	for i := 0; i < 20; i++ {
		tick(t, sender, local, echo, i)
	}
	if dr, dw := metered.read.Load()-r, metered.written.Load()-w; dr != 0 || dw != 0 {
		t.Fatalf("after verification the ticks used 0x83: %d bytes in, %d bytes out", dr, dw)
	}
}

// A node without UDP_PORT answers 0x84 with port 0, and the association goes
// by 0x83 on the connection that asked: the ticks cross the metered one.
func TestANodeWithoutNativeUDPCarriesTheAssociationOnOneConnection(t *testing.T) {
	addr, cfg := startTunnelServer(t, false)
	echo := udpEcho(t)
	sender, local, metered := openNativeAssociation(t, addr, cfg.ObfsPSK)
	for i := 0; i < 3; i++ {
		r, w := metered.read.Load(), metered.written.Load()
		tick(t, sender, local, echo, i)
		if metered.read.Load() == r || metered.written.Load() == w {
			t.Fatalf("tick %d did not cross the connection that asked for 0x84", i)
		}
	}
	if got := udpCommandFor(nativeParams(addr, cfg.ObfsPSK)); got != socks5.UDPTunnelCommand {
		t.Fatalf("the next association asks for %#x, want 0x83", got)
	}
}

// WS_URL and SERVER_ADDR may reach different nodes, and an answer is about
// the node that gave it. Here the one behind WS_URL has no UDP_PORT: its
// port 0 keeps the associations over WS on 0x83 and leaves those over obfs
// asking for 0x84. The answer used to be remembered by SERVER_ADDR, so one
// association over WS kept the obfs ones on 0x83 for ten minutes.
func TestAnAnswerOverWebSocketIsNotTakenForTheObfsNode(t *testing.T) {
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wsAddr string
	startTunnelServerWith(t, func(c *s5server.Config) {
		wsAddr = net.JoinHostPort("127.0.0.1", freeTCPPort(t))
		c.WSEnabled, c.WSAddr, c.WSCertFile, c.WSKeyFile, c.WSPath = true, wsAddr, cert, key, "/ws"
	})
	addr, cfg := startTunnelServer(t, true)
	overWS := nativeParams(addr, cfg.ObfsPSK)
	overWS.Transport, overWS.WSUrl, overWS.WSMinFrame, overWS.WSMaxFrame = "ws", "wss://"+wsAddr+"/ws", 256, 4096
	overWS.DialTimeout = 3 * time.Second
	overWS.rootCAs = x509.NewCertPool()
	if pem, err := os.ReadFile(cert); err != nil || !overWS.rootCAs.AppendCertsFromPEM(pem) {
		t.Fatal("test CA", err)
	}
	echo := udpEcho(t)
	sender, local, _ := openAssociation(t, overWS)
	tick(t, sender, local, echo, 0)
	if got := udpCommandFor(overWS); got != socks5.UDPTunnelCommand {
		t.Fatalf("the next association over WS asks for %#x, want 0x83", got)
	}
	if got := udpCommandFor(nativeParams(addr, cfg.ObfsPSK)); got != socks5.UDPNativeCommand {
		t.Fatalf("the next association over obfs asks for %#x, want 0x84", got)
	}
}

// A server that predates 0x84 refuses it: 2.2 by its rules, a plain SOCKS5
// server as unsupported. The association asks again by 0x83 on a second
// tunnel, and the next association goes to 0x83 at once. The first version
// of this retry took only the second answer, and against a 2.2 server no UDP
// association opened at all.
func TestAServerThatPredatesNativeIsAskedOnce(t *testing.T) {
	psk := "01234567890123456789012345678901"
	for name, rules := range map[string]socks5.RuleSet{"2.2": rulesOf22{}, "plain SOCKS5": nil} {
		t.Run(name, func(t *testing.T) {
			addr, accepted := startOldServer(t, psk, nil, rules)
			echo := udpEcho(t)
			sender, local, _ := openNativeAssociation(t, addr, psk)
			tick(t, sender, local, echo, 0)
			if n := accepted.Load(); n != 2 {
				t.Fatalf("%d tunnels for the first association, want 2", n)
			}
			sender, local, _ = openNativeAssociation(t, addr, psk)
			tick(t, sender, local, echo, 1)
			if n := accepted.Load(); n != 3 {
				t.Fatalf("%d tunnels after the second association, want 3", n)
			}
		})
	}
}

// A 2.3 server whose rules refuse UDP answers 0x84 as a 2.2 one does. The
// retry by 0x83 is refused too, so the refusal goes to the application and
// the server is not taken for one without native: the next association asks
// for 0x84 again. The log names the command refused last, 0x83; it used to
// name the 0x84 asked for first.
func TestARefusalOfUDPIsNotTakenForAnOldServer(t *testing.T) {
	psk := "01234567890123456789012345678901"
	addr, accepted := startOldServer(t, psk, nil, refuseUDP{})
	logs := captureLogs(t)
	cfg := nativeParams(addr, psk)
	t.Cleanup(func() { noNative.Delete(nativeKey(cfg)) })
	req := []byte{5, udpCommandFor(cfg), 0, 1, 0, 0, 0, 0, 0, 0}
	stream, _, err := dialTunnel(cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	app, handlerSide := tcpPair(t)
	runUDPAssociate(t, handlerSide, stream, "", cfg, req)
	if reply := readAppReply(t, app); reply[1] != replyNotAllowed {
		t.Fatalf("the application was told %x, want the refusal", reply)
	}
	if n := accepted.Load(); n != 2 {
		t.Fatalf("%d tunnels, want 2", n)
	}
	if got := udpCommandFor(cfg); got != socks5.UDPNativeCommand {
		t.Fatalf("the next association asks for %#x, want 0x84", got)
	}
	if logged(logs, `msg="Server rejected the UDP association"`) != 1 || logged(logs, `msg="Server rejected the UDP association"`, "command=0x83") != 1 {
		t.Fatalf("the refusal of the retry was logged as:\n%s", logs)
	}
}

// allowOnce accepts the first login and refuses the rest.
type allowOnce struct{ used atomic.Bool }

func (a *allowOnce) Valid(string, string) bool { return !a.used.Swap(true) }

// The retry by 0x83 is refused its login. That is the server answering, and
// the log names the phase dialTunnel saw, without the hint for a server that
// went quiet. The retry's error used to be wrapped once more as the reply
// phase, and the hint sent the operator after the PSK and the clock.
func TestARefusedRetryKeepsItsPhase(t *testing.T) {
	psk := "01234567890123456789012345678901"
	addr, _ := startOldServer(t, psk, &allowOnce{}, rulesOf22{})
	logs := captureLogs(t)
	cfg := nativeParams(addr, psk)
	cfg.ProxyUser, cfg.ProxyPass = "alice", "secret"
	t.Cleanup(func() { noNative.Delete(nativeKey(cfg)) })
	req := []byte{5, socks5.UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}
	stream, _, err := dialTunnel(cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	app, handlerSide := tcpPair(t)
	runUDPAssociate(t, handlerSide, stream, "", cfg, req)
	if reply := readAppReply(t, app); reply[1] == 0 {
		t.Fatalf("the application was told %x", reply)
	}
	out := logs.String()
	if !strings.Contains(out, "phase="+string(phaseAuthRejected)) || strings.Contains(out, "hint=") {
		t.Fatalf("the retry's failure was logged as:\n%s", out)
	}
}
