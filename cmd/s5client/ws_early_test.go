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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// earlyNode runs a server with a WSS listener and returns the parameters of
// a client pointed at it, plus an echo target behind it.
func earlyNode(t *testing.T, earlyData string) (clientParams, string) {
	t.Helper()
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := s5server.DefaultConfig()
	cfg.ListenIP = "127.0.0.1"
	cfg.Port = streamPort(t)
	cfg.RequireAuth = false
	cfg.ObfsEnabled = true
	cfg.ObfsPort = streamPort(t)
	cfg.ObfsPSK = testPSK32
	cfg.ObfsMaxPadding = 64
	cfg.ObfsMTU = 1400
	cfg.WSEnabled = true
	cfg.WSAddr = "127.0.0.1:" + streamPort(t)
	cfg.WSCertFile = cert
	cfg.WSKeyFile = key
	cfg.WSPath = "/ws"
	cfg.WSEarlyData = earlyData
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := s5server.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	t.Cleanup(func() { cancel(); srv.Stop(); <-done })
	for i := 0; srv.WSAddr() == ""; i++ {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("the server did not start: %v", err)
		default:
		}
		if i == 300 {
			t.Fatal("the WS listener did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	cp := clientParams{PSK: testPSK32, MTU: 1400, MaxPadding: 64, Prologue: "printable", Format: "v1",
		HandshakeTimeout: 5 * time.Second, DialTimeout: 5 * time.Second, Transport: "ws",
		WSUrl: "wss://" + cfg.WSAddr + "/ws", WSMinFrame: 256, WSMaxFrame: 4096}
	cp.rootCAs = x509.NewCertPool()
	pemBytes, err := os.ReadFile(cert)
	if err != nil || !cp.rootCAs.AppendCertsFromPEM(pemBytes) {
		t.Fatal("test CA", err)
	}
	freshEarlyData(t, cp)
	return cp, echo.Addr().String()
}

// freshEarlyData starts a test with nothing known about the node, either way.
func freshEarlyData(t *testing.T, cp clientParams) {
	reset := func() {
		earlyData.Delete(nativeKey(cp))
		earlyFailed.Lock()
		delete(earlyFailed.m, nativeKey(cp))
		earlyFailed.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func connectTo(t *testing.T, addr string) []byte {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() {
		t.Fatalf("not an IPv4 target: %q, %v", addr, err)
	}
	ip := ap.Addr().As4()
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip[:]...)
	return binary.BigEndian.AppendUint16(req, ap.Port())
}

// echoThrough reads the CONNECT reply on a fresh tunnel and checks that it
// carries bytes both ways.
func echoThrough(t *testing.T, c net.Conn) {
	t.Helper()
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("CONNECT reply % x, %v", reply, err)
	}
	msg := []byte("both ways")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(c, back); err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("echo %q, %v", back, err)
	}
}

func tunnelEcho(t *testing.T, cp clientParams, echo string) {
	t.Helper()
	c, err := dialObfsTunnel(cp, connectTo(t, echo))
	if err != nil {
		t.Fatal(err)
	}
	echoThrough(t, c)
}

func dialsEarly(t *testing.T, cp clientParams) bool {
	t.Helper()
	c, err := dialServer(cp)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, early := c.(*earlyTunnel)
	return early
}

func TestEarlyDataWaitsForTheNodeToAnnounceIt(t *testing.T) {
	cp, echo := earlyNode(t, "")

	if dialsEarly(t, cp) {
		t.Fatal("the first connection to a node used early data")
	}
	tunnelEcho(t, cp, echo)
	if !dialsEarly(t, cp) {
		t.Fatal("a node that announced early data is not dialled with it")
	}
	tunnelEcho(t, cp, echo)
	if dialsEarly(t, waitingForUpgrade(cp)) {
		t.Fatal("a dial told to wait for the upgrade used early data")
	}

	obfsCP := cp
	obfsCP.Transport = "obfs"
	obfsCP.WSUrl = ""
	obfsCP.ServerAddr = "127.0.0.1:1"
	if earlyDataKnown(obfsCP) {
		t.Fatal("the announcement of the WSS node leaked to the obfs key")
	}
}

func TestANodeWithoutEarlyDataIsNotDialledWithIt(t *testing.T) {
	cp, echo := earlyNode(t, s5server.WSEarlyDataOff)
	tunnelEcho(t, cp, echo)
	if dialsEarly(t, cp) {
		t.Fatal("WS_EARLY_DATA=off on the server, and the client sends early data anyway")
	}
}

func TestEarlyDataIsTrustedForTenMinutes(t *testing.T) {
	cp := clientParams{Transport: "ws", WSUrl: "wss://node.invalid/ws"}
	freshEarlyData(t, cp)
	key := nativeKey(cp)

	earlyData.Store(key, time.Now().Add(-earlyDataFor+time.Minute))
	if !earlyDataKnown(cp) {
		t.Fatal("an announcement nine minutes old was not trusted")
	}
	earlyData.Store(key, time.Now().Add(-earlyDataFor-time.Second))
	if earlyDataKnown(cp) {
		t.Fatal("an announcement older than ten minutes was trusted")
	}
}

func TestTheCapabilityIsKeptOutOfTheAdvicePolicy(t *testing.T) {
	cp := clientParams{Transport: "ws", WSUrl: "wss://node.invalid/ws"}
	freshEarlyData(t, cp)
	policy, err := newClientPolicy(cp)
	if err != nil {
		t.Fatal(err)
	}
	cp.policy = policy

	adviceFor(cp)(obfs.Advice{Capabilities: obfs.CapWSEarlyData})
	if !earlyDataKnown(cp) {
		t.Fatal("the bit was not remembered")
	}
	if policy.advice == nil || policy.advice.Capabilities != 0 {
		t.Fatalf("the policy saw %+v, want the advice without capabilities", policy.advice)
	}
	adviceFor(cp)(obfs.Advice{})
	if earlyDataKnown(cp) {
		t.Fatal("an advice without the bit did not withdraw it")
	}
}

func TestAFailedNodeIsNotBelievedForTenMinutes(t *testing.T) {
	cp := clientParams{Transport: "ws", WSUrl: "wss://node.invalid/ws"}
	freshEarlyData(t, cp)
	key := nativeKey(cp)
	bit := obfs.Advice{Capabilities: obfs.CapWSEarlyData}

	forgetEarlyData(key)
	adviceFor(cp)(bit)
	if earlyDataKnown(cp) {
		t.Fatal("the bit was believed right after early data failed on the node")
	}
	failedAgo(key, earlyDataFor+time.Second)
	adviceFor(cp)(bit)
	if !earlyDataKnown(cp) {
		t.Fatal("the bit is still ignored ten minutes after the failure")
	}
}

// failedAgo moves the node's last early-data failure into the past.
func failedAgo(key string, d time.Duration) {
	earlyFailed.Lock()
	defer earlyFailed.Unlock()
	f := earlyFailed.m[key]
	f.at = time.Now().Add(-d)
	earlyFailed.m[key] = f
}

func distrustWindow(key string) time.Duration {
	earlyFailed.Lock()
	defer earlyFailed.Unlock()
	return earlyFailed.m[key].window
}

// A front that loses early frames keeps answering 101, so the node keeps
// failing each time its bit is believed again. The distrust doubles with
// every failure after the first, up to a day; the connections that fail
// together inside one window are one failure.
func TestTheDistrustOfANodeThatFailsAgainGrows(t *testing.T) {
	cp := clientParams{Transport: "ws", WSUrl: "wss://node.invalid/ws"}
	freshEarlyData(t, cp)
	key := nativeKey(cp)
	bit := obfs.Advice{Capabilities: obfs.CapWSEarlyData}

	forgetEarlyData(key)
	forgetEarlyData(key)
	if w := distrustWindow(key); w != earlyDataFor {
		t.Fatalf("two failures inside one window are distrusted for %s, want %s", w, earlyDataFor)
	}

	failedAgo(key, earlyDataFor+time.Second)
	forgetEarlyData(key)
	if w := distrustWindow(key); w != 2*earlyDataFor {
		t.Fatalf("the second failure is distrusted for %s, want %s", w, 2*earlyDataFor)
	}
	failedAgo(key, earlyDataFor+time.Second)
	adviceFor(cp)(bit)
	if earlyDataKnown(cp) {
		t.Fatal("the bit was believed ten minutes after the second failure")
	}

	for want := 2 * earlyDataFor; want < earlyDistrustMax; {
		failedAgo(key, want+time.Second)
		if distrusted(key) {
			t.Fatalf("the node is still distrusted after its window of %s", want)
		}
		forgetEarlyData(key)
		want = min(2*want, earlyDistrustMax)
		if w := distrustWindow(key); w != want {
			t.Fatalf("the window grew to %s, want %s", w, want)
		}
	}
	failedAgo(key, earlyDistrustMax+time.Second)
	forgetEarlyData(key)
	if w := distrustWindow(key); w != earlyDistrustMax {
		t.Fatalf("the window went past a day: %s", w)
	}
}

// Every failure of an early tunnel before the server's first byte is
// classified by one rule, whatever wraps it on the way out: a timeout before
// the 101 is the dial's, anything else is early_upgrade and gets no hint.
func TestAnUnansweredEarlyTunnelHasOneClassification(t *testing.T) {
	refused := &ws.UpgradeError{Status: http.StatusForbidden, Err: errors.New("bad handshake")}
	expired := &ws.UpgradeError{Err: context.DeadlineExceeded}
	for _, c := range []struct {
		name string
		err  error
		want tunnelPhase
	}{
		{"read deadline before the 101", &earlyUnanswered{err: os.ErrDeadlineExceeded}, phaseDial},
		{"dial budget before the 101", &earlyUnanswered{err: expired}, phaseDial},
		{"refusal", &earlyUnanswered{err: refused}, phaseEarlyUpgrade},
		{"close without an answer", &earlyUnanswered{err: &ws.UpgradeError{Err: io.EOF}}, phaseEarlyUpgrade},
		{"silence after the 101", &earlyUnanswered{err: os.ErrDeadlineExceeded, upgraded: true}, phaseEarlyUpgrade},
		{"close after the 101", &earlyUnanswered{err: io.EOF, upgraded: true}, phaseEarlyUpgrade},
		{"answered tunnel", os.ErrDeadlineExceeded, phaseGreeting},
	} {
		err := tunnelFail(phaseGreeting, "failed to read server greeting: %w", c.err)
		if got := tunnelPhaseOf(err); got != c.want {
			t.Errorf("%s: phase %q, want %q", c.name, got, c.want)
		}
		if hint := setupHint(err, clientParams{PSK: testPSK32}); (hint != "") != (c.want == phaseGreeting) {
			t.Errorf("%s: hint %q", c.name, hint)
		}
	}
}

// A node that refuses every upgrade is judged by the ordinary repeat of the
// refused early one: that failure is a dial's, as without early data.
func TestARefusedEarlyUpgradeIsJudgedByItsRepeat(t *testing.T) {
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	cp := clientParams{PSK: testPSK32, MTU: 1400, MaxPadding: 64, Prologue: "printable", Format: "v1",
		HandshakeTimeout: 5 * time.Second, DialTimeout: 5 * time.Second, Transport: "ws",
		WSUrl: strings.Replace(srv.URL, "http", "ws", 1) + "/ws", WSMinFrame: 256, WSMaxFrame: 4096}
	freshEarlyData(t, cp)
	earlyData.Store(nativeKey(cp), time.Now())

	_, err := dialObfsTunnel(cp, connectTo(t, "127.0.0.1:9"))
	if err == nil {
		t.Fatal("a tunnel came up through a 404")
	}
	if n := seen.Load(); n != 2 {
		t.Fatalf("the node saw %d upgrades, want the early one and its repeat", n)
	}
	if phase := tunnelPhaseOf(err); phase != phaseDial {
		t.Fatalf("the repeat failed as phase %q, want %q: %v", phase, phaseDial, err)
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Errorf("the error does not name the answer: %v", err)
	}
	if earlyDataKnown(cp) {
		t.Fatal("a node that refused the upgrade is still dialled with early data")
	}
}

// front is a TLS front for a WSS node. Its first connection is handled by
// first; the rest are passed to the node as they are.
func front(t *testing.T, node clientParams, first func(http.ResponseWriter, *http.Request)) (clientParams, *atomic.Int32) {
	t.Helper()
	upstream := strings.TrimSuffix(strings.TrimPrefix(node.WSUrl, "wss://"), "/ws")
	var seen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) == 1 {
			first(w, r)
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

// policed gives cp a policy free to move off ws, so that a failure it counts
// shows in failuresOf: a pinned transport records none.
func policed(t *testing.T, cp clientParams) (clientParams, *clientPolicy) {
	t.Helper()
	cp.Transport = "auto"
	cp.TransportCooldown = time.Minute
	cp.ServerAddr = "127.0.0.1:9"
	policy, err := newClientPolicy(cp)
	if err != nil {
		t.Fatal(err)
	}
	cp.policy = policy
	return cp, policy
}

func failuresOf(p *clientPolicy) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.failedAt)
}

// A node rolled back to 2.3 or set to WS_EARLY_DATA=off refuses the early
// upgrade. The connection is taken back the ordinary way, and ws is not
// sent to rest for it.
func TestARefusedEarlyUpgradeIsDialledAgainTheOrdinaryWay(t *testing.T) {
	node, echo := earlyNode(t, "")
	cp, seen := front(t, node, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	cp, policy := policed(t, cp)
	earlyData.Store(nativeKey(cp), time.Now())

	c, _, err := dialAttempt(cp.attempt(), connectTo(t, echo))
	if err != nil {
		t.Fatalf("the refused early upgrade cost the connection: %v", err)
	}
	echoThrough(t, c)
	if n := seen.Load(); n != 2 {
		t.Fatalf("the front saw %d upgrades, want the refused one and its repeat", n)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the refusal moved the transport policy (%d failures)", n)
	}
	// The repeat brought an advice with the bit again; it is not believed.
	if earlyDataKnown(cp) {
		t.Fatal("the node that refused early data is dialled with it again")
	}
}

// A front that answers 101 and loses what came before it leaves the server
// silent. The node is forgotten, and the bit it keeps announcing is not
// believed: otherwise every connection after the next one would be lost.
func TestAFrontThatLosesEarlyFramesIsForgotten(t *testing.T) {
	node, echo := earlyNode(t, "")
	cp, _ := front(t, node, func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
		_, _ = io.Copy(io.Discard, bufio.NewReader(c))
	})
	cp.HandshakeTimeout = 500 * time.Millisecond
	cp, policy := policed(t, cp)
	earlyData.Store(nativeKey(cp), time.Now())

	_, _, err := dialAttempt(cp.attempt(), connectTo(t, echo))
	if err == nil {
		t.Fatal("a tunnel came up through a front that dropped its opening")
	}
	// Silence after the 101 is what a wrong PSK looks like too, but on an
	// early tunnel the front is the likelier story: the next attempt is an
	// ordinary one, and that one is judged as before.
	if phase := tunnelPhaseOf(err); phase != phaseEarlyUpgrade {
		t.Fatalf("the silence is phase %q, want %q: %v", phase, phaseEarlyUpgrade, err)
	}
	if n := failuresOf(policy); n != 0 {
		t.Fatalf("the lost early frames moved the transport policy (%d failures)", n)
	}
	if hint := setupHint(err, cp); hint != "" {
		t.Fatalf("the lost early frames got the PSK hint: %s", hint)
	}
	if earlyDataKnown(cp) {
		t.Fatal("the node behind the lossy front is still dialled with early data")
	}
	cp.HandshakeTimeout = 5 * time.Second
	tunnelEcho(t, cp, echo)
	if earlyDataKnown(cp) {
		t.Fatal("the advice through the front made the client trust it again at once")
	}
}

// A node that does not answer the upgrade within the budget fails as a dial,
// as it did before early data, whichever of the greeting's read deadline and
// the dial budget comes first: the two are equal here.
func TestAnEarlyUpgradeWithoutAnAnswerIsADialTimeout(t *testing.T) {
	stop := make(chan struct{})
	var seen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stop) })
	cp := clientParams{PSK: testPSK32, MTU: 1400, MaxPadding: 64, Prologue: "printable", Format: "v1",
		HandshakeTimeout: 300 * time.Millisecond, DialTimeout: 300 * time.Millisecond,
		WSUrl: "wss://" + srv.Listener.Addr().String() + "/ws", WSMinFrame: 256, WSMaxFrame: 4096}
	cp.rootCAs = x509.NewCertPool()
	cp.rootCAs.AddCert(srv.Certificate())
	freshEarlyData(t, cp)
	cp, policy := policed(t, cp)
	earlyData.Store(nativeKey(cp), time.Now())

	_, _, err := dialAttempt(cp.attempt(), connectTo(t, "127.0.0.1:9"))
	if !isTimeout(err) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if phase := tunnelPhaseOf(err); phase != phaseDial {
		t.Fatalf("the unanswered upgrade is phase %q, want %q: %v", phase, phaseDial, err)
	}
	if n := failuresOf(policy); n != 1 {
		t.Fatalf("the dead path was counted %d times, want once", n)
	}
	if n := seen.Load(); n != 1 {
		t.Fatalf("the front saw %d upgrades: a timeout is not dialled again", n)
	}
}
