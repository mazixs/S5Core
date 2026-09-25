package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/mazixs/S5Core/pkg/veil"
)

// The association tests put a UDP hop between the client and the server's
// native port, so that a test can cut one direction. The hop lives on
// 127.0.0.2, which Linux routes to loopback without any setup; the client is
// sent there by the address of its control connection.

// nativeHop forwards datagrams between the client (on its front, bound to
// 127.0.0.2 and the hub's port) and the hub (from an ephemeral back socket).
type nativeHop struct {
	t        *testing.T
	frontAt  *net.UDPAddr
	back     *net.UDPConn
	hub      netip.AddrPort
	mu       sync.Mutex
	front    *net.UDPConn
	client   atomic.Pointer[netip.AddrPort]
	dropUp   atomic.Bool // client -> server
	dropDown atomic.Bool // server -> client
	lostUp   atomic.Int64
}

func newNativeHop(t *testing.T, hubPort int) *nativeHop {
	t.Helper()
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	h := &nativeHop{t: t, frontAt: &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: hubPort}, back: back,
		hub: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(hubPort))}
	h.open()
	t.Cleanup(func() { h.close(); _ = back.Close() })
	go func() {
		var b [2048]byte
		for {
			n, err := back.Read(b[:])
			if err != nil {
				return
			}
			c := h.client.Load()
			h.mu.Lock()
			front := h.front
			h.mu.Unlock()
			if c == nil || front == nil || h.dropDown.Load() {
				continue
			}
			_, _ = front.WriteToUDPAddrPort(b[:n], *c)
		}
	}()
	return h
}

// open binds the front, which the client's connected socket expects replies from.
func (h *nativeHop) open() {
	front, err := net.ListenUDP("udp", h.frontAt)
	if err != nil {
		h.t.Fatalf("the hop cannot bind %v: %v", h.frontAt, err)
	}
	h.mu.Lock()
	h.front = front
	h.mu.Unlock()
	go func() {
		var b [2048]byte
		for {
			n, from, err := front.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			h.client.Store(&from)
			if h.dropUp.Load() {
				h.lostUp.Add(1)
				continue
			}
			_, _ = h.back.WriteToUDPAddrPort(b[:n], h.hub)
		}
	}()
}

func (h *nativeHop) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.front != nil {
		_ = h.front.Close()
		h.front = nil
	}
}

// rerouted reports the client's control connection as coming from the hop's
// address, which is where the client then sends its native datagrams.
type rerouted struct {
	*meteredConn
	remote net.Addr
}

func (c *rerouted) RemoteAddr() net.Addr { return c.remote }
func (c *rerouted) NetConn() net.Conn    { return c.Conn }

// streamer is a game server: it echoes what it gets, and after "start" it
// sends state at 64 Hz to whoever asked, whether or not they speak again.
type streamer struct {
	conn *net.UDPConn
	peer atomic.Pointer[netip.AddrPort]
}

func newStreamer(t *testing.T) *streamer {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	s := &streamer{conn: c}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); _ = c.Close() })
	go func() {
		var b [2048]byte
		for {
			n, from, err := c.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			if string(b[:n]) == "start" {
				s.peer.Store(&from)
				continue
			}
			_, _ = c.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	go func() {
		tick := time.NewTicker(time.Second / 64)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if p := s.peer.Load(); p != nil {
					_, _ = c.WriteToUDPAddrPort([]byte("state"), *p)
				}
			}
		}
	}()
	return s
}

// nativeRig is an association whose native datagrams cross the hop.
type nativeRig struct {
	t       *testing.T
	hop     *nativeHop
	target  *streamer
	app     *net.UDPConn
	local   *net.UDPAddr
	control *meteredConn
}

func newNativeRig(t *testing.T) *nativeRig {
	t.Helper()
	udpPort := freeUDPPort(t)
	addr, cfg := startTunnelServerWith(t, func(c *s5server.Config) { c.UDPPort = strconv.Itoa(udpPort) })
	hop := newNativeHop(t, udpPort)
	target := newStreamer(t)

	clientCfg := clientParams{ServerAddr: addr, PSK: cfg.ObfsPSK, MTU: 1400, MaxPadding: 32, Transport: "obfs", UDPNative: true, HandshakeTimeout: 3 * time.Second}
	req := []byte{5, socks5.UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}
	stream, _, err := dialTunnel(clientCfg, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	control := &meteredConn{Conn: stream}
	conn := &rerouted{meteredConn: control, remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: p}}
	app, handlerSide := tcpPair(t)
	go handleUDPAssociate(handlerSide, conn, "", clientCfg, req)
	reply := readAppReply(t, app)
	if reply[1] != 0 {
		t.Fatalf("application refused: %x", reply)
	}
	return &nativeRig{t: t, hop: hop, target: target, app: appSocket(t), local: boundUDPPort(t, reply), control: control}
}

func (r *nativeRig) send(payload string) {
	r.t.Helper()
	d := socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: r.target.conn.LocalAddr().(*net.UDPAddr).Port}, []byte(payload))
	if _, err := r.app.WriteToUDP(d, r.local); err != nil {
		r.t.Fatal(err)
	}
}

// await reads datagrams until one ends with want or the time runs out.
func (r *nativeRig) await(want string, within time.Duration) bool {
	r.t.Helper()
	deadline := time.Now().Add(within)
	var b [2048]byte
	for {
		_ = r.app.SetReadDeadline(deadline)
		n, _, err := r.app.ReadFromUDP(b[:])
		if err != nil {
			return false
		}
		if bytes.HasSuffix(b[:n], []byte(want)) {
			return true
		}
	}
}

// native reports whether one echoed tick crossed the association without
// touching the control connection in either direction.
func (r *nativeRig) native(i int) bool {
	r.t.Helper()
	rd, wr := r.control.read.Load(), r.control.written.Load()
	tag := "tick" + strconv.Itoa(i)
	r.send(tag)
	if !r.await(tag, 3*time.Second) {
		r.t.Fatalf("tick %d was not answered", i)
	}
	return r.control.read.Load() == rd && r.control.written.Load() == wr
}

// verified waits until ticks go native, which is where every test starts.
func (r *nativeRig) verified() {
	r.t.Helper()
	for i := 0; i < 100; i++ {
		if r.native(i) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatal("native UDP never carried a tick")
}

// startStream has the target stream state to the association, and waits
// until that stream arrives natively.
func (r *nativeRig) startStream() {
	r.t.Helper()
	r.send("start")
	if !r.await("state", 3*time.Second) {
		r.t.Fatal("the stream did not arrive")
	}
	rd := r.control.read.Load()
	if !r.await("state", time.Second) || r.control.read.Load() != rd {
		r.t.Fatal("the stream is not native")
	}
}

// Finding 1 of the 2.3 review. The application only listens, and the server's
// datagrams stop reaching the client. The client has nothing to send, so
// nothing it sends can move the server off native: it has to say so.
func TestAListeningApplicationGetsItsStreamBackByTCP(t *testing.T) {
	t.Parallel()
	r := newNativeRig(t)
	r.verified()
	r.startStream()
	r.hop.dropDown.Store(true)
	if !r.streamByControl(5 * time.Second) {
		t.Fatal("the stream never came back by the control connection after the server's datagrams stopped arriving")
	}
}

// streamByControl waits for the stream to arrive by the control connection. A
// native datagram that passed the hop before the break can still be on its way
// to the application, and it does not count.
func (r *nativeRig) streamByControl(within time.Duration) bool {
	r.t.Helper()
	rd := r.control.read.Load()
	deadline := time.Now().Add(within)
	for {
		left := time.Until(deadline)
		if left <= 0 || !r.await("state", left) {
			return false
		}
		if r.control.read.Load() != rd {
			return true
		}
	}
}

// streamNative waits until the stream arrives for half a second without the
// control connection, or the time runs out.
func (r *nativeRig) streamNative(within time.Duration) bool {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		rd := r.control.read.Load()
		first := r.await("state", 500*time.Millisecond)
		if first && r.await("state", 500*time.Millisecond) && r.control.read.Load() == rd {
			return true
		}
	}
	return false
}

// The same break, healed. The application still only listens, so nothing it
// sends can bring the server back to native: the client's probe that hears
// the server does. Without it the stream stayed on TCP until the association
// ended (finding 2 of the third review).
func TestAListeningApplicationGetsItsStreamBackNative(t *testing.T) {
	t.Parallel()
	r := newNativeRig(t)
	r.verified()
	r.startStream()
	r.hop.dropDown.Store(true)
	if !r.streamByControl(5 * time.Second) {
		t.Fatal("the stream did not move to the control connection")
	}
	r.hop.dropDown.Store(false)
	if !r.streamNative(8 * time.Second) {
		t.Fatal("the stream did not come back native after the path healed")
	}
}

// Finding 3 of the third review. More of the client's datagrams are lost in a
// row than the server looks ahead, so none of its tags matches the server's
// window any more, probes included: the path heals, and only the counter the
// client gives by the control connection when it moves to TCP brings native
// back.
func TestTheCountersResyncWhenThePathHeals(t *testing.T) {
	t.Parallel()
	r := newNativeRig(t)
	r.verified()
	r.hop.dropUp.Store(true)
	for i := 0; i < 1200; i++ {
		r.send("lost")
		if i%20 == 19 {
			time.Sleep(time.Millisecond)
		}
	}
	if !eventually(func() bool { return r.hop.lostUp.Load() > 600 }) {
		t.Fatalf("%d datagrams were lost, want more than the server looks ahead", r.hop.lostUp.Load())
	}
	written := r.control.written.Load()
	if !eventually(func() bool { return r.control.written.Load() != written }) {
		t.Fatal("the client never told the server it moved to TCP")
	}
	r.hop.dropUp.Store(false)
	for i, deadline := 0, time.Now().Add(15*time.Second); !r.native(i); i++ {
		if time.Now().After(deadline) {
			t.Fatal("native UDP did not come back after the path healed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The client's datagrams stop reaching the server while the server's still
// arrive. Fresh packets from the server are no evidence that the client is
// heard: only an answer to a probe is.
func TestAClientThatIsNotHeardMovesToTCP(t *testing.T) {
	t.Parallel()
	r := newNativeRig(t)
	r.verified()
	r.startStream()
	r.hop.dropUp.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		tag := "lost" + strconv.Itoa(i)
		r.send(tag)
		if r.await(tag, 250*time.Millisecond) {
			return
		}
	}
	t.Fatal("the client kept sending into a path the server does not hear")
}

// servedPort is the server's end of a native path on a real socket: it answers
// probes, hands over the data it opens, and a test can close it and bind it
// again under the same session.
type servedPort struct {
	t       *testing.T
	at      *net.UDPAddr
	session *nativeudp.Session
	data    chan string
	peer    atomic.Pointer[netip.AddrPort]
	mu      sync.Mutex
	conn    *net.UDPConn
}

func newServedPort(t *testing.T, session *nativeudp.Session) *servedPort {
	t.Helper()
	p := &servedPort{t: t, at: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)}, session: session, data: make(chan string, 16)}
	p.open()
	t.Cleanup(p.close)
	return p
}

func (p *servedPort) open() {
	c, err := net.ListenUDP("udp", p.at)
	if err != nil {
		p.t.Fatalf("cannot bind %v: %v", p.at, err)
	}
	p.mu.Lock()
	p.conn = c
	p.mu.Unlock()
	go func() {
		var b [nativeudp.MaxWire + 1]byte
		for {
			n, from, err := c.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			pk, err := p.session.Open(b[:n])
			if err != nil {
				continue
			}
			p.peer.Store(&from)
			switch pk.Kind {
			case nativeudp.KindProbe:
				p.send(c, from, nativeudp.KindProbeAck, nil)
			case nativeudp.KindData:
				select {
				case p.data <- string(pk.Data):
				default:
				}
			}
		}
	}()
}

// close unbinds the port: the client's next datagram earns its connected
// socket an ICMP port unreachable, as a restarted server would.
func (p *servedPort) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

func (p *servedPort) send(c *net.UDPConn, to netip.AddrPort, kind byte, d []byte) {
	wire, err := p.session.Seal(nil, kind, d)
	if err == nil {
		_, _ = c.WriteToUDPAddrPort(wire, to)
	}
}

// say sends data to the client the port last heard.
func (p *servedPort) say(d string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if to := p.peer.Load(); to != nil && p.conn != nil {
		p.send(p.conn, *to, nativeudp.KindData, []byte(d))
	}
}

// readErrors is the client's socket, handing over the first error a read got.
type readErrors struct {
	*net.UDPConn
	errs chan error
}

func (c *readErrors) Read(b []byte) (int, error) {
	n, err := c.UDPConn.Read(b)
	if err != nil {
		select {
		case c.errs <- err:
		default:
		}
	}
	return n, err
}

// eventually polls cond until it holds or 10 s pass.
func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// Finding 2. An ICMP error on the client's connected socket is an answer about
// one datagram: the reader goes on, and native carries both ways once the port
// is back. The error here is the kernel's; the moments are held in the bubble
// by TestAnErrorOnTheSocketIsNotTheEndOfIt and TestAnErrorOnAVerifiedPathKeepsItNative.
func TestAnICMPErrorDoesNotEndNativeUDP(t *testing.T) {
	t.Parallel()
	psk, secret := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 40)
	ck, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	server := newServedPort(t, nativeudp.NewSession(sk))
	sock, err := net.DialUDP("udp", nil, server.at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	conn := &readErrors{UDPConn: sock, errs: make(chan error, 1)}
	client := newNativeClient(conn, nativeudp.NewSession(ck), func() {})
	delivered := make(chan string, 16)
	go client.run(func(d []byte) {
		select {
		case delivered <- string(d):
		default:
		}
	})
	if !eventually(client.up.Load) {
		t.Fatal("the path was not verified")
	}

	server.close()
	client.carry([]byte("into the void"))
	select {
	case err := <-conn.errs:
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("the closed port gave the reader %v, want ECONNREFUSED", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the closed port gave the reader no error")
	}

	// Carrying alone could ride on an answer from before the error; a
	// datagram of the server's after it reaches only a reader that went on.
	server.open()
	server.say("after the error")
	select {
	case d := <-delivered:
		if d != "after the error" {
			t.Fatalf("delivered %q", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reader stopped at the error")
	}
	if !eventually(func() bool { return client.carry([]byte("back")) }) {
		t.Fatal("the client's datagrams did not go native again")
	}
	select {
	case d := <-server.data:
		if d != "back" {
			t.Fatalf("the server got %q", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the native datagram did not reach the server")
	}
}
