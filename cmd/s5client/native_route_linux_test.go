package main

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/s5server"
)

// ecmpHop spreads the flows of the client over routes, as a provider that
// hashes the ports does: every source port of the client has a back socket of
// its own toward the hub, so that the hub sees a peer per flow, and the first
// flow's route is slower by slow each way. Like nativeHop it lives on
// 127.0.0.2 and the hub's port.
type ecmpHop struct {
	front *net.UDPConn
	hub   netip.AddrPort
	slow  time.Duration
	mu    sync.Mutex
	flows []*ecmpFlow
	// misroute sends the next datagram of 300-1000 bytes of a later flow by
	// the first flow's route, as if from the socket the association left.
	misroute, misrouted atomic.Bool
}

type ecmpFlow struct {
	client   netip.AddrPort
	back     *net.UDPConn
	delay    time.Duration
	up, down atomic.Int64
}

func newECMPHop(t *testing.T, hubPort int, slow time.Duration) *ecmpHop {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: hubPort})
	if err != nil {
		t.Fatalf("the hop cannot bind 127.0.0.2:%d: %v", hubPort, err)
	}
	h := &ecmpHop{front: front, hub: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(hubPort)), slow: slow}
	t.Cleanup(func() {
		_ = front.Close()
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, f := range h.flows {
			_ = f.back.Close()
		}
	})
	go func() {
		var b [2048]byte
		for {
			n, from, err := front.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			f, first := h.flow(t, from)
			via := f
			if f != first && n > 300 && n < 1000 && h.misroute.CompareAndSwap(true, false) {
				via = first
				h.misrouted.Store(true)
			}
			f.up.Add(1)
			later(via.delay, bytes.Clone(b[:n]), func(w []byte) { _, _ = via.back.WriteToUDPAddrPort(w, h.hub) })
		}
	}()
	return h
}

// flow is the route of a source port of the client, and the first route.
func (h *ecmpHop) flow(t *testing.T, client netip.AddrPort) (f, first *ecmpFlow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range h.flows {
		if f.client == client {
			return f, h.flows[0]
		}
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Errorf("the hop cannot open a route: %v", err)
		return nil, nil
	}
	f = &ecmpFlow{client: client, back: back}
	if len(h.flows) == 0 {
		f.delay = h.slow
	}
	h.flows = append(h.flows, f)
	go func() {
		var b [2048]byte
		for {
			n, err := back.Read(b[:])
			if err != nil {
				return
			}
			f.down.Add(1)
			later(f.delay, bytes.Clone(b[:n]), func(w []byte) { _, _ = h.front.WriteToUDPAddrPort(w, f.client) })
		}
	}()
	return f, h.flows[0]
}

func (h *ecmpHop) routes() []*ecmpFlow {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*ecmpFlow(nil), h.flows...)
}

func later(d time.Duration, w []byte, write func([]byte)) {
	if d == 0 {
		write(w)
		return
	}
	time.AfterFunc(d, func() { write(w) })
}

// recorder is the target: it counts what it gets and sends it back.
type recorder struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  map[string]int
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{conn: c, got: map[string]int{}}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		var b [2048]byte
		for {
			n, from, err := c.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			r.mu.Lock()
			r.got[string(b[:n])]++
			r.mu.Unlock()
			_, _ = c.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	return r
}

func (r *recorder) count(d string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[d]
}

// The search for a faster route end to end (docs/veil-spec.md, 10.6.1),
// through the server's hub. The first flow of the association crosses a
// route 80 ms longer than the others, so the first candidate wins and the hub
// moves its answers to the candidate's socket. The application's datagrams
// reach the target once each, natively or by 0x83 while the move lasts, and
// so do the target's answers to them. A datagram of the client that comes by
// the old route after the move never reaches the target: the hub drops it,
// which is why the move goes by 0x83.
func TestTheHubFollowsTheAssociationToAFasterRoute(t *testing.T) {
	t.Parallel()
	udpPort := freeUDPPort(t)
	addr, cfg := startTunnelServerWith(t, func(c *s5server.Config) { c.UDPPort = strconv.Itoa(udpPort) })
	hop := newECMPHop(t, udpPort, 40*time.Millisecond)
	target := newRecorder(t)

	clientCfg := clientParams{ServerAddr: addr, PSK: cfg.ObfsPSK, MTU: 1400, MaxPadding: 32, Transport: "obfs", UDPNative: true,
		HandshakeTimeout: 3 * time.Second, OptimisticConnect: true, UDPRouteCandidates: 3}
	req := []byte{5, socks5.UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}
	stream, _, err := dialAttempt(clientCfg.attempt(), req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	control := &meteredConn{Conn: stream}
	conn := &rerouted{meteredConn: control, remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: p}}
	appControl, handlerSide := tcpPair(t)
	runUDPAssociate(t, handlerSide, "", clientCfg, req, dialled(conn))
	reply := readAppReply(t, appControl)
	if reply[1] != 0 {
		t.Fatalf("application refused: %x", reply)
	}
	app, local := appSocket(t), boundUDPPort(t, reply)
	to := &socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: target.conn.LocalAddr().(*net.UDPAddr).Port}
	send := func(d string) {
		if _, err := app.WriteToUDP(socksDatagram(to, []byte(d)), local); err != nil {
			t.Error(err)
		}
	}
	var mu sync.Mutex
	echoed := map[string]int{}
	go func() {
		var b [2048]byte
		for {
			n, _, err := app.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			// The SOCKS5 UDP header of an IPv4 address.
			if n > 10 {
				mu.Lock()
				echoed[string(b[10:n])]++
				mu.Unlock()
			}
		}
	}()

	var sent atomic.Int64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			send("u" + strconv.Itoa(i))
			sent.Add(1)
		}
	}()
	defer func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
		<-done
	}()

	// quiet reports whether the client wrote nothing on the control
	// connection for 300 ms while the datagrams went on.
	quiet := func() bool {
		w := control.written.Load()
		time.Sleep(300 * time.Millisecond)
		return control.written.Load() == w
	}
	if !eventually(quiet) {
		t.Fatal("the datagrams never went native")
	}
	before := control.written.Load()
	moved := func() bool { r := hop.routes(); return len(r) >= 2 && r[1].down.Load() > 20 }
	if !eventually(moved) {
		t.Fatalf("the hub did not move its answers to a candidate: %d routes", len(hop.routes()))
	}
	if !eventually(quiet) {
		t.Fatal("the datagrams did not go native on the new socket")
	}
	routes := hop.routes()
	if control.written.Load() == before {
		t.Fatal("nothing went by 0x83 while the association moved")
	}
	if len(routes) != 2 {
		t.Fatalf("%d routes, want the first candidate to win", len(routes))
	}
	up := routes[1].up.Load()
	time.Sleep(200 * time.Millisecond)
	if routes[1].up.Load() == up {
		t.Fatal("the datagrams do not go by the new route")
	}
	old := routes[0].down.Load()

	// A datagram by the old route after the move. Until the hop finds one,
	// the long ones go by the new route and count as any other.
	long := func(tag string) string { return strings.Repeat("x", 400-len(tag)) + tag }
	var lost string
	hop.misroute.Store(true)
	for k := 0; lost == "" && k < 50; k++ {
		d := long("miss" + strconv.Itoa(k))
		send(d)
		if eventually(func() bool { return hop.misrouted.Load() || target.count(d) != 0 }) && hop.misrouted.Load() {
			lost = d
		}
	}
	if lost == "" {
		t.Fatal("no datagram of the new route came to the hop")
	}
	after := long("after")
	send(after)
	if !eventually(func() bool { return target.count(after) == 1 }) {
		t.Fatal("the datagram after the misrouted one did not reach the target")
	}
	close(stop)
	<-done
	time.Sleep(time.Second)
	if target.count(lost) != 0 {
		t.Fatal("a datagram from the old route reached the target after the move")
	}
	if routes[0].down.Load() != old {
		t.Fatal("the hub still sends by the old route")
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range int(sent.Load()) {
		d := "u" + strconv.Itoa(i)
		if n, back := target.count(d), echoed[d]; n != 1 || back != 1 {
			t.Fatalf("%s reached the target %d times and came back %d times", d, n, back)
		}
	}
}
