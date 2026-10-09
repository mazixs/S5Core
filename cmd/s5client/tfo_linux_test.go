package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/netnstest"
	"github.com/mazixs/S5Core/internal/tcptune"
	"github.com/mazixs/S5Core/pkg/s5server"
	"golang.org/x/sys/unix"
)

func fastOpenConnect(t *testing.T, c net.Conn) int {
	t.Helper()
	sc, err := tcptune.Socket(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT) })
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// tunnelDials records the tunnels the client opens and which dialler opened them.
type tunnelDials struct {
	mu       sync.Mutex
	conns    []net.Conn
	fastOpen int
}

func (d *tunnelDials) hook(t *testing.T) {
	outbound, fast := dialOutbound, dialFastOpen
	record := func(dial func(context.Context, string, string) (net.Conn, error), viaFastOpen bool) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err == nil {
				d.mu.Lock()
				d.conns = append(d.conns, c)
				if viaFastOpen {
					d.fastOpen++
				}
				d.mu.Unlock()
			}
			return c, err
		}
	}
	dialOutbound, dialFastOpen = record(outbound, false), record(fast, true)
	t.Cleanup(func() { dialOutbound, dialFastOpen = outbound, fast })
}

func (d *tunnelDials) last() (net.Conn, int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil, 0, 0
	}
	return d.conns[len(d.conns)-1], len(d.conns), d.fastOpen
}

func TestOBFSTFOSetsTheOptionOnlyWhenAsked(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, tc := range []struct {
		name string
		cfg  clientParams
		want int
	}{
		{"on", clientParams{FastOpen: true}, 1},
		{"off", clientParams{}, 0},
		{"spare", clientParams{FastOpen: true, noFastOpen: true}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ServerAddr = l.Addr().String()
			c, err := dialTCP(context.Background(), tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if got := fastOpenConnect(t, c); got != tc.want {
				t.Fatalf("TCP_FASTOPEN_CONNECT = %d, want %d", got, tc.want)
			}
		})
	}
	ws := clientParams{FastOpen: true, WSUrl: "wss://example.test/ws", transport: transportWS}
	if ws.fastOpen() {
		t.Fatal("the WebSocket transport took TCP Fast Open")
	}
}

// A spare is dialled long before its first write. With the option connect()
// would send no SYN until then, so the spare would look warm toward a node
// that is down, and hungUp and the bytes_acked count would read a connection
// that does not exist.
func TestASpareIsDialledWithoutFastOpen(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := clientParams{ServerAddr: l.Addr().String(), FastOpen: true, DialTimeout: 5 * time.Second}

	var p prewarmPool
	p.on = true
	p.lastKey = spareKey(cfg)
	p.fill(cfg, p.lastKey, p.gen)
	defer p.stop()
	if p.spare == nil {
		t.Fatal("no spare")
	}
	if got := fastOpenConnect(t, p.spare.conn); got != 0 {
		t.Fatalf("the spare has TCP_FASTOPEN_CONNECT = %d", got)
	}

	tunnel, err := dialServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if got := fastOpenConnect(t, tunnel); got != 1 {
		t.Fatalf("a tunnel dialled at once has TCP_FASTOPEN_CONNECT = %d", got)
	}
}

// tfoClient serves the client's SOCKS5 port with cp and returns its address.
func tfoClient(t *testing.T, cp clientParams) string {
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

// pingThrough opens a stream to echo through the client and checks that it
// carries bytes, then returns with the stream still open.
func pingThrough(t *testing.T, proxy, echo string) net.Conn {
	t.Helper()
	c, reply := socksConnect(t, proxy, echo, []byte("ping"))
	if reply[1] != socks5Success {
		t.Fatalf("reply %v", reply)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q, %v", got, err)
	}
	return c
}

// With OBFS_TFO on both ends the tunnel works, and once the kernel holds the
// server's cookie, the opening, the greeting and the request of the next
// tunnel go in its SYN.
func TestATunnelWithFastOpenSendsItsRequestInTheSYN(t *testing.T) {
	if !netnstest.FastOpen(t) {
		return
	}
	logs := captureLogs(t)
	server, _ := startTunnelServerWith(t, func(c *s5server.Config) { c.ObfsTFO = true })
	echo := target(t, "")
	for _, optimistic := range []bool{false, true} {
		var d tunnelDials
		d.hook(t)
		proxy := tfoClient(t, clientParams{ServerAddr: server, PSK: "01234567890123456789012345678901", MTU: 1400,
			Transport: "obfs", HandshakeTimeout: 5 * time.Second, DialTimeout: 5 * time.Second,
			OptimisticConnect: optimistic, FastOpen: true})
		for range 2 {
			c := pingThrough(t, proxy, echo)
			tunnel, _, _ := d.last()
			carried, ok := tcptune.SYNData(tunnel)
			_ = c.Close()
			if !ok {
				t.Fatal("the kernel did not say whether the SYN carried data")
			}
			if carried {
				break
			}
		}
		tunnel, n, viaFastOpen := d.last()
		if viaFastOpen != n {
			t.Fatalf("optimistic=%v: %d of %d tunnels dialled with TCP Fast Open", optimistic, viaFastOpen, n)
		}
		if carried, _ := tcptune.SYNData(tunnel); !carried {
			t.Fatalf("optimistic=%v: the second tunnel carried nothing in its SYN", optimistic)
		}
	}
	if !strings.Contains(logs.String(), "syn_data=true") {
		t.Fatalf("no debug line says the SYN carried data:\n%s", logs.String())
	}
}

// OBFS_TFO off is the dial the client always made: the same dialler, no
// option on the socket, nothing in a SYN, whatever the sysctl allows.
func TestWithoutFastOpenTheTunnelIsDialledAsBefore(t *testing.T) {
	logs := captureLogs(t)
	server, _ := startTunnelServer(t, false)
	echo := target(t, "")
	var d tunnelDials
	d.hook(t)
	proxy := tfoClient(t, clientParams{ServerAddr: server, PSK: "01234567890123456789012345678901", MTU: 1400,
		Transport: "obfs", HandshakeTimeout: 5 * time.Second, DialTimeout: 5 * time.Second})
	for i := range 2 {
		c := pingThrough(t, proxy, echo)
		tunnel, _, _ := d.last()
		if got := fastOpenConnect(t, tunnel); got != 0 {
			t.Fatalf("tunnel %d: TCP_FASTOPEN_CONNECT = %d", i+1, got)
		}
		if carried, _ := tcptune.SYNData(tunnel); carried {
			t.Fatalf("tunnel %d carried data in its SYN", i+1)
		}
		_ = c.Close()
	}
	if _, n, viaFastOpen := d.last(); n != 2 || viaFastOpen != 0 {
		t.Fatalf("%d tunnels, %d of them through the fast open dialler", n, viaFastOpen)
	}
	if strings.Contains(logs.String(), "Fast Open") {
		t.Fatalf("TCP Fast Open is mentioned with OBFS_TFO off:\n%s", logs.String())
	}
}

func fastOpenParams(server string, optimistic bool) clientParams {
	return clientParams{ServerAddr: server, PSK: "01234567890123456789012345678901", MTU: 1400,
		Transport: "obfs", HandshakeTimeout: 10 * time.Second, DialTimeout: 5 * time.Second,
		OptimisticConnect: optimistic, FastOpen: true}
}

// fetchCookie leaves the kernel holding a Fast Open cookie for 127.0.0.1,
// which it keeps by address and not by port.
func fetchCookie(t *testing.T) {
	t.Helper()
	l, err := (&net.ListenConfig{Control: tcptune.ListenFastOpen(nil)}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := dialFastOpen(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	c, err = dialFastOpen(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if waiting, _ := tcptune.SYNSent(c); !waiting {
		t.Fatal("the kernel holds no cookie: connect() waited for the handshake")
	}
}

func unusedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func waitLog(t *testing.T, logs *syncBuffer, what string) string {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, what) {
				return line
			}
		}
	}
	t.Fatalf("no log line with %q:\n%s", what, logs.String())
	return ""
}

// With a cookie connect() returns before the handshake, so a node that is
// down shows at the first read. That is still a failure of the dial: no hint
// about the PSK and the clock, and a path that drops the SYN is given up at
// DIAL_TIMEOUT, not at HANDSHAKE_TIMEOUT.
func TestAFastOpenTunnelThatNeverReachedTheServerFailsAtTheDial(t *testing.T) {
	if !netnstest.Namespace(t) {
		return
	}
	t.Cleanup(noFastOpenAt.Clear)
	fetchCookie(t)
	refused, dropped := unusedPort(t), unusedPort(t)
	netnstest.Nft(t, fmt.Sprintf("table inet tfo_dial {\n chain in {\n type filter hook input priority 0;\n tcp dport %d drop\n }\n}\n", portOf(t, dropped)))
	echo := target(t, "")
	// The handshake deadline counts from before the dial, so where it is the
	// shorter one it ends the wait first, with the socket still in SYN_SENT.
	for _, tc := range []struct {
		name      string
		server    string
		dial      time.Duration
		handshake time.Duration
		within    time.Duration
	}{
		{"refused", refused, 300 * time.Millisecond, 10 * time.Second, time.Second},
		{"dropped", dropped, 300 * time.Millisecond, 10 * time.Second, 2 * time.Second},
		{"dropped, handshake shorter", dropped, 10 * time.Second, 300 * time.Millisecond, 2 * time.Second},
	} {
		for _, optimistic := range []bool{false, true} {
			noFastOpenAt.Clear()
			logs := captureLogs(t)
			cfg := fastOpenParams(tc.server, optimistic)
			cfg.DialTimeout, cfg.HandshakeTimeout = tc.dial, tc.handshake
			proxy := tfoClient(t, cfg)
			start := time.Now()
			c, reply := socksConnect(t, proxy, echo, nil)
			if optimistic {
				if _, err := c.Read(make([]byte, 1)); err == nil {
					t.Fatalf("%s optimistic: the application read from a tunnel that failed", tc.name)
				}
			} else if reply[1] == socks5Success {
				t.Fatalf("%s: the setup succeeded", tc.name)
			}
			line := waitLog(t, logs, "Tunnel setup")
			elapsed := time.Since(start)
			if !strings.Contains(line, "phase=dial") || !strings.Contains(line, "was not reached") || strings.Contains(line, "hint=") {
				t.Errorf("%s optimistic=%v: %s", tc.name, optimistic, line)
			}
			if tc.name != "refused" && elapsed < min(tc.dial, tc.handshake) {
				t.Errorf("%s optimistic=%v: failed after %v, before the budget", tc.name, optimistic, elapsed)
			}
			if elapsed > tc.within {
				t.Errorf("%s optimistic=%v: failed after %v, want within %v", tc.name, optimistic, elapsed, tc.within)
			}
			if !fastOpenRested(nativeKey(cfg)) {
				t.Errorf("%s optimistic=%v: the node is still dialled with Fast Open", tc.name, optimistic)
			}
			waitLog(t, logs, "The server was not reached; dialling it without TCP Fast Open")
			if strings.Contains(logs.String(), "Fast Open to the server failed") {
				t.Errorf("%s optimistic=%v: a node that was not reached is said to fail Fast Open", tc.name, optimistic)
			}
		}
	}

	// Whatever deadline ends the wait, a socket still in SYN_SENT never
	// reached the server.
	raw, err := dialFastOpen(context.Background(), "tcp", dropped)
	if err != nil {
		t.Fatal(err)
	}
	c := newFastOpenConn(raw, "any deadline", time.Time{}, false)
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	var unreached *unreachedError
	if !errors.As(err, &unreached) || !isTimeout(err) {
		t.Fatalf("a read that timed out in SYN_SENT: %v", err)
	}
}

// The kernel does not stop putting data in the SYNs to a node whose path
// drops them; each tunnel would pay a SYN retransmit, a second at least. The
// client stops after the first.
func TestANodeThatDropsSYNDataIsDialledWithoutFastOpen(t *testing.T) {
	if !netnstest.Namespace(t) {
		return
	}
	t.Cleanup(noFastOpenAt.Clear)
	logs := captureLogs(t)
	server, _ := startTunnelServerWith(t, func(c *s5server.Config) { c.ObfsTFO = true })
	echo := target(t, "")
	var d tunnelDials
	d.hook(t)
	proxy := tfoClient(t, fastOpenParams(server, false))
	_ = pingThrough(t, proxy, echo).Close()

	// A SYN with no data is under 100 bytes, one with the opening is over.
	netnstest.Nft(t, fmt.Sprintf("table inet tfo_data {\n chain in {\n type filter hook input priority 0;\n"+
		" tcp dport %d tcp flags & (syn | ack) == syn ip length > 100 drop\n }\n}\n", portOf(t, server)))
	start := time.Now()
	_ = pingThrough(t, proxy, echo).Close()
	slow := time.Since(start)
	if slow < 900*time.Millisecond {
		t.Fatalf("the tunnel took %v: the SYN with data was not dropped, or not sent", slow)
	}
	tunnel, _, _ := d.last()
	if carried, _ := tcptune.SYNData(tunnel); carried {
		t.Fatal("the SYN carried data through a path that drops it")
	}
	waitLog(t, logs, "TCP Fast Open to the server failed")

	start = time.Now()
	_ = pingThrough(t, proxy, echo).Close()
	fast := time.Since(start)
	if _, n, viaFastOpen := d.last(); n != 3 || viaFastOpen != 2 {
		t.Fatalf("%d tunnels, %d of them with Fast Open; want the third without", n, viaFastOpen)
	}
	if fast > 500*time.Millisecond {
		t.Fatalf("the tunnel after the first drop took %v (the one that met it %v)", fast, slow)
	}
	t.Logf("the tunnel that met the drop: %v, the next one: %v", slow, fast)
}

func setFastOpenKey(t *testing.T) {
	t.Helper()
	k := make([]byte, 16)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%x-%x-%x-%x", k[0:4], k[4:8], k[8:12], k[12:16])
	if err := os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen_key", []byte(key), 0); err != nil {
		t.Fatal(err)
	}
}

// A server whose Fast Open key changed - a new container, a new network
// namespace - answers a SYN with an old cookie without taking its data, and
// hands out a new cookie: the node keeps Fast Open. A kernel that does not
// say why (older than 5.5) cannot tell this from a path that drops SYNs with
// data, and the node is dialled without it for a while.
func TestANodeWhoseKeyChangedKeepsFastOpen(t *testing.T) {
	if !netnstest.Namespace(t) {
		return
	}
	for _, oldKernel := range []bool{false, true} {
		noFastOpenAt.Clear()
		if oldKernel {
			fastOpenCause = func(net.Conn) (int, bool) { return tcptune.FastOpenFailUnknown, true }
		}
		t.Cleanup(func() { fastOpenCause = tcptune.FastOpenClientFail; noFastOpenAt.Clear() })
		logs := captureLogs(t)
		server, _ := startTunnelServerWith(t, func(c *s5server.Config) { c.ObfsTFO = true })
		echo := target(t, "")
		var d tunnelDials
		d.hook(t)
		proxy := tfoClient(t, fastOpenParams(server, false))
		_ = pingThrough(t, proxy, echo).Close()
		_ = pingThrough(t, proxy, echo).Close()

		setFastOpenKey(t)
		_ = pingThrough(t, proxy, echo).Close()
		tunnel, _, _ := d.last()
		if carried, _ := tcptune.SYNData(tunnel); carried {
			t.Fatalf("old kernel %v: the SYN carried data with a cookie of the old key", oldKernel)
		}
		_ = pingThrough(t, proxy, echo).Close()
		tunnel, n, viaFastOpen := d.last()
		carried, _ := tcptune.SYNData(tunnel)
		failed := strings.Contains(logs.String(), "TCP Fast Open to the server failed")
		if oldKernel {
			if !failed || viaFastOpen != 3 || carried {
				t.Errorf("old kernel: %d of %d tunnels with Fast Open, the last carried data %v, logged:\n%s", viaFastOpen, n, carried, logs.String())
			}
			continue
		}
		if failed || viaFastOpen != 4 || !carried {
			t.Errorf("%d of %d tunnels with Fast Open, the last carried data %v, logged:\n%s", viaFastOpen, n, carried, logs.String())
		}
	}
}

func TestOnlyASYNSentAgainWithoutItsDataCountsAsAFailure(t *testing.T) {
	for _, tc := range []struct {
		carried bool
		cause   int
		want    bool
	}{
		{true, tcptune.FastOpenFailUnknown, false},
		{false, tcptune.FastOpenFailUnknown, true},
		{false, tcptune.FastOpenNoCookie, false},
		{false, tcptune.FastOpenDataNotAcked, false},
		{false, tcptune.FastOpenSYNRetransmitted, true},
	} {
		if got := fastOpenFailed(tc.carried, tc.cause); got != tc.want {
			t.Errorf("carried %v, cause %d: failed %v, want %v", tc.carried, tc.cause, got, tc.want)
		}
	}
}

// scriptedConn reads what it is given and then an error.
type scriptedConn struct {
	net.Conn
	reads []any
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	next := c.reads[0]
	c.reads = c.reads[1:]
	if err, ok := next.(error); ok {
		return 0, err
	}
	return copy(b, next.([]byte)), nil
}

// Once the server has answered, the node was reached: a refusal after that
// is the server's, not the dial's.
func TestAFailureAfterTheServerAnsweredIsNotTheDials(t *testing.T) {
	pipe, _ := net.Pipe()
	defer pipe.Close()
	c := newFastOpenConn(&scriptedConn{Conn: pipe, reads: []any{[]byte("ok"), syscall.ECONNREFUSED}}, "answered", time.Time{}, false)
	if _, err := c.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 2))
	var unreached *unreachedError
	if !errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &unreached) {
		t.Fatalf("a refusal after the answer: %v", err)
	}
}

// A kernel without TCP_FASTOPEN_CONNECT costs one debug line, whether the
// startup check or a dial finds it, and the startup line does not say that
// Fast Open is on.
func TestTheClientSaysOnceThatTheKernelRefusesFastOpen(t *testing.T) {
	logs := captureLogs(t)
	fastOpenRefusedSaid = sync.Once{}
	probe := probeFastOpen
	t.Cleanup(func() { fastOpenRefusedSaid, probeFastOpen = sync.Once{}, probe })
	probeFastOpen = func() error { return unix.ENOPROTOOPT }
	checkFastOpen(clientParams{FastOpen: true})

	// The option on a socket that is not TCP is refused by the kernel itself.
	sock := t.TempDir() + "/s"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for range 2 {
		c, err := dialFastOpen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatalf("a refused option failed the dial: %v", err)
		}
		_ = c.Close()
	}
	if n := strings.Count(logs.String(), "TCP Fast Open is not available"); n != 1 {
		t.Fatalf("%d lines about the refusal:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "TCP Fast Open on") {
		t.Fatalf("the startup line says Fast Open is on:\n%s", logs.String())
	}
}

func TestTheClientSaysAtStartupWhatFastOpenDoes(t *testing.T) {
	if err := tcptune.ProbeFastOpenConnect(); err != nil {
		t.Skipf("the kernel has no TCP_FASTOPEN_CONNECT: %v", err)
	}
	logs := captureLogs(t)
	checkFastOpen(clientParams{})
	if logs.String() != "" {
		t.Fatalf("OBFS_TFO off says something:\n%s", logs.String())
	}
	checkFastOpen(clientParams{FastOpen: true})
	want := "TCP Fast Open on the obfs transport"
	if mode, _ := tcptune.FastOpenMode(); mode&tcptune.FastOpenClient == 0 {
		want = "does not let the client send data in a SYN"
	}
	if !strings.Contains(logs.String(), want) {
		t.Fatalf("want %q:\n%s", want, logs.String())
	}
}
