package tcptune

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/mazixs/S5Core/internal/netnstest"
	"golang.org/x/sys/unix"
)

func sockopt(t *testing.T, c syscall.Conn, opt int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func TestTheListenerAcceptsSYNDataOnlyWhenAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		lc   net.ListenConfig
		want int
	}{
		{"on", net.ListenConfig{Control: ListenFastOpen(skipRefused(t))}, fastOpenQueue},
		{"off", net.ListenConfig{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := tc.lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			if got := sockopt(t, l.(*net.TCPListener), unix.TCP_FASTOPEN); got != tc.want {
				t.Fatalf("TCP_FASTOPEN = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTheDialerSendsSYNDataOnlyWhenAsked(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, tc := range []struct {
		name string
		d    net.Dialer
		want int
	}{
		{"on", net.Dialer{Control: DialFastOpen(skipRefused(t))}, 1},
		{"off", net.Dialer{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.d.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if got := sockopt(t, c.(*net.TCPConn), unix.TCP_FASTOPEN_CONNECT); got != tc.want {
				t.Fatalf("TCP_FASTOPEN_CONNECT = %d, want %d", got, tc.want)
			}
			if on, ok := DialsFastOpen(c); !ok || on != (tc.want == 1) {
				t.Fatalf("DialsFastOpen = %v, %v", on, ok)
			}
		})
	}
}

// A kernel without the option (a router on 4.9) costs a debug line, not the
// listener or the dial.
func TestARefusedOptionFailsNothing(t *testing.T) {
	refusal := errors.New("ENOPROTOOPT")
	var said []error
	control := fastOpenControl(func(uintptr) error { return refusal }, func(err error) { said = append(said, err) })
	l, err := (&net.ListenConfig{Control: control}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the listen failed with the option: %v", err)
	}
	defer l.Close()
	c, err := (&net.Dialer{Control: control}).Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("the dial failed with the option: %v", err)
	}
	c.Close()
	if len(said) != 2 || !errors.Is(said[0], refusal) {
		t.Fatalf("refusals said: %v", said)
	}
}

// skipRefused skips a test on a kernel without the option (ENOPROTOOPT,
// EOPNOTSUPP), which is not what it checks.
func skipRefused(t *testing.T) func(error) {
	return func(err error) {
		if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("the kernel has no such option: %v", err)
		}
		t.Fatalf("refused: %v", err)
	}
}

func TestTheProbeAsksForTheOptionTheDialSets(t *testing.T) {
	if err := ProbeFastOpenConnect(); err != nil {
		skipRefused(t)(err)
	}
}

// The first connection to an address fetches the cookie, the second puts its
// first write in the SYN, and both ends say so. The namespace is new, so the
// kernel holds no cookie from before.
func TestTheSecondConnectionCarriesDataInItsSYN(t *testing.T) {
	if !netnstest.FastOpen(t) {
		return
	}
	l, err := (&net.ListenConfig{Control: ListenFastOpen(skipRefused(t))}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d := net.Dialer{Control: DialFastOpen(skipRefused(t))}
	passive, _ := FastOpenPassive()
	for i := range 2 {
		c, err := d.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		// With the cookie, the one the first connection fetched, connect()
		// returns before the handshake; without it, after.
		if waiting, ok := SYNSent(c); !ok || waiting != (i == 1) {
			t.Errorf("connection %d: SYN_SENT after the dial %v (%v)", i+1, waiting, ok)
		}
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		client, cok := SYNData(c)
		server, sok := SYNData(s)
		if !cok || !sok || client != server {
			t.Errorf("connection %d: client SYN data %v (%v), server %v (%v)", i+1, client, cok, server, sok)
		}
		if client != (i == 1) {
			t.Errorf("connection %d carried data in its SYN: %v", i+1, client)
		}
		c.Close()
		s.Close()
	}
	if now, ok := FastOpenPassive(); !ok || now <= passive {
		t.Errorf("TCPFastOpenPassive %d -> %d (%v), want it to grow", passive, now, ok)
	}
}

// On a connection without Fast Open the kernel still answers: no data in the
// SYN, the handshake done. Something that is not a socket gets no answer.
func TestTheKernelAnswersForAnOrdinaryConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if carried, ok := SYNData(c); !ok || carried {
		t.Fatalf("SYNData = %v, %v", carried, ok)
	}
	if waiting, ok := SYNSent(c); !ok || waiting {
		t.Fatalf("SYNSent = %v, %v", waiting, ok)
	}
	if _, ok := FastOpenMode(); !ok {
		t.Fatal("net.ipv4.tcp_fastopen was not read")
	}
	if _, ok := FastOpenPassive(); !ok {
		t.Fatal("TCPFastOpenPassive was not read")
	}
	pipe, _ := net.Pipe()
	defer pipe.Close()
	if _, ok := SYNData(pipe); ok {
		t.Fatal("a pipe has SYN data")
	}
	if _, ok := SYNSent(pipe); ok {
		t.Fatal("a pipe has a TCP state")
	}
	if _, ok := DialsFastOpen(pipe); ok {
		t.Fatal("a pipe has a TCP option")
	}
	if cause, ok := FastOpenClientFail(c); !ok || cause != FastOpenFailUnknown {
		t.Fatalf("FastOpenClientFail = %d, %v", cause, ok)
	}
	if _, ok := FastOpenClientFail(pipe); ok {
		t.Fatal("a pipe has a Fast Open failure")
	}
}

// The two bits sit at the low end of their byte on a little-endian machine,
// past tcpi_delivery_rate_app_limited, and at the high end on a big-endian
// one; the bits around them are not theirs.
func TestTheCauseIsReadFromItsBitsOnEitherEnd(t *testing.T) {
	for cause := range 4 {
		for _, around := range []byte{0, 0xff} {
			little := byte(cause)<<1 | around&^0b110
			big := byte(cause)<<5 | around&^0b1100000
			if got := clientFail(little, true); got != cause {
				t.Errorf("little-endian %08b: %d, want %d", little, got, cause)
			}
			if got := clientFail(big, false); got != cause {
				t.Errorf("big-endian %08b: %d, want %d", big, got, cause)
			}
		}
	}
}

func kernelAtLeast(t *testing.T, major, minor int) bool {
	t.Helper()
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}
	var ma, mi int
	if _, err := fmt.Sscanf(unix.ByteSliceToString(u.Release[:]), "%d.%d", &ma, &mi); err != nil {
		t.Fatal(err)
	}
	return ma > major || ma == major && mi >= minor
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

// The kernel tells a server whose key changed, which takes the SYN and not
// its data and gives a new cookie, from a path that drops SYNs with data,
// where the SYN goes again without it; a connection that carried its data
// has no cause.
func TestTheKernelSaysWhySYNDataDidNotGetThrough(t *testing.T) {
	if !netnstest.Namespace(t) {
		return
	}
	if !kernelAtLeast(t, 5, 5) {
		t.Skip("tcpi_fastopen_client_fail is Linux 5.5 and later")
	}
	l, err := (&net.ListenConfig{Control: ListenFastOpen(skipRefused(t))}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d := net.Dialer{Control: DialFastOpen(skipRefused(t))}
	exchange := func() (carried bool, cause int) {
		t.Helper()
		c, err := d.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(make([]byte, 200)); err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := io.ReadFull(s, make([]byte, 200)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		carried, _ = SYNData(c)
		cause, ok := FastOpenClientFail(c)
		if !ok {
			t.Fatal("tcpi_fastopen_client_fail was not read")
		}
		return carried, cause
	}
	exchange()
	for _, step := range []struct {
		name    string
		before  func()
		carried bool
		cause   int
	}{
		{"with the cookie", func() {}, true, FastOpenFailUnknown},
		{"after the server's key changed", func() { setFastOpenKey(t) }, false, FastOpenDataNotAcked},
		{"with the new cookie", func() {}, true, FastOpenFailUnknown},
		{"through a path that drops SYNs with data", func() {
			netnstest.Nft(t, fmt.Sprintf("table inet tfo_cause {\n chain in {\n type filter hook input priority 0;\n"+
				" tcp dport %d tcp flags & (syn | ack) == syn ip length > 100 drop\n }\n}\n", l.Addr().(*net.TCPAddr).Port))
		}, false, FastOpenSYNRetransmitted},
	} {
		step.before()
		if carried, cause := exchange(); carried != step.carried || cause != step.cause {
			t.Errorf("%s: SYN data %v, cause %d; want %v, %d", step.name, carried, cause, step.carried, step.cause)
		}
	}
}

func TestParseNetstat(t *testing.T) {
	const sample = "TcpExt: SyncookiesSent TCPFastOpenActive TCPFastOpenPassive TCPFastOpenPassiveFail\n" +
		"TcpExt: 0 7 42 1\n" +
		"IpExt: InNoRoutes TCPFastOpenPassive\n" +
		"IpExt: 0 9\n"
	if n, ok := parseNetstat(sample, "TcpExt:", "TCPFastOpenPassive"); !ok || n != 42 {
		t.Fatalf("got %d %v, want 42", n, ok)
	}
	if _, ok := parseNetstat(sample, "TcpExt:", "Missing"); ok {
		t.Fatal("a missing counter was found")
	}
}
