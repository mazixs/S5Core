package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// A UDP association names its destination once per datagram, in the SOCKS5
// UDP header, and that is the only place a UDP destination ever appears. The
// address in the ASSOCIATE request describes the client side of the
// association, so checking the rules there and nowhere else meant they were
// never checked against a destination at all.
//
// Finding F02 of docs/reports/code-quality-audit-2026-09-20.md.

// recordingRules allows the destinations it was given and remembers every
// question it was asked, so a test can tell "refused" from "never asked".
type recordingRules struct {
	allowed map[string]bool

	mu       sync.Mutex
	asked    []string
	datagram int
}

func (r *recordingRules) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.Datagram {
		r.datagram++
	}
	dest := ""
	if req.DestAddr != nil {
		if req.DestAddr.FQDN != "" {
			dest = req.DestAddr.FQDN
		} else {
			dest = req.DestAddr.Address()
		}
	}
	r.asked = append(r.asked, dest)
	if !req.Datagram {
		// The command itself: this test is about destinations.
		return ctx, true
	}
	return ctx, r.allowed[dest]
}

func (r *recordingRules) datagramQuestions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.datagram
}

// udpSink is a socket that records what reaches it. A destination that is off
// the allow-list must stay silent, and "silent" has to be observed at the
// destination rather than inferred from the proxy.
type udpSink struct {
	conn *net.UDPConn
	echo bool
}

func newUDPSink(t *testing.T, echo bool) *udpSink {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &udpSink{conn: conn, echo: echo}
	if echo {
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP(buf[:n], from)
			}
		}()
	}
	return s
}

func (s *udpSink) addr() *net.UDPAddr { return s.conn.LocalAddr().(*net.UDPAddr) }

func (s *udpSink) spec() *AddrSpec {
	a := s.addr()
	return &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: a.Port}
}

// receivedNothing waits out a grace period and reports whether the sink
// stayed silent.
func (s *udpSink) receivedNothing(t *testing.T, grace time.Duration) bool {
	t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(grace))
	buf := make([]byte, 2048)
	n, _, err := s.conn.ReadFromUDP(buf)
	if err == nil {
		t.Logf("the sink received %d bytes: %q", n, buf[:n])
		return false
	}
	return isTimeout(err)
}

// udpRuleServer starts a SOCKS5 server whose rules are under the test's
// control and returns it with its listener address.
func udpRuleServer(t *testing.T, rules RuleSet, resolver NameResolver) string {
	t.Helper()
	conf := &Config{
		BindIP:   net.ParseIP("127.0.0.1"),
		Rules:    rules,
		Resolver: resolver,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() { _ = server.ServeContext(ctx, ln) }()
	return ln.Addr().String()
}

// associateThrough runs the handshake and the ASSOCIATE request, naming the
// setup address the caller gives it, and returns the connection plus the
// reply.
func associateThrough(t *testing.T, addr string, command byte, setup []byte) (net.Conn, []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	req := append([]byte{0x05, command, 0x00}, setup...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("associate: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("associate refused: 0x%02x", reply[1])
	}
	return conn, reply
}

// F02, the RFC 1928 path. The setup request names the one allowed
// destination, and the datagrams name another.
func TestAnAssociationMayNotSendWhereItsRulesForbid(t *testing.T) {
	allowedSink := newUDPSink(t, true)
	forbiddenSink := newUDPSink(t, false)
	rules := &recordingRules{allowed: map[string]bool{allowedSink.spec().Address(): true}}
	addr := udpRuleServer(t, rules, &countingResolver{})

	// The setup request names the allowed destination, which is how the
	// check that only happens at setup is satisfied.
	allowed := allowedSink.addr()
	setup := []byte{0x01, 127, 0, 0, 1, byte(allowed.Port >> 8), byte(allowed.Port)}
	conn, reply := associateThrough(t, addr, AssociateCommand, setup)
	defer func() { _ = conn.Close() }()

	proxyUDP := &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(reply[8])<<8 | int(reply[9]),
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The forbidden destination first: a datagram the rules do not allow must
	// not reach it.
	blocked := BuildUDPHeader(forbiddenSink.spec(), []byte("where I was not allowed"))
	if _, err := client.WriteToUDP(blocked, proxyUDP); err != nil {
		t.Fatalf("send blocked: %v", err)
	}
	if !forbiddenSink.receivedNothing(t, 400*time.Millisecond) {
		t.Fatal("a datagram reached a destination the rules forbid")
	}

	// And the association is alive, so the silence above is a refusal and not
	// a broken relay.
	msg := []byte("where I was allowed")
	if _, err := client.WriteToUDP(BuildUDPHeader(allowedSink.spec(), msg), proxyUDP); err != nil {
		t.Fatalf("send allowed: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the allowed destination did not answer: %v", err)
	}
	hdrLen, _, err := ParseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("reply header: %v", err)
	}
	if !bytes.Equal(buf[hdrLen:n], msg) {
		t.Fatalf("echo returned %q, want %q", buf[hdrLen:n], msg)
	}

	if got := rules.datagramQuestions(); got < 2 {
		t.Fatalf("the rules were asked about %d datagrams, want one per datagram", got)
	}
}

// F02, the 0x83 path. The same association, the same rule, carried over TCP -
// the two handlers must not differ in what they allow.
func TestATunnelledAssociationMayNotSendWhereItsRulesForbid(t *testing.T) {
	allowedSink := newUDPSink(t, true)
	forbiddenSink := newUDPSink(t, false)
	rules := &recordingRules{allowed: map[string]bool{allowedSink.spec().Address(): true}}
	addr := udpRuleServer(t, rules, &countingResolver{})

	allowed := allowedSink.addr()
	setup := []byte{0x01, 127, 0, 0, 1, byte(allowed.Port >> 8), byte(allowed.Port)}
	conn, _ := associateThrough(t, addr, UDPTunnelCommand, setup)
	defer func() { _ = conn.Close() }()

	send := func(dest *AddrSpec, payload string) {
		t.Helper()
		body := BuildUDPHeader(dest, []byte(payload))
		frame := make([]byte, 2+len(body))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
		copy(frame[2:], body)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}

	send(forbiddenSink.spec(), "where I was not allowed")
	if !forbiddenSink.receivedNothing(t, 400*time.Millisecond) {
		t.Fatal("a tunnelled datagram reached a destination the rules forbid")
	}

	msg := "where I was allowed"
	send(allowedSink.spec(), msg)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("the allowed destination did not answer: %v", err)
	}
	frame := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err := io.ReadFull(conn, frame); err != nil {
		t.Fatalf("reply frame: %v", err)
	}
	hdrLen, _, err := ParseUDPHeader(frame)
	if err != nil {
		t.Fatalf("reply header: %v", err)
	}
	if string(frame[hdrLen:]) != msg {
		t.Fatalf("echo returned %q, want %q", frame[hdrLen:], msg)
	}

	if got := rules.datagramQuestions(); got < 2 {
		t.Fatalf("the rules were asked about %d datagrams, want one per datagram", got)
	}
}

// A refused name is never looked up, on the UDP path as on the CONNECT path:
// the query would tell a resolver - and anyone watching the server - what the
// client asked for, which is exactly what a blocked destination must not
// reveal.
func TestABlockedDatagramNameIsNeverResolved(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command byte
	}{
		{"associate", AssociateCommand},
		{"tunnelled", UDPTunnelCommand},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &countingResolver{}
			rules := &recordingRules{allowed: map[string]bool{}}
			addr := udpRuleServer(t, rules, resolver)

			conn, reply := associateThrough(t, addr, tc.command,
				[]byte{0x01, 0, 0, 0, 0, 0, 0})
			defer func() { _ = conn.Close() }()

			blocked := BuildUDPHeader(
				&AddrSpec{FQDN: "blocked.example.com", Port: 53},
				[]byte("a query nobody should see"))

			if tc.command == AssociateCommand {
				proxyUDP := &net.UDPAddr{
					IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
					Port: int(reply[8])<<8 | int(reply[9]),
				}
				client, err := net.ListenUDP("udp",
					&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
				if err != nil {
					t.Fatalf("client socket: %v", err)
				}
				defer func() { _ = client.Close() }()
				if _, err := client.WriteToUDP(blocked, proxyUDP); err != nil {
					t.Fatalf("send: %v", err)
				}
			} else {
				frame := make([]byte, 2+len(blocked))
				binary.BigEndian.PutUint16(frame[0:2], uint16(len(blocked)))
				copy(frame[2:], blocked)
				if _, err := conn.Write(frame); err != nil {
					t.Fatalf("write frame: %v", err)
				}
			}

			// Long enough for the datagram to have been handled; the
			// assertion is about what did not happen.
			deadline := time.Now().Add(time.Second)
			for rules.datagramQuestions() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if rules.datagramQuestions() == 0 {
				t.Fatal("the rules were never asked about the datagram")
			}
			if n := resolver.calls.Load(); n != 0 {
				t.Fatalf("a blocked name was resolved %d times", n)
			}
		})
	}
}
