package socks5

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func fallbackDNS(t *testing.T, ips []net.IP, delay time.Duration) *atomic.Int32 {
	t.Helper()
	u, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", u.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; u.Close() })
	calls := new(atomic.Int32)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, e := u.ReadFrom(buf)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			calls.Add(1)
			go func(q dnsmessage.Message, a net.Addr) {
				time.Sleep(delay)
				resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: q.Questions}
				for _, v := range q.Questions {
					if v.Type == dnsmessage.TypeA {
						for _, ip := range ips {
							resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: v.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte(ip.To4())}})
						}
					}
				}
				b, _ := resp.Pack()
				u.WriteTo(b, a)
			}(q, a)
		}
	}()
	return calls
}
func fallbackTarget(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	return l.Addr().String()
}
func TestDNSFallbackConnect(t *testing.T) {
	addr := fallbackTarget(t)
	_, port, _ := net.SplitHostPort(addr)
	fallbackDNS(t, []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.1")}, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", "fallback.audit.")
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("DNS addresses=%v", ips)
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("fallback.audit.", port))
	if e != nil {
		t.Fatal("direct fallback", e)
	}
	c.Close()
	p, _ := net.LookupPort("tcp", port)
	s, e := New(&Config{})
	if e != nil {
		t.Fatal(e)
	}
	req := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{FQDN: "fallback.audit.", Port: p}, bufConn: bytes.NewReader(nil)}
	out := new(MockConn)
	start := time.Now()
	e = s.handleRequest(ctx, req, out)
	t.Logf("SOCKS err=%v elapsed=%s reply=%x selected=%s", e, time.Since(start), out.buf.Bytes(), req.DestAddr.IP)
	if e != nil {
		t.Fatal("fallback failed", e)
	}
	if !req.DestAddr.IP.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatal("unexpected DNS order")
	}
}
func TestDNSPhaseMeasuresLookup(t *testing.T) {
	addr := fallbackTarget(t)
	_, port, _ := net.SplitHostPort(addr)
	calls := fallbackDNS(t, []net.IP{net.ParseIP("127.0.0.1")}, 200*time.Millisecond)
	p, _ := net.LookupPort("tcp", port)
	for i := 0; i < 3; i++ {
		observed := make(map[Phase]time.Duration)
		s, e := New(&Config{ObservePhase: func(p Phase, d time.Duration, _ bool) { observed[p] = d }})
		if e != nil {
			t.Fatal(e)
		}
		req := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{FQDN: "slow.audit.", Port: p}, bufConn: bytes.NewReader(nil)}
		out := new(MockConn)
		start := time.Now()
		e = s.handleRequest(context.Background(), req, out)
		if e != nil {
			t.Fatal(e)
		}
		total := time.Since(start)
		t.Logf("DNSMETRIC request=%d total=%s phases=%s dns_packets=%d", i, total, fmt.Sprint(observed), calls.Load())
		if observed[PhaseDNS] < 190*time.Millisecond || observed[PhaseDial] >= observed[PhaseDNS] || total < observed[PhaseDNS] {
			t.Fatal("unexpected measurement")
		}
	}
}

type candidateResolver struct{ ips []net.IP }

func (r candidateResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, r.ips[0], nil
}
func (r candidateResolver) ResolveAll(ctx context.Context, _ string) (context.Context, []net.IP, error) {
	return ctx, r.ips, nil
}

type candidateRules struct{ allowed string }

func (r candidateRules) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	return ctx, req.DestAddr.IP == nil || req.DestAddr.IP.String() == r.allowed
}

type fixedRewrite struct{ dest *AddrSpec }

func (r fixedRewrite) Rewrite(ctx context.Context, _ *Request) (context.Context, *AddrSpec) {
	return ctx, r.dest
}

func TestFallbackRespectsPolicyAndRewrite(t *testing.T) {
	for _, rewrite := range []bool{false, true} {
		t.Run(fmt.Sprint(rewrite), func(t *testing.T) {
			target := fallbackTarget(t)
			host, port, _ := net.SplitHostPort(target)
			p, _ := net.LookupPort("tcp", port)
			cfg := &Config{Resolver: candidateResolver{[]net.IP{net.ParseIP("127.0.0.2"), net.ParseIP(host)}}, Rules: candidateRules{host}}
			if rewrite {
				cfg.Rewriter = fixedRewrite{&AddrSpec{IP: net.ParseIP("127.0.0.3"), Port: p}}
			}
			var attempted []string
			cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				attempted = append(attempted, addr)
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			req := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{FQDN: "policy.invalid", Port: p}, bufConn: bytes.NewReader(nil)}
			err = s.handleRequest(context.Background(), req, new(MockConn))
			if rewrite {
				if err == nil || len(attempted) != 1 || attempted[0] != net.JoinHostPort("127.0.0.3", port) {
					t.Fatalf("rewrite escaped: %v %v", attempted, err)
				}
			} else if err != nil || len(attempted) != 1 || attempted[0] != target {
				t.Fatalf("policy escaped: %v %v", attempted, err)
			}
		})
	}
}

func TestDNSFailureIsObserved(t *testing.T) {
	fallbackDNS(t, nil, 50*time.Millisecond)
	observed := make(chan bool, 1)
	s, err := New(&Config{ObservePhase: func(p Phase, d time.Duration, ok bool) {
		if p == PhaseDNS {
			observed <- !ok && d >= 40*time.Millisecond
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{FQDN: "missing.audit.", Port: 443}, bufConn: bytes.NewReader(nil)}
	if err := s.handleRequest(context.Background(), req, new(MockConn)); err == nil {
		t.Fatal("expected DNS error")
	}
	select {
	case ok := <-observed:
		if !ok {
			t.Fatal("incorrect DNS failure metric")
		}
	default:
		t.Fatal("missing DNS failure metric")
	}
}

func TestInvalidResolvedSetCannotTriggerAnotherLookup(t *testing.T) {
	s, err := New(&Config{Resolver: candidateResolver{[]net.IP{nil}}, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial called with invalid DNS result")
		return nil, fmt.Errorf("unexpected dial")
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := &Request{Command: ConnectCommand, DestAddr: &AddrSpec{FQDN: "invalid.audit.", Port: 443}, bufConn: bytes.NewReader(nil)}
	if err := s.handleRequest(context.Background(), req, new(MockConn)); err == nil {
		t.Fatal("invalid DNS result accepted")
	}
}
