package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
)

// countingResolver records every lookup it is asked for.
type countingResolver struct {
	calls atomic.Int32
	names []string
}

func (r *countingResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.calls.Add(1)
	r.names = append(r.names, name)
	return ctx, net.ParseIP("203.0.113.9"), nil
}

// denyAll refuses every request, the way a destination allow-list refuses a
// name that is not on it.
type denyAll struct{}

func (denyAll) Allow(ctx context.Context, _ *Request) (context.Context, bool) { return ctx, false }

func connectToFQDN(t *testing.T, fqdn string) *bytes.Buffer {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, ConnectCommand, 0, fqdnAddress, byte(len(fqdn))})
	buf.WriteString(fqdn)
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, 443)
	buf.Write(port)
	return buf
}

// The rule used to be checked inside the command handler, after the name had
// already been resolved. The connection was then refused, but the DNS query
// had gone out: anyone watching the server's own traffic learned the name the
// client asked for, which is precisely what a blocked destination must not
// reveal.
func TestABlockedNameIsNeverResolved(t *testing.T) {
	resolver := &countingResolver{}
	s := &Server{config: &Config{
		Rules:    denyAll{},
		Resolver: resolver,
		Logger:   slog.Default(),
	}}

	req, err := NewRequest(connectToFQDN(t, "blocked.example.com"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := &MockConn{}
	if err := s.handleRequest(context.Background(), req, resp); err == nil {
		t.Fatal("a blocked request was handled without error")
	}

	if got := resolver.calls.Load(); got != 0 {
		t.Errorf("the resolver was called %d time(s) for a blocked name: %v", got, resolver.names)
	}

	// The client is told the rules refused it, not that the host is down.
	out := resp.buf.Bytes()
	if len(out) < 2 || out[1] != ruleFailure {
		t.Errorf("expected a rule-failure reply, got % x", out)
	}
}

// The counterpart: an allowed name still reaches the resolver, so the check
// above is not passing simply because nothing resolves any more.
func TestAnAllowedNameStillReachesTheResolver(t *testing.T) {
	resolver := &countingResolver{}
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: resolver,
		Logger:   slog.Default(),
		// The dial is stubbed out: this test is about the lookup, and a real
		// dial to a documentation address would just sit there until it timed
		// out.
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial stubbed out")
		},
	}}

	req, err := NewRequest(connectToFQDN(t, "allowed.example.com"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The stubbed dial fails; only the lookup matters here.
	_ = s.handleRequest(context.Background(), req, &MockConn{})

	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("the resolver was called %d time(s), want 1", got)
	}
	if resolver.names[0] != "allowed.example.com" {
		t.Errorf("resolved %q, want allowed.example.com", resolver.names[0])
	}
}
