package socks5

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// A host without IPv6 fails the v6 address at once with ENETUNREACH. That
// says nothing about the target, so when v4 then times out the client is told
// about the timeout, not about a route this host never had.
func TestAMissingRouteDoesNotNameTheFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		timeout := errors.New("dial tcp 192.0.2.1:80: i/o timeout")
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "[") {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
			}
			return nil, timeout
		}
		_, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "[2001:db8::1]:80"}, {ctx: ctx, addr: "192.0.2.1:80"}})
		if !errors.Is(err, timeout) {
			t.Fatalf("got %v, want the v4 timeout", err)
		}
	})
}

// Both families answering keeps net.Dialer's rule: the preferred one names it.
func TestThePreferredFamilyStillNamesARealFailure(t *testing.T) {
	ctx := context.Background()
	refused := errors.New("connection refused")
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		if addr == "a" {
			return nil, refused
		}
		return nil, errors.New("i/o timeout")
	}
	if _, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "a"}, {ctx: ctx, addr: "b"}}); !errors.Is(err, refused) {
		t.Fatalf("got %v, want the first real failure", err)
	}
}

// A timeout cut from a resolver-values context used to park one goroutine per
// attempt: WithTimeout could not find the lifetime's cancelCtx through Value.
func TestADerivedDeadlineCostsNoGoroutine(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	type key struct{}
	v := keepValues(lifetime, context.WithValue(context.Background(), key{}, 1))

	before := runtime.NumGoroutine()
	stops := make([]context.CancelFunc, 0, 100)
	children := make([]context.Context, 0, 100)
	for i := 0; i < 100; i++ {
		c, stop := context.WithTimeout(v, time.Hour)
		children = append(children, c)
		stops = append(stops, stop)
	}
	if grown := runtime.NumGoroutine() - before; grown > 5 {
		t.Errorf("100 derived deadlines started %d goroutines", grown)
	}
	if children[0].Value(key{}) != 1 {
		t.Error("the resolver's value was lost")
	}
	cancel()
	for _, c := range children {
		select {
		case <-c.Done():
		case <-time.After(time.Second):
			t.Fatal("cancelling the lifetime did not reach a derived context")
		}
	}
	for _, stop := range stops {
		stop()
	}
}

func TestInterleaveDropsMappedDuplicates(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("::ffff:192.0.2.1").To16(), net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.2"), {1, 2, 3}}
	got := interleaveIPs(ips)
	want := []string{"192.0.2.1", "2001:db8::1", "192.0.2.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// One address takes the whole budget and no race machinery.
func TestASingleAddressDialsInline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	var sawDeadline time.Time
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		sawDeadline, _ = ctx.Deadline()
		return a, nil
	}
	c, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "only"}})
	if err != nil || c != a {
		t.Fatalf("got %v, %v", c, err)
	}
	c.Close()
	if want, _ := ctx.Deadline(); !sawDeadline.Equal(want) {
		t.Fatalf("attempt deadline %v, want the whole budget %v", sawDeadline, want)
	}
	cancel()
	if _, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "only"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled request dialled anyway: %v", err)
	}
}
