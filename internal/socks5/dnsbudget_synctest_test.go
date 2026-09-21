package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// A client that has sent CONNECT is waiting for one reply, and everything
// between the request and that reply is the wait it experiences: the name
// lookup and the dial alike. The lookup used to run on the connection's own
// context, which carries no deadline, so a resolver that did not answer held
// the handler open past every timeout the session has (audit finding F12).
//
// These tests run in a testing/synctest bubble: the assertions are about
// exact moments ("at 10s, not at 16s"), and net.Pipe's deadlines follow the
// bubble's clock. A real socket's would not.

const testDialBudget = 10 * time.Second

// haltingResolver blocks until the lookup is cancelled, which is what a DNS
// server that stops answering looks like from here. The failsafe keeps a
// regression legible: without a deadline on the lookup this would block
// forever, and the bubble would report a deadlock instead of the test
// reporting what it measured.
type haltingResolver struct {
	failsafe time.Duration
	deadline chan time.Time
	// started, when set, reports that a lookup is under way, so a test can
	// wait for the association to be stuck rather than guess that it is.
	started chan struct{}
}

func (r *haltingResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if d, ok := ctx.Deadline(); ok {
		select {
		case r.deadline <- d:
		default:
		}
	}
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		return ctx, nil, ctx.Err()
	case <-time.After(r.failsafe):
		return ctx, nil, context.DeadlineExceeded
	}
}

// slowResolver answers, but only after spending part of the budget.
type slowResolver struct {
	takes time.Duration
}

func (r slowResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	select {
	case <-time.After(r.takes):
		return ctx, net.ParseIP("203.0.113.7"), nil
	case <-ctx.Done():
		return ctx, nil, ctx.Err()
	}
}

// serveInBubble runs one connection through the server without registering a
// cleanup: a bubble has to be empty of goroutines before the test function
// returns, so the caller stops it by hand.
func serveInBubble(t *testing.T, conf *Config, sla session.SLA) (client net.Conn, stop func()) {
	t.Helper()
	server, err := New(conf)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	sess := session.NewRegistry(nil).Open("plain", false, sla)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeConnContext(context.Background(), &sessionConn{Conn: serverSide, sess: sess})
	}()
	return clientSide, func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		<-done
	}
}

// connectToName sends a CONNECT naming an FQDN.
func connectToName(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	req := []byte{5, ConnectCommand, 0, fqdnAddress, byte(len(name))}
	req = append(req, name...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 443)
	if _, err := conn.Write(append(req, port...)); err != nil {
		t.Fatalf("connect request: %v", err)
	}
}

func readConnectReply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return reply
}

func TestALookupThatNeverAnswersIsCutOffAtTheDialBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resolver := &haltingResolver{failsafe: 10 * testDialBudget, deadline: make(chan time.Time, 1)}
		client, stop := serveInBubble(t, &Config{Resolver: resolver}, session.SLA{Dial: testDialBudget})
		defer stop()

		greet(t, client)
		start := time.Now()
		connectToName(t, client, "never.answers.example")

		reply := readConnectReply(t, client)
		waited := time.Since(start)
		if reply[1] != hostUnreachable {
			t.Fatalf("the reply is %#x, want host unreachable", reply[1])
		}
		if waited != testDialBudget {
			t.Fatalf("the client waited %s for its reply, want exactly the dial budget of %s", waited, testDialBudget)
		}
		select {
		case d := <-resolver.deadline:
			if want := start.Add(testDialBudget); !d.Equal(want) {
				t.Fatalf("the lookup was given a deadline of %s, want %s", d, want)
			}
		default:
			t.Fatal("the lookup ran with no deadline at all")
		}
	})
}

// The budget is for reaching the destination, not for each step of reaching
// it: a lookup that spends most of it leaves the dial with the rest.
func TestTheLookupAndTheDialShareOneBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const lookupTakes = 6 * time.Second

		dialDeadline := make(chan time.Time, 1)
		conf := &Config{
			Resolver: slowResolver{takes: lookupTakes},
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if d, ok := ctx.Deadline(); ok {
					dialDeadline <- d
				}
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		client, stop := serveInBubble(t, conf, session.SLA{Dial: testDialBudget})
		defer stop()

		greet(t, client)
		start := time.Now()
		connectToName(t, client, "slow.example")

		reply := readConnectReply(t, client)
		waited := time.Since(start)
		if reply[1] == successReply {
			t.Fatal("the dial that never connected was reported as a success")
		}
		if waited != testDialBudget {
			t.Fatalf("the client waited %s, want exactly %s: the lookup's %s has to come out of the same budget",
				waited, testDialBudget, lookupTakes)
		}
		select {
		case d := <-dialDeadline:
			if want := start.Add(testDialBudget); !d.Equal(want) {
				t.Fatalf("the dial was given until %s, want %s - it got a fresh budget rather than what the lookup left",
					d, want)
			}
		default:
			t.Fatal("the dial ran with no deadline at all")
		}
	})
}

// valueResolver answers immediately, hands back a context carrying a value,
// and puts a short deadline on it. Both are things a custom resolver is
// allowed to do; only one of them may survive the lookup.
type valueKey struct{}

type valueResolver struct {
	lifetime time.Duration
	cancels  chan context.CancelFunc
}

func (r *valueResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	withValue := context.WithValue(ctx, valueKey{}, name)
	short, cancel := context.WithTimeout(withValue, r.lifetime)
	r.cancels <- cancel
	return short, net.ParseIP("203.0.113.8"), nil
}

// seenValue records what the request context carried by the time the address
// was rewritten, which is the first place after the lookup that sees it.
type seenValue struct {
	got chan any
}

func (r *seenValue) Rewrite(ctx context.Context, req *Request) (context.Context, *AddrSpec) {
	r.got <- ctx.Value(valueKey{})
	return ctx, req.DestAddr
}

func TestWhatTheResolverAddsSurvivesButItsDeadlineDoesNot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const lookupLifetime = time.Second

		resolver := &valueResolver{lifetime: lookupLifetime, cancels: make(chan context.CancelFunc, 1)}
		rewriter := &seenValue{got: make(chan any, 1)}
		target, destination := net.Pipe()
		conf := &Config{
			Resolver: resolver,
			Rewriter: rewriter,
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return destination, nil
			},
		}
		client, stop := serveInBubble(t, conf, session.SLA{Dial: testDialBudget})
		defer func() {
			_ = target.Close()
			_ = destination.Close()
			stop()
			(<-resolver.cancels)()
		}()

		greet(t, client)
		connectToName(t, client, "carries.a.value.example")
		if reply := readConnectReply(t, client); reply[1] != successReply {
			t.Fatalf("connect failed with reply %#x", reply[1])
		}

		if got := <-rewriter.got; got != "carries.a.value.example" {
			t.Fatalf("the request context carried %v after the lookup, want the value the resolver attached", got)
		}

		// Long past the lookup's own deadline, the relay is still a relay.
		time.Sleep(5 * lookupLifetime)
		synctest.Wait()

		if _, err := client.Write([]byte("still here")); err != nil {
			t.Fatalf("writing to the relay: %v", err)
		}
		buf := make([]byte, len("still here"))
		if _, err := io.ReadFull(target, buf); err != nil {
			t.Fatalf("the relay stopped carrying bytes: %v", err)
		}
	})
}
