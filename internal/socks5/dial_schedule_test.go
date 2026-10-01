package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// scriptDial numbers the attempts at each address and records when each
// started; behave decides what attempt n at addr meets.
type scriptDial struct {
	mu           sync.Mutex
	origin       time.Time
	starts       map[string][]time.Duration
	active, peak int
	behave       func(ctx context.Context, addr string, n int) (net.Conn, error)
}

func newScriptDial(behave func(ctx context.Context, addr string, n int) (net.Conn, error)) *scriptDial {
	return &scriptDial{origin: time.Now(), starts: map[string][]time.Duration{}, behave: behave}
}

func (d *scriptDial) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	n := len(d.starts[addr])
	d.starts[addr] = append(d.starts[addr], time.Since(d.origin))
	d.active++
	d.peak = max(d.peak, d.active)
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.active--; d.mu.Unlock() }()
	return d.behave(ctx, addr, n)
}

func (d *scriptDial) at(addr string) []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.starts[addr])
}

func (d *scriptDial) all() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	var all []time.Duration
	for _, s := range d.starts {
		all = append(all, s...)
	}
	slices.Sort(all)
	return all
}

// counts returns how many attempts are dialing now and the most at once.
func (d *scriptDial) counts() (active, peak int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active, d.peak
}

func millis(v ...float64) []time.Duration {
	out := make([]time.Duration, len(v))
	for i, ms := range v {
		out[i] = time.Duration(ms * float64(time.Millisecond))
	}
	return out
}

func candidatesFor(ctx context.Context, addrs ...string) []dialCandidate {
	out := make([]dialCandidate, len(addrs))
	for i, a := range addrs {
		out[i] = dialCandidate{ctx: ctx, addr: a}
	}
	return out
}

const (
	liveV4 = "192.0.2.1:443"
	deadV6 = "[2001:db8::1]:443"
)

var (
	unreachable = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
	refusal     = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
)

type dialRun struct {
	starts    []time.Duration
	elapsed   time.Duration
	connected bool
	err       error
	recorded  []time.Duration
}

// runDial dials addrs in a bubble of its own. The IPv6 address has no route;
// what the IPv4 one meets is the scenario's.
func runDial(t *testing.T, budget, firstBackup time.Duration, addrs []string, behave func(ctx context.Context, n int, conn net.Conn) (net.Conn, error)) dialRun {
	var run dialRun
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		conn, peer := net.Pipe()
		defer peer.Close()
		d := newScriptDial(func(ctx context.Context, addr string, n int) (net.Conn, error) {
			if addr == deadV6 {
				return nil, unreachable
			}
			return behave(ctx, n, conn)
		})
		candidates := candidatesFor(ctx, addrs...)
		for i := range candidates {
			candidates[i].onConnect = func(d time.Duration) { run.recorded = append(run.recorded, d) }
			if candidates[i].addr == liveV4 {
				candidates[i].firstBackup = firstBackup
			}
		}
		c, err := dialResolved(ctx, d.dial, candidates)
		run.elapsed = time.Since(d.origin)
		run.connected = c == conn
		run.err = err
		if c != nil {
			c.Close()
		}
		synctest.Wait()
		run.starts = d.at(liveV4)
		if active, _ := d.counts(); active != 0 {
			t.Fatalf("%d attempts still dialing", active)
		}
	})
	return run
}

// A name whose other addresses fail without leaving the host dials its one
// live address as that address's literal does: the same sockets at the same
// moments and the same answer, whichever family the resolver put first. This
// is the dial of Ч-26: A and AAAA on a host without IPv6, and an IPv4 flow
// hashed into a hole.
func TestANameWithOneRoutableAddressDialsLikeItsLiteral(t *testing.T) {
	for _, tc := range []struct {
		name        string
		firstBackup time.Duration
		behave      func(ctx context.Context, n int, conn net.Conn) (net.Conn, error)
		starts      []time.Duration
		elapsed     time.Duration
	}{
		{"third_socket_connects", 0, func(ctx context.Context, n int, conn net.Conn) (net.Conn, error) {
			if n < 2 {
				return hole(ctx)
			}
			return conn, nil
		}, millis(0, 500, 1500), 1500 * time.Millisecond},
		{"never_answers", 0, func(ctx context.Context, _ int, _ net.Conn) (net.Conn, error) {
			return hole(ctx)
		}, millis(0, 500, 1500, 3000, 5000, 7000), 10 * time.Second},
		{"first_attempt_refused", 0, func(context.Context, int, net.Conn) (net.Conn, error) {
			return nil, refusal
		}, millis(0), 0},
		{"two_backups_refused", 0, func(ctx context.Context, n int, _ net.Conn) (net.Conn, error) {
			if n == 0 {
				return hole(ctx)
			}
			return nil, refusal
		}, millis(0, 500, 1500), 1500 * time.Millisecond},
		{"history_times_the_first_backup", 120 * time.Millisecond, func(ctx context.Context, n int, conn net.Conn) (net.Conn, error) {
			if n == 0 {
				return hole(ctx)
			}
			return conn, nil
		}, millis(0, 120), 120 * time.Millisecond},
		{"quick_first_attempt", 0, func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) {
			time.Sleep(200 * time.Millisecond)
			return conn, nil
		}, millis(0), 200 * time.Millisecond},
		{"first_attempt_on_a_retransmission", 0, func(ctx context.Context, n int, conn net.Conn) (net.Conn, error) {
			if n == 0 {
				time.Sleep(1200 * time.Millisecond)
				return conn, nil
			}
			return hole(ctx)
		}, millis(0, 500), 1200 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			literal := runDial(t, 10*time.Second, tc.firstBackup, []string{liveV4}, tc.behave)
			if !slices.Equal(literal.starts, tc.starts) || literal.elapsed != tc.elapsed {
				t.Fatalf("literal: sockets at %v, over after %v; want %v and %v", literal.starts, literal.elapsed, tc.starts, tc.elapsed)
			}
			for _, order := range [][]string{{liveV4, deadV6}, {deadV6, liveV4}} {
				name := runDial(t, 10*time.Second, tc.firstBackup, order, tc.behave)
				if !slices.Equal(name.starts, literal.starts) || name.elapsed != literal.elapsed || name.connected != literal.connected {
					t.Fatalf("name %v: sockets at %v, over after %v, connected %v; literal %v, %v, %v",
						order, name.starts, name.elapsed, name.connected, literal.starts, literal.elapsed, literal.connected)
				}
				if !slices.Equal(name.recorded, literal.recorded) {
					t.Fatalf("name %v recorded %v, literal %v", order, name.recorded, literal.recorded)
				}
				if (name.err == nil) != (literal.err == nil) {
					t.Fatalf("name %v: %v, literal: %v", order, name.err, literal.err)
				}
				if literal.err == nil {
					continue
				}
				if dialFailureReply(name.err) != dialFailureReply(literal.err) ||
					errors.Is(name.err, refusal) != errors.Is(literal.err, refusal) ||
					errors.Is(name.err, context.DeadlineExceeded) != errors.Is(literal.err, context.DeadlineExceeded) ||
					noRoute(name.err) {
					t.Fatalf("name %v answered %v, literal %v", order, name.err, literal.err)
				}
			}
		})
	}
}

// A failure that never left the host takes no place among the six sockets:
// however many such addresses a name has, its live address still gets all six,
// and the answer at the end of the budget is that address's, not the missing
// route.
func TestAnUnroutableFailureTakesNoSocket(t *testing.T) {
	for _, addrs := range [][]string{
		{deadV6, liveV4},
		{liveV4, deadV6},
		{liveV4, "[2001:db8::2]:443", "[2001:db8::3]:443", "[2001:db8::4]:443", "[2001:db8::5]:443", "[2001:db8::6]:443", "[2001:db8::7]:443"},
	} {
		t.Run(fmt.Sprint(len(addrs)), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				d := newScriptDial(func(ctx context.Context, addr string, _ int) (net.Conn, error) {
					if strings.HasPrefix(addr, "[") {
						return nil, unreachable
					}
					return hole(ctx)
				})
				_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, addrs...))
				if !errors.Is(err, context.DeadlineExceeded) || noRoute(err) || !strings.Contains(err.Error(), liveV4) || time.Since(d.origin) != 10*time.Second {
					t.Fatalf("after %v got %v, want the end of the budget named by %s", time.Since(d.origin), err, liveV4)
				}
				synctest.Wait()
				if got, want := d.at(liveV4), millis(0, 500, 1500, 3000, 5000, 7000); !slices.Equal(got, want) {
					t.Fatalf("sockets to %s at %v, want %v", liveV4, got, want)
				}
				for _, a := range addrs[1:] {
					if a != liveV4 && len(d.at(a)) != 1 {
						t.Fatalf("%s dialled %d times, want once", a, len(d.at(a)))
					}
				}
			})
		})
	}
}

// Silent addresses share six sockets: two addresses get three each, at their
// own moments; eight get one each for the first six and none for the rest.
// Nothing is dialled after the last of them until the budget ends.
func TestADialNeverOpensMoreThanSixSockets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addrs  []string
		starts map[string][]time.Duration
	}{
		{"two", []string{"a", "b"}, map[string][]time.Duration{
			"a": millis(0, 500, 1500),
			"b": millis(250, 750, 1750),
		}},
		{"eight", []string{"a", "b", "c", "d", "e", "f", "g", "h"}, map[string][]time.Duration{
			"a": millis(0), "b": millis(250), "c": millis(500), "d": millis(750), "e": millis(1000), "f": millis(1250),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				d := newScriptDial(func(ctx context.Context, _ string, _ int) (net.Conn, error) { return hole(ctx) })
				_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, tc.addrs...))
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(d.origin) != 10*time.Second {
					t.Fatalf("after %v got %v", time.Since(d.origin), err)
				}
				synctest.Wait()
				for _, a := range tc.addrs {
					if got := d.at(a); !slices.Equal(got, tc.starts[a]) {
						t.Fatalf("%s dialled at %v, want %v", a, got, tc.starts[a])
					}
				}
				if active, peak := d.counts(); len(d.all()) != dialSocketLimit || peak != dialSocketLimit || active != 0 {
					t.Fatalf("%d sockets, peak %d, %d left dialing", len(d.all()), peak, active)
				}
			})
		})
	}
}

// When a new address and a backup are due at the same moment, the new address
// starts first: another address is another hash and maybe another host.
func TestANewAddressGoesBeforeABackup(t *testing.T) {
	p := newDialPlan(make([]dialCandidate, 3), dialAttemptDelay)
	t0 := time.Now()
	type step struct {
		index  int
		backup bool
	}
	take := func(at time.Duration) []step {
		var steps []step
		for {
			i, backup, ok := p.next(t0.Add(at))
			if !ok {
				return steps
			}
			steps = append(steps, step{i, backup})
		}
	}
	for _, tc := range []struct {
		at   time.Duration
		want []step
		wake time.Duration
	}{
		{0, []step{{0, false}}, 250 * time.Millisecond},
		{250 * time.Millisecond, []step{{1, false}}, 500 * time.Millisecond},
		{500 * time.Millisecond, []step{{2, false}, {0, true}}, 750 * time.Millisecond},
	} {
		if got := take(tc.at); !slices.Equal(got, tc.want) {
			t.Fatalf("at %v started %v, want %v", tc.at, got, tc.want)
		}
		if wake, ok := p.wake(); !ok || wake.Sub(t0) != tc.wake {
			t.Fatalf("after %v the next moment is %v, want %v", tc.at, wake.Sub(t0), tc.wake)
		}
	}
}

// A backup never takes the place of an address still waiting for its first
// try: with five silent addresses one backup fits, with six none does.
func TestEveryAddressGetsATryBeforeTheLimit(t *testing.T) {
	for _, tc := range []struct {
		addrs  []string
		starts map[string][]time.Duration
	}{
		{[]string{"a", "b", "c", "d", "e"}, map[string][]time.Duration{
			"a": millis(0, 500), "b": millis(250), "c": millis(500), "d": millis(750), "e": millis(1000),
		}},
		{[]string{"a", "b", "c", "d", "e", "f"}, map[string][]time.Duration{
			"a": millis(0), "b": millis(250), "c": millis(500), "d": millis(750), "e": millis(1000), "f": millis(1250),
		}},
	} {
		t.Run(fmt.Sprint(len(tc.addrs)), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				d := newScriptDial(func(ctx context.Context, _ string, _ int) (net.Conn, error) { return hole(ctx) })
				if _, err := dialResolved(ctx, d.dial, candidatesFor(ctx, tc.addrs...)); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
				synctest.Wait()
				for _, a := range tc.addrs {
					if got := d.at(a); !slices.Equal(got, tc.starts[a]) {
						t.Fatalf("%s dialled at %v, want %v", a, got, tc.starts[a])
					}
				}
			})
		})
	}
}

// The first attempt's failure answers for its own address at once: the next
// address starts in the same moment, and the failed one opens no backup. A
// refusal reached the destination, so it keeps its place among the six. When
// no address connects, the first one's answer names the dial.
func TestTheFirstAttemptsFailureAnswersForItsAddressOnly(t *testing.T) {
	other := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for _, tc := range []struct {
		name    string
		b       func(ctx context.Context) (net.Conn, error)
		bStarts []time.Duration
		elapsed time.Duration
	}{
		{"both_refuse", func(context.Context) (net.Conn, error) { return nil, other }, millis(0), 0},
		{"other_is_silent", hole, millis(0, 500, 1500, 3000, 5000), 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				d := newScriptDial(func(ctx context.Context, addr string, _ int) (net.Conn, error) {
					if addr == "a" {
						return nil, refusal
					}
					return tc.b(ctx)
				})
				_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b"))
				if !errors.Is(err, refusal) || time.Since(d.origin) != tc.elapsed {
					t.Fatalf("after %v got %v, want a's refusal after %v", time.Since(d.origin), err, tc.elapsed)
				}
				synctest.Wait()
				if got := d.at("a"); !slices.Equal(got, millis(0)) {
					t.Fatalf("a dialled at %v, want once at 0", got)
				}
				if got := d.at("b"); !slices.Equal(got, tc.bStarts) {
					t.Fatalf("b dialled at %v, want %v", got, tc.bStarts)
				}
			})
		})
	}
}

// Two refused backups answer for their address, as for a literal: it opens no
// more sockets and its first attempt is released, while the other address
// keeps its own schedule and connects on its third socket.
func TestASecondRefusedBackupAnswersForItsAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		winner, peer := net.Pipe()
		defer peer.Close()
		released := make(chan time.Duration, 1)
		origin := time.Now()
		d := newScriptDial(func(ctx context.Context, addr string, n int) (net.Conn, error) {
			switch {
			case addr == "a" && n == 0:
				defer func() { released <- time.Since(origin) }()
				return hole(ctx)
			case addr == "a":
				return nil, refusal
			case n < 2:
				return hole(ctx)
			}
			return winner, nil
		})
		c, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b"))
		if err != nil || c != winner || time.Since(d.origin) != 1750*time.Millisecond {
			t.Fatalf("after %v got %v, %v, want b's third socket at 1.75s", time.Since(d.origin), c, err)
		}
		c.Close()
		synctest.Wait()
		if got := d.at("a"); !slices.Equal(got, millis(0, 500, 1500)) {
			t.Fatalf("a dialled at %v", got)
		}
		if got := d.at("b"); !slices.Equal(got, millis(250, 750, 1750)) {
			t.Fatalf("b dialled at %v", got)
		}
		if at := <-released; at != 1500*time.Millisecond {
			t.Fatalf("a's first attempt released at %v, want at its answer, 1.5s", at)
		}
	})
}

// lateDial hands every attempt a connection once the dial is over, the way a
// SYN-ACK that crosses the cancellation does, and keeps the peers to check
// that each of them was closed.
type lateDial struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (l *lateDial) behave(ctx context.Context, _ string, _ int) (net.Conn, error) {
	<-ctx.Done()
	c, peer := net.Pipe()
	l.mu.Lock()
	l.peers = append(l.peers, peer)
	l.mu.Unlock()
	return c, nil
}

func (l *lateDial) allClosed(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, p := range l.peers {
		if _, err := p.Write([]byte{1}); err == nil {
			t.Fatalf("late socket %d of %d left open", i+1, len(l.peers))
		}
		p.Close()
	}
}

// A backup due at the very end of the budget is not opened, and connections
// that arrive after it are closed.
func TestNothingStartsAfterTheBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 500 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		late := &lateDial{}
		d := newScriptDial(late.behave)
		c, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b"))
		if c != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(d.origin) != budget {
			t.Fatalf("after %v got %v, %v", time.Since(d.origin), c, err)
		}
		synctest.Wait()
		if got := d.all(); !slices.Equal(got, []time.Duration{0, budget / 3}) {
			t.Fatalf("dialled at %v, want 0 and %v only", got, budget/3)
		}
		late.allClosed(t)
	})
}

// A cancelled dial is answered at once with the cancellation, opens nothing
// after it, and closes the connections that arrive after it.
func TestNothingStartsAfterCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		time.AfterFunc(1400*time.Millisecond, cancel)
		late := &lateDial{}
		d := newScriptDial(late.behave)
		c, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b"))
		if c != nil || !errors.Is(err, context.Canceled) || time.Since(d.origin) != 1400*time.Millisecond {
			t.Fatalf("after %v got %v, %v", time.Since(d.origin), c, err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := d.all(); !slices.Equal(got, millis(0, 250, 500, 750)) {
			t.Fatalf("dialled at %v", got)
		}
		late.allClosed(t)
	})
}

// Each address of a name times its first backup by the history of its own
// prefix and from its own start, and only its own clean first attempt is
// recorded.
func TestEveryAddressHasItsOwnHistory(t *testing.T) {
	t.Run("backup_moments", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			d := newScriptDial(func(ctx context.Context, _ string, _ int) (net.Conn, error) { return hole(ctx) })
			candidates := candidatesFor(ctx, "a", "b")
			candidates[0].firstBackup = 120 * time.Millisecond
			if _, err := dialResolved(ctx, d.dial, candidates); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			synctest.Wait()
			if got := d.at("a"); !slices.Equal(got, millis(0, 120, 1500)) {
				t.Fatalf("a dialled at %v", got)
			}
			if got := d.at("b"); !slices.Equal(got, millis(250, 750, 1750)) {
				t.Fatalf("b dialled at %v", got)
			}
		})
	})
	for _, tc := range []struct {
		name   string
		behave func(ctx context.Context, addr string, n int) (net.Conn, error)
		want   map[string][]time.Duration
	}{
		{"clean_first_attempt_of_the_second_address", func(ctx context.Context, addr string, n int) (net.Conn, error) {
			if addr == "b" && n == 0 {
				time.Sleep(200 * time.Millisecond)
				return nil, nil
			}
			return hole(ctx)
		}, map[string][]time.Duration{"b": millis(200)}},
		{"rescued_by_a_backup", func(ctx context.Context, addr string, n int) (net.Conn, error) {
			if addr == "a" && n == 1 {
				return nil, nil
			}
			return hole(ctx)
		}, map[string][]time.Duration{}},
		{"first_attempt_slower_than_the_default", func(ctx context.Context, addr string, n int) (net.Conn, error) {
			if addr == "b" && n == 0 {
				time.Sleep(600 * time.Millisecond)
				return nil, nil
			}
			return hole(ctx)
		}, map[string][]time.Duration{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				winner, peer := net.Pipe()
				defer peer.Close()
				d := newScriptDial(func(ctx context.Context, addr string, n int) (net.Conn, error) {
					c, err := tc.behave(ctx, addr, n)
					if c == nil && err == nil {
						return winner, nil
					}
					return c, err
				})
				recorded := map[string][]time.Duration{}
				candidates := candidatesFor(ctx, "a", "b")
				for i := range candidates {
					addr := candidates[i].addr
					candidates[i].firstBackup = 120 * time.Millisecond
					candidates[i].onConnect = func(d time.Duration) { recorded[addr] = append(recorded[addr], d) }
				}
				c, err := dialResolved(ctx, d.dial, candidates)
				if err != nil || c != winner {
					t.Fatalf("got %v, %v", c, err)
				}
				c.Close()
				if len(recorded) != len(tc.want) {
					t.Fatalf("recorded %v, want %v", recorded, tc.want)
				}
				for addr, want := range tc.want {
					if !slices.Equal(recorded[addr], want) {
						t.Fatalf("recorded %v, want %v", recorded, tc.want)
					}
				}
			})
		})
	}
}

// handleConnect hands every address the history of its own prefix, and a
// clean connect lands in the prefix of the address that made it.
func TestTheServerTimesEveryAddressByItsOwnHistory(t *testing.T) {
	s := &Server{dialHistory: newDialHistory()}
	s.dialHistory.record("198.51.100.9:443", 80*time.Millisecond)
	timed := s.timedByHistory(candidatesFor(context.Background(), "192.0.2.1:443", "198.51.100.1:443"))
	if timed[0].firstBackup != 0 || timed[1].firstBackup != 120*time.Millisecond {
		t.Fatalf("first backups %v and %v, want none and 120ms", timed[0].firstBackup, timed[1].firstBackup)
	}
	timed[0].onConnect(40 * time.Millisecond)
	if got := s.dialHistory.firstBackup("192.0.2.77:443"); got != dialBackupFloor {
		t.Fatalf("after a clean connect the first backup of 192.0.2.0/24 is %v, want the floor", got)
	}
}

// A short budget divides the delay between addresses, but not below the
// 10ms RFC 8305 (section 5) allows.
func TestTheAttemptDelayHasAFloor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 30 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		if got := attemptDelay(ctx, 8); got != dialAttemptFloor {
			t.Fatalf("delay %v, want the floor %v", got, dialAttemptFloor)
		}
		d := newScriptDial(func(ctx context.Context, _ string, _ int) (net.Conn, error) { return hole(ctx) })
		_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b", "c", "d", "e", "f", "g", "h"))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(d.origin) != budget {
			t.Fatalf("after %v got %v", time.Since(d.origin), err)
		}
		synctest.Wait()
		if got := d.all(); !slices.Equal(got, millis(0, 10, 20)) {
			t.Fatalf("dialled at %v, want 0, 10ms and 20ms", got)
		}
	})
}

// Ядро без IPv6 отвечает EAFNOSUPPORT, и такой отказ, как отсутствие маршрута,
// не называет итог: его называет то, что встретил другой адрес.
func TestAFamilyTheKernelLacksDoesNotNameTheFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d := newScriptDial(func(_ context.Context, addr string, _ int) (net.Conn, error) {
			if addr == deadV6 {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EAFNOSUPPORT}
			}
			return nil, refusal
		})
		_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, deadV6, liveV4))
		if !errors.Is(err, refusal) || dialFailureReply(err) != connectionRefused {
			t.Fatalf("got %v (reply %d), want the refusal of the IPv4 address", err, dialFailureReply(err))
		}
	})
}

// Когда все адреса ответили отказом на шести сокетах, седьмой не стартует и
// dial заканчивается сразу, а не в конце бюджета.
func TestSevenRefusedAddressesAnswerAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d := newScriptDial(func(context.Context, string, int) (net.Conn, error) { return nil, refusal })
		_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b", "c", "d", "e", "f", "g"))
		if !errors.Is(err, refusal) || time.Since(d.origin) != 0 || len(d.all()) != dialSocketLimit {
			t.Fatalf("after %v got %v with %d sockets, want the refusal at once after %d sockets", time.Since(d.origin), err, len(d.all()), dialSocketLimit)
		}
	})
}
