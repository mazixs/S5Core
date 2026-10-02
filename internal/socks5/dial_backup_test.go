package socks5

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// countingDial numbers the attempts at one address and records when each
// started; behave decides what attempt n meets.
type countingDial struct {
	mu     sync.Mutex
	starts []time.Duration
	origin time.Time
	behave func(ctx context.Context, n int) (net.Conn, error)
}

func (d *countingDial) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	n := len(d.starts)
	d.starts = append(d.starts, time.Since(d.origin))
	d.mu.Unlock()
	return d.behave(ctx, n)
}

func (d *countingDial) started() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Duration(nil), d.starts...)
}

func hole(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The first attempt's source port hashed onto a link that drops everything:
// its retransmissions never arrive. The backup half a second later takes
// another port and connects, and the stuck attempt is released.
func TestABackupSocketGetsPastAFlowThatFallsIntoAHole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		winner, peer := net.Pipe()
		defer peer.Close()
		released := make(chan struct{})
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				defer close(released)
				return hole(ctx)
			}
			return winner, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if err != nil || c != winner {
			t.Fatalf("got %v, %v", c, err)
		}
		if elapsed := time.Since(d.origin); elapsed != 500*time.Millisecond {
			t.Fatalf("connected after %v, want the first backup at 500ms", elapsed)
		}
		c.Close()
		<-released
	})
}

// A destination that never answers gets a new socket at each moment of the
// schedule that falls inside the budget, and the reply is the first attempt's
// own error at the end of it - the same answer as before backups existed.
func TestBackupsKeepDrawingUntilTheBudgetEnds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget time.Duration
		starts []time.Duration
	}{
		{"whole_budget", 10 * time.Second, []time.Duration{
			0, 500 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second, 5 * time.Second, 7 * time.Second,
		}},
		{"short_budget", 2 * time.Second, []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond}},
		{"budget_ends_on_a_backup", 3 * time.Second, []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, _ int) (net.Conn, error) { return hole(ctx) }}
				_, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
				synctest.Wait()
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(d.origin) != tc.budget {
					t.Fatalf("elapsed=%v err=%v", time.Since(d.origin), err)
				}
				got := d.started()
				if len(got) != len(tc.starts) {
					t.Fatalf("attempts started at %v, want %v", got, tc.starts)
				}
				for i := range got {
					if got[i] != tc.starts[i] {
						t.Fatalf("attempts started at %v, want %v", got, tc.starts)
					}
				}
			})
		})
	}
}

// A destination that answers opens no second socket, and one that refuses
// is reported at once.
func TestAnAnsweredDialOpensNoBackup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a, b := net.Pipe()
		defer b.Close()
		ok := &countingDial{origin: time.Now(), behave: func(context.Context, int) (net.Conn, error) {
			time.Sleep(300 * time.Millisecond)
			return a, nil
		}}
		c, err := dialResolved(ctx, ok.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if err != nil || c != a {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()

		refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		no := &countingDial{origin: time.Now(), behave: func(context.Context, int) (net.Conn, error) { return nil, refused }}
		if _, err := dialResolved(ctx, no.dial, []dialCandidate{{ctx: ctx, addr: "only"}}); !errors.Is(err, refused) {
			t.Fatalf("got %v, want the refusal", err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if n := len(ok.started()) + len(no.started()); n != 2 {
			t.Fatalf("%d attempts, want one per dial", n)
		}
	})
}

// A backup that fails on its own, say on a local bind error, does not end
// the dial: the first attempt still decides.
func TestABackupsOwnFailureDoesNotAnswerForTheDestination(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		first, peer := net.Pipe()
		defer peer.Close()
		d := &countingDial{origin: time.Now(), behave: func(_ context.Context, n int) (net.Conn, error) {
			if n == 0 {
				time.Sleep(1200 * time.Millisecond)
				return first, nil
			}
			return nil, syscall.EADDRINUSE
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if err != nil || c != first {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
	})
}

// Two attempts that both connect leave one socket to the caller and close
// the other.
func TestTheLosingSocketOfABackupRaceIsClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		late, latePeer := net.Pipe()
		defer latePeer.Close()
		backup, backupPeer := net.Pipe()
		defer backupPeer.Close()
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				<-ctx.Done()
				return late, nil
			}
			return backup, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if err != nil || c != backup {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
		synctest.Wait()
		if _, err := latePeer.Write([]byte{1}); err == nil {
			t.Fatal("the losing socket was left open")
		}
	})
}

// A dial cancelled while its first attempt has not yet noticed opens no more
// backups: they would only be handed a dead context. The answer is still the
// first attempt's own.
func TestACancelledDialOpensNoMoreBackups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		time.AfterFunc(time.Second, cancel)
		late := errors.New("the first attempt, late")
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				time.Sleep(2 * time.Second)
				return nil, late
			}
			return hole(ctx)
		}}
		_, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if !errors.Is(err, late) || time.Since(d.origin) != 2*time.Second {
			t.Fatalf("elapsed=%v err=%v", time.Since(d.origin), err)
		}
		synctest.Wait()
		if got := d.started(); len(got) != 2 || got[1] != 500*time.Millisecond {
			t.Fatalf("attempts started at %v, want 0 and 500ms", got)
		}
	})
}

// Two backups refused, each from its own port, are the destination answering:
// nothing listens there, and the first attempt, lost on the way, would have
// heard the same. The client is told then, not after the budget. A Dial
// hook's own error counts by its text.
func TestASecondRefusedBackupAnswersForTheDestination(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal error
	}{
		{"errno", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
		{"text", errors.New("dial tcp 192.0.2.1:80: connect: connection refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				released := make(chan struct{})
				d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
					if n == 0 {
						defer close(released)
						return hole(ctx)
					}
					return nil, tc.refusal
				}}
				_, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
				if !errors.Is(err, tc.refusal) || time.Since(d.origin) != 1500*time.Millisecond {
					t.Fatalf("elapsed=%v err=%v, want the refusal at 1.5s", time.Since(d.origin), err)
				}
				<-released
			})
		})
	}
}

// One refused backup may have met a firewall or a balancer on its own path
// rather than the destination: the dial goes on, and the next backup connects.
func TestOneRefusedBackupDoesNotEndTheDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		winner, peer := net.Pipe()
		defer peer.Close()
		released := make(chan struct{})
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			switch n {
			case 0:
				defer close(released)
				return hole(ctx)
			case 1:
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
			}
			return winner, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
		if err != nil || c != winner || time.Since(d.origin) != 1500*time.Millisecond {
			t.Fatalf("after %v got %v, %v, want the second backup's connection at 1.5s", time.Since(d.origin), c, err)
		}
		c.Close()
		<-released
	})
}

// A connection that arrives once the budget is over is closed, whichever
// socket brings it, as it is with several addresses: the caller has stopped
// waiting for it. The answer is then the first attempt's own, or the end of
// the budget when the first attempt is the late one.
func TestAConnectionThatComesTooLateIsClosed(t *testing.T) {
	late := errors.New("the first attempt, late")
	for _, tc := range []struct {
		name   string
		behave func(ctx context.Context, n int, conn net.Conn) (net.Conn, error)
		want   error
		after  time.Duration
	}{
		{"first_attempt", func(ctx context.Context, n int, conn net.Conn) (net.Conn, error) {
			<-ctx.Done()
			if n == 0 {
				return conn, nil
			}
			return nil, ctx.Err()
		}, context.DeadlineExceeded, 2 * time.Second},
		{"backup", func(ctx context.Context, n int, conn net.Conn) (net.Conn, error) {
			switch n {
			case 0:
				time.Sleep(3 * time.Second)
				return nil, late
			case 1:
				<-ctx.Done()
				return conn, nil
			}
			return hole(ctx)
		}, late, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				conn, peer := net.Pipe()
				defer peer.Close()
				d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
					return tc.behave(ctx, n, conn)
				}}
				c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only"}})
				if c != nil || !errors.Is(err, tc.want) || time.Since(d.origin) != tc.after {
					t.Fatalf("after %v got %v, %v, want %v after %v", time.Since(d.origin), c, err, tc.want, tc.after)
				}
				synctest.Wait()
				if _, err := peer.Write([]byte{1}); err == nil {
					t.Fatal("the late socket was left open")
				}
			})
		})
	}
}
