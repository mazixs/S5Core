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
// its retransmissions never arrive. The backup a second later takes another
// port and connects, and the stuck attempt is released.
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
		if elapsed := time.Since(d.origin); elapsed != time.Second {
			t.Fatalf("connected after %v, want the first backup at 1s", elapsed)
		}
		c.Close()
		<-released
	})
}

// A destination that never answers gets a new socket at each moment Linux
// would retransmit the SYN, and the reply is the first attempt's own error
// at the end of the budget - the same answer as before backups existed.
func TestEveryBackupWaitsForARetransmissionMoment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget time.Duration
		starts []time.Duration
	}{
		{"whole_budget", 10 * time.Second, []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second}},
		{"short_budget", 2 * time.Second, []time.Duration{0, time.Second}},
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
				time.Sleep(1500 * time.Millisecond)
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
