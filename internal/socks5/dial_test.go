package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestDialFallbackCancelsBlackhole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		exited := make(chan struct{})
		winner, peer := net.Pipe()
		defer peer.Close()
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			if addr == "[::1]:80" {
				defer close(exited)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return winner, nil
		}
		start := time.Now()
		got, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "[::1]:80"}, {ctx: ctx, addr: "127.0.0.1:80"}})
		if err != nil {
			t.Fatal(err)
		}
		got.Close()
		<-exited
		if elapsed := time.Since(start); elapsed != 250*time.Millisecond {
			t.Fatalf("fallback took %v", elapsed)
		}
	})
}

// Short budgets may expire before every blackholed address is attempted:
// exhausting the list must not take precedence over viable attempt durations.
func TestDialAllAttemptsShareBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget time.Duration
		calls  int
	}{
		{"enough_time_for_all", 10 * time.Second, 4},
		{"short_budget", time.Second, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				var mu sync.Mutex
				calls, active, peak := 0, 0, 0
				dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
					mu.Lock()
					calls++
					active++
					peak = max(peak, active)
					mu.Unlock()
					defer func() { mu.Lock(); active--; mu.Unlock() }()
					<-ctx.Done()
					return nil, ctx.Err()
				}
				start := time.Now()
				_, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "a"}, {ctx: ctx, addr: "b"}, {ctx: ctx, addr: "c"}, {ctx: ctx, addr: "d"}})
				synctest.Wait()
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != tc.budget {
					t.Fatalf("elapsed=%v err=%v", time.Since(start), err)
				}
				mu.Lock()
				defer mu.Unlock()
				if calls != tc.calls || active != 0 || peak > 2 {
					t.Fatalf("calls=%d active=%d peak=%d", calls, active, peak)
				}
			})
		})
	}
}

func TestDialClosesLateWinningSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		slow, slowPeer := net.Pipe()
		defer slowPeer.Close()
		fast, fastPeer := net.Pipe()
		defer fastPeer.Close()
		released := make(chan struct{})
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			if addr == "slow" {
				<-ctx.Done()
				close(released)
				return slow, nil
			}
			return fast, nil
		}
		c, err := dialResolved(ctx, dial, []dialCandidate{{ctx: ctx, addr: "slow"}, {ctx: ctx, addr: "fast"}})
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		<-released
		synctest.Wait()
		if _, err := slowPeer.Write([]byte{1}); err == nil {
			t.Fatal("losing socket left open")
		}
	})
}

// A large DNS answer must not cancel the only reachable address before a
// normal connection delay has elapsed. Fast failures in the other lane
// should not shorten the working attempt's lifetime.
func TestDialLargeAddressSetPreservesWorkingCandidate(t *testing.T) {
	for _, tc := range []struct {
		name            string
		count           int
		budget, connect time.Duration
	}{
		{"review_16_addresses", 16, 10 * time.Second, time.Second},
		{"large_mixed_set", 64, 10 * time.Second, 1500 * time.Millisecond},
		{"short_parent_budget", 16, time.Second, 750 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				candidates := make([]dialCandidate, tc.count)
				for i := range candidates {
					addr := fmt.Sprintf("192.0.2.%d:443", i+1)
					if i%2 != 0 {
						addr = fmt.Sprintf("[2001:db8::%x]:443", i+1)
					}
					candidates[i] = dialCandidate{ctx: ctx, addr: addr}
				}
				var mu sync.Mutex
				active, peak, calls := 0, 0, 0
				dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
					mu.Lock()
					active++
					calls++
					peak = max(peak, active)
					mu.Unlock()
					defer func() { mu.Lock(); active--; mu.Unlock() }()
					if addr != candidates[0].addr {
						return nil, errors.New("connection refused")
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(tc.connect):
						local, peer := net.Pipe()
						peer.Close()
						return local, nil
					}
				}
				start := time.Now()
				c, err := dialResolved(ctx, dial, candidates)
				if c != nil {
					c.Close()
				}
				synctest.Wait()
				t.Logf("addresses=%d budget=%v elapsed=%v error=%v parent=%v", tc.count, tc.budget, time.Since(start), err, ctx.Err())
				if err != nil || c == nil || time.Since(start) != tc.connect || ctx.Err() != nil {
					t.Fatal("working address canceled prematurely")
				}
				mu.Lock()
				defer mu.Unlock()
				if active != 0 || peak > 2 || calls != tc.count {
					t.Fatalf("active=%d peak=%d calls=%d", active, peak, calls)
				}
			})
		})
	}
}
