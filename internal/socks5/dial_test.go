package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
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

// All attempts share one budget. This test used to hold the race to two
// attempts in flight, each with a share of the budget, and so to four sockets
// in 10s and two in 1s. Since Н-5 (docs/plan/v2.3-rc6.md) the addresses start
// 250ms apart, or budget/(n+1) apart when that is shorter, every first attempt
// keeps the whole budget and each address opens its own backups, under one
// limit of six sockets that keeps a place for every address not yet tried:
// with four silent addresses that is a, b, c and d with backups of a and b.
func TestDialAllAttemptsShareBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget time.Duration
		starts map[string][]time.Duration
	}{
		{"enough_time_for_all", 10 * time.Second, map[string][]time.Duration{
			"a": millis(0, 500), "b": millis(250, 750), "c": millis(500), "d": millis(750),
		}},
		{"short_budget", time.Second, map[string][]time.Duration{
			"a": millis(0, 500), "b": millis(200, 700), "c": millis(400), "d": millis(600),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				d := newScriptDial(func(ctx context.Context, _ string, _ int) (net.Conn, error) { return hole(ctx) })
				_, err := dialResolved(ctx, d.dial, candidatesFor(ctx, "a", "b", "c", "d"))
				synctest.Wait()
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(d.origin) != tc.budget {
					t.Fatalf("elapsed=%v err=%v", time.Since(d.origin), err)
				}
				for addr, want := range tc.starts {
					if got := d.at(addr); !slices.Equal(got, want) {
						t.Fatalf("%s dialled at %v, want %v", addr, got, want)
					}
				}
				if active, peak := d.counts(); len(d.all()) != dialSocketLimit || active != 0 || peak != dialSocketLimit {
					t.Fatalf("calls=%d active=%d peak=%d", len(d.all()), active, peak)
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
// normal connection delay has elapsed. Fast failures of the other addresses
// do not shorten the working attempt's lifetime. A refusal reached the
// destination, so the refused addresses fill the six sockets and the rest of
// a large answer is not tried (Н-5 of docs/plan/v2.3-rc6.md; before it every
// address was tried, two at a time).
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
				if active != 0 || peak > dialSocketLimit || calls != dialSocketLimit {
					t.Fatalf("active=%d peak=%d calls=%d", active, peak, calls)
				}
			})
		})
	}
}
