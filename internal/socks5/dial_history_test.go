package socks5

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// A recorded connect time moves the next first backup to a margin over it,
// within [dialBackupFloor, backupAfter[0]].
func TestTheHistoryTimesTheFirstBackup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		connect time.Duration
		want    time.Duration
	}{
		{"quick_hits_the_floor", 20 * time.Millisecond, dialBackupFloor},
		{"middle_uses_the_margin", 300 * time.Millisecond, 450 * time.Millisecond},
		{"slow_hits_the_default", time.Second, backupAfter[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDialHistory()
			h.record("203.0.113.7:443", tc.connect)
			if got := h.firstBackup("203.0.113.7:443"); got != tc.want {
				t.Fatalf("first backup %v, want %v", got, tc.want)
			}
		})
	}
}

// A prefix never dialed has no history, and the caller keeps the default.
func TestAnUnknownPrefixHasNoHistory(t *testing.T) {
	h := newDialHistory()
	if got := h.firstBackup("198.51.100.1:80"); got != 0 {
		t.Fatalf("first backup %v, want 0", got)
	}
	// A neighbour in the same /24 shares the sample; another /24 does not.
	h.record("198.51.100.9:80", 40*time.Millisecond)
	if got := h.firstBackup("198.51.100.1:80"); got != dialBackupFloor {
		t.Fatalf("neighbour first backup %v, want the floor", got)
	}
	if got := h.firstBackup("198.51.101.1:80"); got != 0 {
		t.Fatalf("other /24 first backup %v, want 0", got)
	}
}

// The estimate is an average, so one outlier does not move it far.
func TestTheHistoryAveragesConnectTimes(t *testing.T) {
	h := newDialHistory()
	addr := "192.0.2.1:80"
	h.record(addr, 200*time.Millisecond)
	h.record(addr, 200*time.Millisecond)
	h.record(addr, time.Second) // one slow dial
	p, _ := dialPrefix(addr)
	if got := h.sample[p]; got < 200*time.Millisecond || got > 500*time.Millisecond {
		t.Fatalf("averaged sample %v, want it near 200ms after one outlier", got)
	}
}

// The map does not grow past its bound: the oldest prefix is evicted.
func TestTheHistoryIsBounded(t *testing.T) {
	h := newDialHistory()
	for i := 0; i < dialHistoryLimit+10; i++ {
		h.record(net.JoinHostPort(net.IPv4(203, 0, byte(i>>8), byte(i)).String(), "80"), 30*time.Millisecond)
	}
	if len(h.sample) > dialHistoryLimit {
		t.Fatalf("history holds %d prefixes, want at most %d", len(h.sample), dialHistoryLimit)
	}
}

// A candidate carrying a history-timed first backup opens it then, not at the
// default 500ms.
func TestABackupHonoursTheHistoryTiming(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		winner, peer := net.Pipe()
		defer peer.Close()
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				return hole(ctx)
			}
			return winner, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{ctx: ctx, addr: "only", firstBackup: 100 * time.Millisecond}})
		if err != nil || c != winner {
			t.Fatalf("got %v, %v", c, err)
		}
		if elapsed := time.Since(d.origin); elapsed != 100*time.Millisecond {
			t.Fatalf("connected after %v, want the history-timed backup at 100ms", elapsed)
		}
		c.Close()
	})
}

// onConnect is called with the first attempt's time only when the first
// attempt is the one that connected.
func TestTheConnectTimeIsRecordedForACleanDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a, peerA := net.Pipe()
		defer peerA.Close()
		var recorded time.Duration
		gotCall := false
		d := &countingDial{origin: time.Now(), behave: func(context.Context, int) (net.Conn, error) {
			time.Sleep(120 * time.Millisecond)
			return a, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{
			ctx:  ctx,
			addr: "only",
			onConnect: func(dd time.Duration) {
				gotCall = true
				recorded = dd
			},
		}})
		if err != nil || c != a {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
		if !gotCall || recorded != 120*time.Millisecond {
			t.Fatalf("recorded %v (called=%v), want 120ms", recorded, gotCall)
		}
	})
}

// When a backup rescues the dial, the time is the hole's, not the path's, so
// nothing is recorded.
func TestARescuedDialRecordsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		winner, peer := net.Pipe()
		defer peer.Close()
		gotCall := false
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				return hole(ctx)
			}
			return winner, nil
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{
			ctx:         ctx,
			addr:        "only",
			firstBackup: 100 * time.Millisecond,
			onConnect:   func(time.Duration) { gotCall = true },
		}})
		if err != nil || c != winner {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
		if gotCall {
			t.Fatal("a backup-rescued dial recorded a connect time")
		}
	})
}

// A first attempt that connected only after the default first backup, as one
// does on a retransmitted SYN, records nothing: a backup opened by the history
// sooner than that must not make a slow win look like the path.
func TestAFirstAttemptSlowerThanTheDefaultRecordsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a, peerA := net.Pipe()
		defer peerA.Close()
		gotCall := false
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				time.Sleep(1030 * time.Millisecond) // the kernel's SYN retransmission
				return a, nil
			}
			return hole(ctx)
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{
			ctx:         ctx,
			addr:        "only",
			firstBackup: 100 * time.Millisecond,
			onConnect:   func(time.Duration) { gotCall = true },
		}})
		if err != nil || c != a {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
		if gotCall {
			t.Fatal("a first attempt slower than the default first backup was recorded")
		}
	})
}

// A first attempt slower than the history's guess but within the default is
// still the path's own time, and the history learns it, even though a backup
// had been opened meanwhile.
func TestASlowFirstAttemptWithinTheDefaultIsRecorded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a, peerA := net.Pipe()
		defer peerA.Close()
		var recorded time.Duration
		d := &countingDial{origin: time.Now(), behave: func(ctx context.Context, n int) (net.Conn, error) {
			if n == 0 {
				time.Sleep(200 * time.Millisecond)
				return a, nil
			}
			return hole(ctx)
		}}
		c, err := dialResolved(ctx, d.dial, []dialCandidate{{
			ctx:         ctx,
			addr:        "only",
			firstBackup: 100 * time.Millisecond,
			onConnect:   func(dd time.Duration) { recorded = dd },
		}})
		if err != nil || c != a {
			t.Fatalf("got %v, %v", c, err)
		}
		c.Close()
		if recorded != 200*time.Millisecond {
			t.Fatalf("recorded %v, want the first attempt's 200ms", recorded)
		}
	})
}
