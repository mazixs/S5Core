package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

type dialCandidate struct {
	ctx  context.Context
	addr string
}

// interleaveIPs preserves the resolver's preferred family and alternates
// families for fallback. It also removes duplicate addresses.
func interleaveIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	var first, other []net.IP
	seen := make(map[netip.Addr]struct{}, len(ips))
	prefer4 := ips[0].To4() != nil
	for _, ip := range ips {
		key, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		key = key.Unmap()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if (ip.To4() != nil) == prefer4 {
			first = append(first, ip)
		} else {
			other = append(other, ip)
		}
	}
	out := make([]net.IP, 0, len(first)+len(other))
	for len(first) > 0 || len(other) > 0 {
		if len(first) > 0 {
			out = append(out, first[0])
			first = first[1:]
		}
		if len(other) > 0 {
			out = append(out, other[0])
			other = other[1:]
		}
	}
	return out
}

// dialResolved races at most two checked numeric addresses. Fast failures
// advance immediately; a stalled attempt gives its alternate a head start
// after 250ms (or less for a short budget). Per-attempt shares leave room for
// later addresses, with a 2s minimum like net.Dialer, capped by the parent
// deadline. A large DNS answer must not shrink a usable attempt to milliseconds.
// An unbuffered result channel transfers socket ownership exactly once.
func dialResolved(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), candidates []dialCandidate) (net.Conn, error) {
	if len(candidates) == 1 {
		return dialOne(ctx, dial, candidates[0])
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	delay := 250 * time.Millisecond
	if end, ok := ctx.Deadline(); ok && time.Until(end)/time.Duration(len(candidates)+1) < delay {
		delay = max(time.Nanosecond, time.Until(end)/time.Duration(len(candidates)+1))
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	next, active := 0, 0
	launch := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A child deadline can fire before the parent's cancellation callback.
		// Do not start another address after the shared deadline in that gap.
		if end, ok := ctx.Deadline(); ok && !time.Now().Before(end) {
			return context.DeadlineExceeded
		}
		candidate := candidates[next]
		remaining := len(candidates) - next
		next++
		active++
		go func() {
			// The budget is cut from the lifetime and the values attached
			// after, so the timeout context finds its parent's cancelCtx.
			lifetime := ctx
			if end, ok := ctx.Deadline(); ok && remaining > 1 {
				var stop context.CancelFunc
				left := time.Until(end)
				// Match net.partialDeadline's lower bound. With less than 2s
				// left, spend only the remaining parent budget.
				share := min(left, max(2*time.Second, left/time.Duration(remaining)))
				lifetime, stop = context.WithTimeout(ctx, share)
				defer stop()
			}
			c, err := checkedDial(keepValues(lifetime, candidate.ctx), dial, candidate.addr)
			select {
			case results <- result{c, err}:
			case <-ctx.Done():
				if c != nil {
					_ = c.Close()
				}
			}
		}()
		return nil
	}
	if err := launch(); err != nil {
		return nil, err
	}
	var firstErr error
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dial %s: %w", candidates[next-1].addr, ctx.Err())
		case r := <-results:
			active--
			if r.err == nil {
				if ctx.Err() != nil {
					_ = r.conn.Close()
					return nil, ctx.Err()
				}
				return r.conn, nil
			}
			// The first failure names the preferred family, as in
			// net.Dialer, unless it only says this host has no route for
			// that family: then what the other family met is the answer.
			if firstErr == nil || (noRoute(firstErr) && !noRoute(r.err)) {
				firstErr = r.err
			}
			if next < len(candidates) {
				if err := launch(); err != nil {
					return nil, err
				}
				timer.Reset(delay)
			}
		case <-timer.C:
			if next < len(candidates) && active < 2 {
				if err := launch(); err != nil {
					return nil, err
				}
			}
			if next < len(candidates) {
				timer.Reset(delay)
			}
		}
	}
	return nil, firstErr
}

// dialOne is the single-address path: no race, so no goroutine, channel or
// timer, and the whole budget belongs to the one attempt.
func dialOne(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), candidate dialCandidate) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return checkedDial(keepValues(ctx, candidate.ctx), dial, candidate.addr)
}

// checkedDial holds a Dial hook to one outcome: a connection or an error.
func checkedDial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), addr string) (net.Conn, error) {
	c, err := dial(ctx, "tcp", addr)
	if err == nil && c == nil {
		err = errors.New("dial returned no connection")
	}
	if err != nil && c != nil {
		_ = c.Close()
		c = nil
	}
	return c, err
}

// noRoute reports a local "no route for this family" failure, the one IPv6
// gives on a host without IPv6. The text match covers Dial hooks that return
// their own errors; handleConnect maps replies by the same text.
func noRoute(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || strings.Contains(err.Error(), "network is unreachable")
}
