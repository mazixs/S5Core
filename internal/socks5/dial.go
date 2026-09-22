package socks5

import (
	"context"
	"errors"
	"net"
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
	seen := make(map[string]bool)
	prefer4 := ips[0].To4() != nil
	for _, ip := range ips {
		if ip.To16() == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
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
			attempt := keepValues(ctx, candidate.ctx)
			if end, ok := ctx.Deadline(); ok && remaining > 1 {
				var stop context.CancelFunc
				left := time.Until(end)
				// Match net.partialDeadline's lower bound. With less than 2s
				// left, spend only the remaining parent budget.
				share := min(left, max(2*time.Second, left/time.Duration(remaining)))
				attempt, stop = context.WithTimeout(attempt, share)
				defer stop()
			}
			c, err := dial(attempt, "tcp", candidate.addr)
			if err == nil && c == nil {
				err = errors.New("dial returned no connection")
			}
			if err != nil && c != nil {
				_ = c.Close()
				c = nil
			}
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
			return nil, ctx.Err()
		case r := <-results:
			active--
			if r.err == nil {
				if ctx.Err() != nil {
					_ = r.conn.Close()
					return nil, ctx.Err()
				}
				return r.conn, nil
			}
			if firstErr == nil {
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
