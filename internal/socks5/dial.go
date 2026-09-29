package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

type dialCandidate struct {
	ctx  context.Context
	addr string
	// firstBackup, when nonzero, is when dialOne opens its first backup
	// socket instead of the default backupAfter[0]. handleConnect sets it
	// from the dial history of this address's prefix, clamped to
	// [dialBackupFloor, backupAfter[0]], so a destination we have reached
	// before gets its backup sooner but never later than the default
	// (RFC 8305, section 5). Zero keeps the default schedule, and it only
	// takes effect on the single-address path.
	firstBackup time.Duration
	// onConnect, when set, is called with how long the first attempt took,
	// but only when the first attempt is the one that connected, and within
	// backupAfter[0]. A time from a dial the backups rescued, or from a
	// first attempt that connected on a retransmitted SYN, would be the
	// hole's, not the path's, so it is not recorded.
	onConnect func(time.Duration)
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
	switch len(candidates) {
	case 0:
		return nil, errors.New("no address to dial")
	case 1:
		return dialOne(ctx, dial, candidates[0])
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn  net.Conn
		err   error
		index int
	}
	results := make(chan result)
	delay := 250 * time.Millisecond
	if end, ok := ctx.Deadline(); ok && time.Until(end)/time.Duration(len(candidates)+1) < delay {
		delay = max(time.Nanosecond, time.Until(end)/time.Duration(len(candidates)+1))
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	next, active := 0, 0
	errs := make([]error, len(candidates))
	// A cancelled dial is answered with the cancellation, named by the first
	// address like any other answer. An address still dialing when the budget
	// ends met the end of the budget, and the order decides as usual.
	ended := func(cause error) error {
		if !errors.Is(cause, context.DeadlineExceeded) {
			return fmt.Errorf("dial %s: %w", candidates[0].addr, cause)
		}
		for i := range next {
			if errs[i] == nil {
				errs[i] = fmt.Errorf("dial %s: %w", candidates[i].addr, cause)
			}
		}
		return firstFailure(errs)
	}
	launch := func() error {
		if err := spent(ctx); err != nil {
			return err
		}
		index := next
		candidate := candidates[index]
		remaining := len(candidates) - index
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
			case results <- result{c, err, index}:
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
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, ended(ctx.Err())
		case r := <-results:
			active--
			if r.err == nil {
				if err := ctx.Err(); err != nil {
					_ = r.conn.Close()
					return nil, ended(err)
				}
				return r.conn, nil
			}
			errs[r.index] = r.err
			if next < len(candidates) {
				if err := launch(); err != nil {
					return nil, ended(err)
				}
				timer.Reset(delay)
			}
		case <-timer.C:
			if next < len(candidates) && active < 2 {
				if err := launch(); err != nil {
					return nil, ended(err)
				}
			}
			if next < len(candidates) {
				timer.Reset(delay)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, ended(err)
	}
	return nil, firstFailure(errs)
}

// firstFailure names a dial that no address answered: the first address in
// the resolver's order, as in net.Dialer, whichever failed first, unless it
// only says this host has no route for that family - then what another
// address met is the answer. Addresses never tried have no error.
func firstFailure(errs []error) error {
	var missing error
	for _, err := range errs {
		switch {
		case err == nil:
		case !noRoute(err):
			return err
		case missing == nil:
			missing = err
		}
	}
	return missing
}

// spent reports why ctx can start no more attempts. A child deadline can fire
// before the parent's cancellation callback, so the deadline is read from the
// clock as well: nothing new starts after it in that gap.
func spent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if end, ok := ctx.Deadline(); ok && !time.Now().Before(end) {
		return context.DeadlineExceeded
	}
	return nil
}

// backupAfter is when a single-address dial opens another socket to the same
// address while no socket has connected. A SYN retransmission
// keeps the source port, so on a path that spreads flows over parallel links
// by their ports, a flow hashed onto a link that drops everything retries into
// the same hole until the budget is gone; a new socket takes a new port and
// another draw. On the node where this was found, 551 of the 553 dials that
// needed no backup were over within half a second, and a new socket fell into
// the hole again about one time in three, so the draws come early and often:
// next to backups at 1s, 3s and 7s, this schedule cut the wait of a dial that
// met the hole from 2.0s to 1.1s on average, and none of 81 waited 7s where 7
// of 75 did (docs/field/nodes.md). A destination that never answers costs six
// sockets.
var backupAfter = [...]time.Duration{
	500 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second, 5 * time.Second, 7 * time.Second,
}

// dialOne is the single-address path. The first attempt keeps the whole
// budget, and its outcome is the answer unless a backup connects first or a
// second backup is refused. One refusal may come from a firewall or a
// balancer on that backup's own path, while a second, by another port, is
// the destination answering; any other failure of a backup, such as a local
// bind error, says nothing about it. As in dialResolved, a connection that
// arrives once the budget is over or the dial is cancelled is closed. A name
// with several addresses gets its second socket from the race in
// dialResolved instead.
func dialOne(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), candidate dialCandidate) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn   net.Conn
		err    error
		backup bool
	}
	// Results are taken until dialOne returns, not until ctx ends: at the
	// deadline the first attempt's own error is the answer. Like the race in
	// net.Dialer, this relies on Dial returning once ctx is done.
	results := make(chan result)
	returned := make(chan struct{})
	defer close(returned)
	attempt := func(backup bool) {
		c, err := checkedDial(keepValues(ctx, candidate.ctx), dial, candidate.addr)
		select {
		case results <- result{c, err, backup}:
		case <-returned:
			if c != nil {
				_ = c.Close()
			}
		}
	}
	start := time.Now()
	go attempt(false)
	// The first backup may come sooner than the default when the history of
	// this prefix says a healthy connection is quick here; it never comes
	// later. The rest of the schedule is unchanged, measured from start.
	first := backupAfter[0]
	if candidate.firstBackup > 0 && candidate.firstBackup < first {
		first = candidate.firstBackup
	}
	timer := time.NewTimer(first)
	defer timer.Stop()
	next, refusals := 0, 0
	for {
		select {
		case r := <-results:
			if r.err == nil {
				if err := ctx.Err(); err != nil {
					_ = r.conn.Close()
					if !r.backup {
						return nil, fmt.Errorf("dial %s: %w", candidate.addr, err)
					}
					continue
				}
				// A first attempt that took longer than the default first
				// backup has nothing to teach the history: it either lost its
				// SYN and connected on the kernel's retransmission, which
				// comes after a second, or sits on a path where the default
				// is right anyway. One such sample would lift the estimate for
				// several dials.
				if elapsed := time.Since(start); !r.backup && candidate.onConnect != nil && elapsed < backupAfter[0] {
					candidate.onConnect(elapsed)
				}
				return r.conn, nil
			}
			if !r.backup {
				return nil, r.err
			}
			if refused(r.err) {
				if refusals++; refusals == 2 {
					return nil, r.err
				}
			}
		case <-timer.C:
			// The first attempt is about to report the end of the budget;
			// a backup started now would only be handed a dead context.
			if spent(ctx) != nil {
				continue
			}
			go attempt(true)
			if next++; next < len(backupAfter) {
				timer.Reset(backupAfter[next] - time.Since(start))
			}
		}
	}
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

// refused reports a connection refused: an RST, or an ICMP port unreachable,
// in answer to the SYN. Like noRoute, it reads the text as well.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "connection refused")
}

// noRoute reports a local "no route for this family" failure, the one IPv6
// gives on a host without IPv6. The text match covers Dial hooks that return
// their own errors; handleConnect maps replies by the same text.
func noRoute(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || strings.Contains(err.Error(), "network is unreachable")
}

// dialBackupFloor is the earliest a history-timed first backup may open. It is
// RFC 8305's minimum connection attempt delay: below it the backup races the
// first attempt so closely that healthy destinations open a second socket for
// nothing.
const dialBackupFloor = 100 * time.Millisecond

// dialHistory remembers how long a healthy connection to a destination prefix
// took, so the next dial there can time its first backup socket from the path
// rather than from a fixed default (RFC 8305, section 5). It is keyed by prefix,
// not by address, because a link is chosen by the whole 5-tuple and neighbours
// share a path: /24 for IPv4, /48 for IPv6. The map is bounded by a ring that
// evicts the oldest prefix, so a server that dials everywhere does not grow it
// without limit.
type dialHistory struct {
	mu     sync.Mutex
	sample map[netip.Prefix]time.Duration
	ring   []netip.Prefix
	next   int
}

const dialHistoryLimit = 1024

func newDialHistory() *dialHistory {
	return &dialHistory{
		sample: make(map[netip.Prefix]time.Duration),
		ring:   make([]netip.Prefix, dialHistoryLimit),
	}
}

// dialPrefix is the history key of a numeric address.
func dialPrefix(addr string) (netip.Prefix, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	bits := 24
	if ip.Is6() {
		bits = 48
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// firstBackup is when the next dial to addr should open its first backup,
// derived from the recorded connect time with a margin so a healthy socket
// usually wins first, clamped to [dialBackupFloor, backupAfter[0]]. Zero means
// no history, and the caller keeps the default schedule.
func (h *dialHistory) firstBackup(addr string) time.Duration {
	p, ok := dialPrefix(addr)
	if !ok {
		return 0
	}
	h.mu.Lock()
	d, ok := h.sample[p]
	h.mu.Unlock()
	if !ok {
		return 0
	}
	return clampDuration(d+d/2, dialBackupFloor, backupAfter[0])
}

// record folds a clean connect time into the prefix's history.
func (h *dialHistory) record(addr string, d time.Duration) {
	if d <= 0 {
		return
	}
	p, ok := dialPrefix(addr)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, ok := h.sample[p]
	if !ok {
		if old := h.ring[h.next]; old.IsValid() {
			delete(h.sample, old)
		}
		h.ring[h.next] = p
		h.next = (h.next + 1) % len(h.ring)
		h.sample[p] = d
		return
	}
	// A slow exponential average keeps one outlier from moving the estimate.
	h.sample[p] = (prev*3 + d) / 4
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
