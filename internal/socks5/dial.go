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
	// firstBackup, when nonzero, is when this address gets its first backup
	// socket, counted from its own first attempt, instead of the default
	// backupAfter[0]. handleConnect sets it from the dial history of this
	// address's prefix, clamped to [dialBackupFloor, backupAfter[0]], so a
	// destination we have reached before gets its backup sooner but never
	// later than the default (RFC 8305, section 5). Zero keeps the default.
	firstBackup time.Duration
	// onConnect, when set, is called with how long this address's first
	// attempt took, but only when that attempt is the one that connected, and
	// within backupAfter[0]. A time from a dial the backups rescued, or from a
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

// dialSocketLimit is how many sockets one CONNECT may send into the network,
// whatever the name resolves to: what one address that never answers costs,
// its first attempt and every backup. A failure that never left this host
// (stayedLocal) takes no place in it.
const dialSocketLimit = 1 + len(backupAfter)

// dialAttemptDelay is how long the next address waits for the one before it
// (RFC 8305, section 5). A short budget divides it, but not below that
// section's minimum, dialAttemptFloor.
const (
	dialAttemptDelay = 250 * time.Millisecond
	dialAttemptFloor = 10 * time.Millisecond
)

// dialResolved dials checked numeric addresses on one schedule, a literal and
// the addresses of a name alike (dialPlan). Every started address keeps its
// first attempt for the whole budget and opens its own backups, counted from
// its own start, so a name with one live address dials it as its literal
// would: the others fail locally and take no socket, or wait for theirs.
// The first connection wins and any other is closed; an unbuffered result
// channel transfers socket ownership exactly once.
func dialResolved(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error),
	candidates []dialCandidate) (net.Conn, error) {
	if len(candidates) == 0 {
		return nil, errors.New("no address to dial")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn   net.Conn
		err    error
		index  int
		backup bool
	}
	results := make(chan result)
	returned := make(chan struct{})
	defer close(returned)
	// Each address has a context of its own, so that its answer releases its
	// remaining sockets and nobody else's.
	lanes := make([]context.Context, len(candidates))
	stops := make([]context.CancelFunc, len(candidates))
	attempt := func(i int, backup bool) {
		if !backup {
			if len(candidates) == 1 {
				lanes[i], stops[i] = ctx, func() {}
			} else {
				lanes[i], stops[i] = context.WithCancel(ctx)
			}
		}
		go func(lane context.Context, c dialCandidate) {
			conn, err := checkedDial(keepValues(lane, c.ctx), dial, c.addr)
			select {
			case results <- result{conn, err, i, backup}:
			case <-returned:
				if conn != nil {
					_ = conn.Close()
				}
			}
		}(lanes[i], candidates[i])
	}
	plan := newDialPlan(candidates, attemptDelay(ctx, len(candidates)))
	errs := make([]error, len(candidates))
	// A cancelled dial is answered with the cancellation, named by the first
	// address like any other answer. An address still dialing when the budget
	// ends met the end of the budget, and the order decides as usual.
	ended := func(cause error) error {
		if !errors.Is(cause, context.DeadlineExceeded) {
			return fmt.Errorf("dial %s: %w", candidates[0].addr, cause)
		}
		for i := range plan.launched {
			if errs[i] == nil {
				errs[i] = fmt.Errorf("dial %s: %w", candidates[i].addr, cause)
			}
		}
		return firstFailure(errs)
	}
	// A literal takes results until it returns, not until ctx ends: at the
	// end of the budget, or on cancellation, its first attempt's own error is
	// the answer, as it was before backups existed. Like the race in
	// net.Dialer, this relies on Dial returning once ctx is done. A name is
	// answered by ended at that moment.
	var done <-chan struct{}
	if len(candidates) > 1 {
		done = ctx.Done()
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var stopped error
	for {
		now := time.Now()
		for stopped == nil {
			// Nothing starts after the budget: an attempt would only be
			// handed a dead context.
			if stopped = spent(ctx); stopped != nil {
				break
			}
			i, backup, ok := plan.next(now)
			if !ok {
				break
			}
			attempt(i, backup)
		}
		if plan.over(stopped != nil) {
			if plan.launched == 0 {
				return nil, stopped
			}
			if done != nil {
				if err := ctx.Err(); err != nil {
					return nil, ended(err)
				}
				if stopped != nil {
					return nil, ended(stopped)
				}
			}
			return nil, firstFailure(errs)
		}
		var wake <-chan time.Time
		if at, ok := plan.wake(); ok && stopped == nil {
			timer.Reset(time.Until(at))
			wake = timer.C
		}
		select {
		case <-done:
			return nil, ended(ctx.Err())
		case <-wake:
		case r := <-results:
			if r.err != nil && stayedLocal(r.err) {
				plan.used--
			}
			if plan.addrs[r.index].answered {
				if r.conn != nil {
					_ = r.conn.Close()
				}
				continue
			}
			if r.err == nil {
				err := ctx.Err()
				if err == nil {
					c := candidates[r.index]
					// A first attempt that took longer than the default first
					// backup has nothing to teach the history: it either lost
					// its SYN and connected on the kernel's retransmission,
					// which comes after a second, or sits on a path where the
					// default is right anyway. One such sample would lift the
					// estimate for several dials.
					if elapsed := time.Since(plan.addrs[r.index].start); !r.backup && c.onConnect != nil && elapsed < backupAfter[0] {
						c.onConnect(elapsed)
					}
					return r.conn, nil
				}
				_ = r.conn.Close()
				if r.backup {
					continue
				}
				r.err = fmt.Errorf("dial %s: %w", candidates[r.index].addr, err)
			}
			if plan.settle(r.index, r.backup, r.err, time.Now()) {
				errs[r.index] = r.err
				stops[r.index]()
			}
		}
	}
}

// dialPlan is the schedule of one dial, kept apart from its sockets.
//
// The first address starts at once, and each next one dialAttemptDelay after
// the one before, or at once when an address answers. Each started address
// opens a backup at each moment of backupAfter counted from its own start,
// the first one sooner when its history says so, until it answers or
// connects. A new address goes before a backup due at the same moment:
// another address is another hash and maybe another host. A backup may not
// take the place of an address still waiting for its first try, and a backup
// moment that finds no room passes without a socket.
type dialPlan struct {
	addrs    []addressPlan
	delay    time.Duration
	launched int       // addresses whose first attempt has started, in order
	used     int       // sockets that may have reached the network
	nextNew  time.Time // when the next address may start
}

type addressPlan struct {
	start       time.Time
	firstBackup time.Duration
	backups     int // backup moments passed, whether a socket opened or not
	refusals    int
	answered    bool
}

func newDialPlan(candidates []dialCandidate, delay time.Duration) *dialPlan {
	p := &dialPlan{addrs: make([]addressPlan, len(candidates)), delay: delay}
	for i, c := range candidates {
		p.addrs[i].firstBackup = c.firstBackup
	}
	return p
}

// attemptDelay leaves every address a moment within the budget when it can.
func attemptDelay(ctx context.Context, n int) time.Duration {
	end, ok := ctx.Deadline()
	if !ok {
		return dialAttemptDelay
	}
	return clampDuration(time.Until(end)/time.Duration(n+1), dialAttemptFloor, dialAttemptDelay)
}

// next returns the attempt due at now, if any, and counts its socket.
func (p *dialPlan) next(now time.Time) (index int, backup, ok bool) {
	if p.launched < len(p.addrs) && p.used < dialSocketLimit && !now.Before(p.nextNew) {
		i := p.launched
		p.addrs[i].start = now
		p.launched++
		p.used++
		p.nextNew = now.Add(p.delay)
		return i, false, true
	}
	waiting := len(p.addrs) - p.launched
	for i := range p.launched {
		a := &p.addrs[i]
		for at, due := a.backupAt(); due && !now.Before(at); at, due = a.backupAt() {
			a.backups++
			if p.used+1+waiting <= dialSocketLimit {
				p.used++
				return i, true, true
			}
		}
	}
	return 0, false, false
}

// wake is the next moment something may start.
func (p *dialPlan) wake() (time.Time, bool) {
	var at time.Time
	ok := p.launched < len(p.addrs) && p.used < dialSocketLimit
	if ok {
		at = p.nextNew
	}
	for i := range p.launched {
		if b, due := p.addrs[i].backupAt(); due && (!ok || b.Before(at)) {
			at, ok = b, true
		}
	}
	return at, ok
}

// settle takes a failed socket of address i and reports whether it is that
// address's answer, as for a literal: the first attempt's failure is, and so
// is a second refused backup. One refusal may come from a firewall or a
// balancer on that backup's own path (RFC 3360), while a second, by another
// port, is the destination answering; any other failure of a backup, such as
// a local bind error, says nothing about it.
func (p *dialPlan) settle(i int, backup bool, err error, now time.Time) bool {
	a := &p.addrs[i]
	if backup {
		if !refused(err) {
			return false
		}
		if a.refusals++; a.refusals < 2 {
			return false
		}
	}
	a.answered = true
	if now.Before(p.nextNew) {
		p.nextNew = now
	}
	return true
}

// over reports that every started address has answered and no other can
// start.
func (p *dialPlan) over(stopped bool) bool {
	for i := range p.launched {
		if !p.addrs[i].answered {
			return false
		}
	}
	return stopped || p.launched == len(p.addrs) || p.used >= dialSocketLimit
}

func (a *addressPlan) backupAt() (time.Time, bool) {
	if a.answered || a.backups == len(backupAfter) {
		return time.Time{}, false
	}
	after := backupAfter[a.backups]
	if a.backups == 0 && a.firstBackup > 0 && a.firstBackup < after {
		after = a.firstBackup
	}
	return a.start.Add(after), true
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
		case !stayedLocal(err):
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

// backupAfter is when an address, counted from its first attempt, opens another
// socket to itself while none of its sockets has connected or been answered. A
// SYN retransmission keeps the source port, so on a path that spreads flows
// over parallel links by their ports, a flow hashed onto a link that drops
// everything retries into the same hole until the budget is gone; a new socket
// takes a new port and another draw. On the node where this was found, 551 of
// the 553 dials that needed no backup were over within half a second, and a new
// socket fell into the hole again about one time in three, so the draws come
// early and often: next to backups at 1s, 3s and 7s, this schedule cut the wait
// of a dial that met the hole from 2.0s to 1.1s on average, and none of 81
// waited 7s where 7 of 75 did (docs/field/nodes.md). A destination that never
// answers costs six sockets, and so does a name: dialSocketLimit.
var backupAfter = [...]time.Duration{
	500 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second, 5 * time.Second, 7 * time.Second,
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

// stayedLocal reports a failure that sent nothing into the network: no route
// for the family, or no such family on this host. It costs no place in
// dialSocketLimit.
func stayedLocal(err error) bool {
	return noRoute(err) || errors.Is(err, syscall.EAFNOSUPPORT)
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
