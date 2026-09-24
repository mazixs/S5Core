package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// A game session: small datagrams both ways at a fixed tick rate for a long
// time, the way a fast-paced multiplayer game sends them, and beside them a
// TCP channel that stays silent longer than the server's idle timeout. Behind
// a proxy the same stream also runs directly at the same time, so its control
// covers the same minutes of the same path.
const (
	// An echo missing this long means the association is gone: reopen it, as
	// a game would reconnect.
	gameStall = 3 * time.Second
	// A gap between arrivals longer than this is a freeze a player sees.
	gameFreeze = 100 * time.Millisecond
	// A reply this much slower than the median is a lag spike, unless the
	// plan sets slow_ms.
	gameSpike = 50 * time.Millisecond
	// Longer than the server's READ_TIMEOUT (30 s): the channel lives only if
	// the tunnel keeps it alive.
	gameIdleEvery = 40 * time.Second
)

type gameWindow struct {
	Minute  int     `json:"minute"`
	P50     float64 `json:"p50_ms"`
	P99     float64 `json:"p99_ms"`
	Max     float64 `json:"max_ms"`
	Loss    float64 `json:"loss_pct"`
	CtlP50  float64 `json:"ctl_p50_ms,omitempty"`
	CtlP99  float64 `json:"ctl_p99_ms,omitempty"`
	CtlMax  float64 `json:"ctl_max_ms,omitempty"`
	CtlLoss float64 `json:"ctl_loss_pct,omitempty"`
}

type gameStream struct {
	p        *prober
	socks    string
	n, size  int
	gap      time.Duration
	rtt      []int32 // microseconds by sequence number, -1 until the echo arrives
	offered  int
	breaks   int
	closed   int
	downtime time.Duration
	firstErr string

	mu          sync.Mutex
	lastArrival time.Time
	freezes     int
	maxGap      time.Duration
	down        time.Time // last echo before a break, zero when none is open
}

func newGameStream(p *prober, socks string, n, hz, size int) *gameStream {
	g := &gameStream{p: p, socks: socks, n: n, size: size, gap: time.Second / time.Duration(hz), rtt: make([]int32, n)}
	for i := range g.rtt {
		g.rtt[i] = -1
	}
	return g
}

func (g *gameStream) fail(err error) {
	if g.firstErr == "" && err != nil {
		g.firstErr = err.Error()
	}
}

// open returns the association and a channel closed when it dies: for a
// SOCKS5 association that is its control connection closing.
func (g *gameStream) open(ctx context.Context) (net.PacketConn, <-chan struct{}) {
	for ctx.Err() == nil {
		octx, cancel := context.WithTimeout(ctx, 10*time.Second)
		pc, err := listenPacket(octx, g.socks)
		cancel()
		if err == nil {
			dead := make(chan struct{})
			if sc, ok := pc.(*socksPacketConn); ok {
				go func() { _, _ = io.Copy(io.Discard, sc.ctl); close(dead) }()
			}
			go g.receive(pc)
			return pc, dead
		}
		g.fail(err)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return nil, nil
}

func (g *gameStream) receive(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		m, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if m != g.size {
			continue
		}
		seq := int(binary.BigEndian.Uint64(buf))
		if seq < 0 || seq >= g.n {
			continue
		}
		now := time.Now()
		rtt := now.Sub(time.Unix(0, int64(binary.BigEndian.Uint64(buf[8:]))))
		if !atomic.CompareAndSwapInt32(&g.rtt[seq], -1, int32(rtt.Microseconds())) {
			continue
		}
		g.mu.Lock()
		if !g.lastArrival.IsZero() {
			gap := now.Sub(g.lastArrival)
			if gap > gameFreeze {
				g.freezes++
			}
			g.maxGap = max(g.maxGap, gap)
		}
		g.lastArrival = now
		if !g.down.IsZero() {
			g.downtime += now.Sub(g.down)
			g.down = time.Time{}
		}
		g.mu.Unlock()
	}
}

func (g *gameStream) last() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastArrival
}

func (g *gameStream) run(ctx context.Context) {
	pc, dead := g.open(ctx)
	if pc == nil {
		return
	}
	opened := time.Now()
	dst, _ := net.ResolveUDPAddr("udp", g.p.o.UDPEcho)
	msg := make([]byte, g.size)
	start := time.Now()
	for i := range g.n {
		at := start.Add(time.Duration(i) * g.gap)
		// Ticks that fell due while the association was being reopened are
		// lost, as they are to a game; sending them now would be a burst.
		if at.Before(opened) {
			g.offered++
			continue
		}
		t := time.NewTimer(time.Until(at))
		select {
		case <-ctx.Done():
			t.Stop()
			_ = pc.Close()
			return
		case <-t.C:
		}
		lost := time.Since(later(g.last(), opened)) > gameStall
		select {
		case <-dead:
			g.closed++
			lost = true
		default:
		}
		if lost {
			g.breaks++
			g.mu.Lock()
			if g.down.IsZero() {
				g.down = later(g.lastArrival, opened)
			}
			g.mu.Unlock()
			_ = pc.Close()
			if pc, dead = g.open(ctx); pc == nil {
				return
			}
			opened = time.Now()
		}
		binary.BigEndian.PutUint64(msg, uint64(i))
		binary.BigEndian.PutUint64(msg[8:], uint64(time.Now().UnixNano()))
		if _, err := pc.WriteTo(msg, dst); err != nil {
			g.fail(err)
		}
		g.offered++
	}
	// Late echoes still count; after this they are lost.
	time.Sleep(2 * time.Second)
	_ = pc.Close()
}

// summary is the stream's numbers and its per-minute windows.
func (g *gameStream) summary() (stats, []gameWindow) {
	var got []time.Duration
	var jitter time.Duration
	spikes, inSpike, prev := 0, false, time.Duration(-1)
	for i := range g.offered {
		if us := atomic.LoadInt32(&g.rtt[i]); us >= 0 {
			d := time.Duration(us) * time.Microsecond
			got = append(got, d)
			if prev >= 0 {
				jitter += max(d-prev, prev-d)
			}
			prev = d
		}
	}
	st := stats{N: len(got), FirstErr: g.firstErr}
	if len(got) == 0 {
		return st, nil
	}
	sorted := slices.Clone(got)
	slices.Sort(sorted)
	q := func(p float64) float64 { return ms(sorted[int(p*float64(len(sorted)-1))]) }
	st.P50, st.P90, st.P99, st.Max = q(0.5), q(0.9), q(0.99), ms(sorted[len(sorted)-1])
	median, margin := sorted[len(sorted)/2], gameSpike
	if g.p.slow > 0 {
		margin = g.p.slow
	}
	slow := 0
	for _, d := range got {
		over := d > median+margin
		if over {
			slow++
		}
		if over && !inSpike {
			spikes++
		}
		inSpike = over
	}
	hours := (time.Duration(g.offered) * g.gap).Hours()
	g.mu.Lock()
	st.Extra = map[string]float64{
		"loss_pct":        100 * float64(g.offered-len(got)) / float64(max(g.offered, 1)),
		"p999_ms":         q(0.999),
		"jitter_ms":       ms(jitter / time.Duration(max(len(got)-1, 1))),
		"spike_pct":       100 * float64(slow) / float64(len(got)),
		"spikes_per_hour": float64(spikes) / hours,
		"freezes":         float64(g.freezes),
		"longest_gap_ms":  ms(g.maxGap),
		"breaks":          float64(g.breaks),
		"breaks_closed":   float64(g.closed),
		"downtime_s":      g.downtime.Seconds(),
	}
	g.mu.Unlock()
	if g.p.slow > 0 {
		st.SlowPct = st.Extra["spike_pct"]
	}
	st.Errors = g.breaks
	st.Bytes = int64(2 * len(got) * g.size)

	perMin := int(time.Minute / g.gap)
	var windows []gameWindow
	for from := 0; from < g.offered; from += perMin {
		to := min(from+perMin, g.offered)
		var w []time.Duration
		for i := from; i < to; i++ {
			if us := atomic.LoadInt32(&g.rtt[i]); us >= 0 {
				w = append(w, time.Duration(us)*time.Microsecond)
			}
		}
		gw := gameWindow{Minute: from / perMin, Loss: 100 * float64(to-from-len(w)) / float64(to-from)}
		if len(w) > 0 {
			slices.Sort(w)
			gw.P50, gw.P99, gw.Max = ms(w[len(w)/2]), ms(w[int(0.99*float64(len(w)-1))]), ms(w[len(w)-1])
		}
		windows = append(windows, gw)
	}
	return st, windows
}

// idleChannel sends one small echo every gameIdleEvery over one connection
// and reconnects when it fails.
func (p *prober) idleChannel(ctx context.Context) (ok, failed int, firstErr string) {
	msg, buf := make([]byte, 64), make([]byte, 64)
	var c net.Conn
	defer func() {
		if c != nil {
			_ = c.Close()
		}
	}()
	for {
		if c == nil {
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			var err error
			c, err = p.dial(dctx, "tcp", p.o.TCPEcho)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				failed++
				if firstErr == "" {
					firstErr = "idle tcp dial: " + err.Error()
				}
				c = nil
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(gameIdleEvery):
		}
		if c == nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err := c.Write(msg)
		if err == nil {
			_, err = io.ReadFull(c, buf)
		}
		if err != nil {
			failed++
			if firstErr == "" {
				firstErr = "idle tcp echo: " + err.Error()
			}
			_ = c.Close()
			c = nil
			continue
		}
		ok++
	}
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (p *prober) game(n, hz, size int) stats {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	g := newGameStream(p, p.socks, n, hz, size)
	var ctl *gameStream
	var streams, idle sync.WaitGroup
	if p.socks != "" {
		ctl = newGameStream(p, "", n, hz, size)
		streams.Go(func() { ctl.run(ctx) })
	}
	var idleOK, idleFailed int
	var idleErr string
	idle.Go(func() { idleOK, idleFailed, idleErr = p.idleChannel(ctx) })
	g.run(ctx)
	streams.Wait()
	cancel()
	idle.Wait()

	st, windows := g.summary()
	if st.Extra == nil {
		st.Extra = map[string]float64{}
	}
	st.Extra["idle_tcp_ok"] = float64(idleOK)
	st.Extra["idle_tcp_failed"] = float64(idleFailed)
	st.Errors += idleFailed
	if st.FirstErr == "" {
		st.FirstErr = idleErr
	}
	if ctl != nil {
		c, cw := ctl.summary()
		st.Extra["ctl_p50_ms"], st.Extra["ctl_p99_ms"], st.Extra["ctl_max_ms"] = c.P50, c.P99, c.Max
		for _, k := range []string{"loss_pct", "p999_ms", "jitter_ms", "spike_pct", "spikes_per_hour", "freezes", "longest_gap_ms", "breaks"} {
			st.Extra["ctl_"+k] = c.Extra[k]
		}
		st.Bytes += c.Bytes
		for i := range min(len(windows), len(cw)) {
			windows[i].CtlP50, windows[i].CtlP99, windows[i].CtlMax, windows[i].CtlLoss = cw[i].P50, cw[i].P99, cw[i].Max, cw[i].Loss
		}
	}
	st.Series = windows
	return st
}
