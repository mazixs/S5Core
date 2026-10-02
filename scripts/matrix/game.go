package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
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
	// A resume is looked at for this long: its first echo, its longest gap.
	gameResumeWindow = 3 * time.Second
	// wakeOff runs this long after the first tick of a resume: long enough
	// for the proxy to send that tick on, and every packet in between is one
	// of the first after the pause.
	gameWakeHold = 20 * time.Millisecond
	// A tick the stream did not send, because it was paused.
	tickPaused = -2
	// After an upload stops, the queue has drained once an echo is back
	// within this of the stream's fastest one; what the sockets still held
	// kept the uplink loaded until then.
	gameDrained = 5 * time.Millisecond
)

// gameShape is what a session does besides the stream: a pause that lets the
// radio of a mobile path fall asleep, and a bulk upload beside the stream.
// Both are laid out in time from the start of the stream.
type gameShape struct {
	on, pause       time.Duration // the stream stops for pause after every on
	bulkOff, bulkOn time.Duration // an upload runs for bulkOn after every bulkOff
}

func (s gameShape) paused(at time.Duration) bool {
	return s.pause > 0 && at%(s.on+s.pause) >= s.on
}

func (s gameShape) loaded(at time.Duration) bool {
	return s.bulkOn > 0 && at%(s.bulkOff+s.bulkOn) >= s.bulkOff
}

// resume is one start of the stream after a pause.
type resume struct {
	at        time.Time
	seq       int
	firstEcho time.Duration // from the first tick to the first echo, 0 while none came
	gap       time.Duration // the longest wait for an echo within gameResumeWindow
}

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
	shape    gameShape
	rtt      []int32 // microseconds by sequence number, -1 until the echo arrives, tickPaused if not sent
	offered  int
	paused   int
	breaks   int
	closed   int
	downtime time.Duration
	firstErr string
	wakeErrs int

	mu          sync.Mutex
	lastArrival time.Time
	freezes     int
	maxGap      time.Duration
	down        time.Time // last echo before a break, zero when none is open
	resumes     []resume
	// began gets the time the stream's schedule starts from.
	began chan time.Time
}

func newGameStream(p *prober, socks string, n, hz, size int, shape gameShape) *gameStream {
	g := &gameStream{p: p, socks: socks, n: n, size: size, gap: time.Second / time.Duration(hz), shape: shape, rtt: make([]int32, n),
		began: make(chan time.Time, 1)}
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
			if k := len(g.resumes) - 1; k >= 0 && seq >= g.resumes[k].seq && now.Sub(g.resumes[k].at) < gameResumeWindow {
				r := &g.resumes[k]
				if r.firstEcho == 0 {
					r.firstEcho = now.Sub(r.at)
				}
				r.gap = max(r.gap, gap)
			}
		}
		g.lastArrival = now
		if !g.down.IsZero() {
			g.downtime += now.Sub(g.down)
			g.down = time.Time{}
		}
		g.mu.Unlock()
	}
}

// runWake runs one of the commands that put the path to sleep and wake it.
// A failure is counted, not fatal: the resume is then measured without it.
func (g *gameStream) runWake(argv []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		g.mu.Lock()
		g.wakeErrs++
		g.mu.Unlock()
		g.fail(fmt.Errorf("wake %s: %w: %s", argv[0], err, strings.TrimSpace(string(out))))
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
	g.began <- start
	var resumed time.Time
	var wakes sync.WaitGroup
	defer wakes.Wait()
	wake := g.socks == g.p.socks && len(g.p.wakeOn) > 0
	for i := range g.n {
		at := start.Add(time.Duration(i) * g.gap)
		if g.shape.paused(time.Duration(i) * g.gap) {
			g.rtt[i] = tickPaused
			g.offered++
			g.paused++
			continue
		}
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
		first := i > 0 && g.rtt[i-1] == tickPaused
		if first {
			if wake {
				g.runWake(g.p.wakeOn)
			}
			resumed = time.Now()
			g.mu.Lock()
			// The pause is not a freeze; the wait for the first echo is.
			g.lastArrival = resumed
			g.resumes = append(g.resumes, resume{at: resumed, seq: i})
			g.mu.Unlock()
		}
		lost := time.Since(later(later(g.last(), opened), resumed)) > gameStall
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
		if first && wake {
			wakes.Add(1)
			time.AfterFunc(gameWakeHold, func() { defer wakes.Done(); g.runWake(g.p.wakeOff) })
		}
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
	fastest := time.Duration(-1)
	for i := range g.offered {
		if us := atomic.LoadInt32(&g.rtt[i]); us >= 0 && (fastest < 0 || time.Duration(us)*time.Microsecond < fastest) {
			fastest = time.Duration(us) * time.Microsecond
		}
	}
	// Ticks sent and echoed while the bulk upload ran, and after it stopped
	// and its queue drained; the ticks in between are in neither.
	var load, clean []time.Duration
	var drains []float64
	loadSent, cleanSent, drained, offAt := 0, 0, true, 0
	for i := range g.offered {
		us := atomic.LoadInt32(&g.rtt[i])
		if us == tickPaused {
			continue
		}
		d := time.Duration(us) * time.Microsecond
		loaded := g.shape.loaded(time.Duration(i) * g.gap)
		switch {
		case loaded:
			if !drained && offAt >= 0 {
				drains = append(drains, -1)
			}
			drained, offAt = false, -1
			loadSent++
		case !drained:
			if offAt < 0 {
				offAt = i
			}
			if us >= 0 && d <= fastest+gameDrained {
				drained = true
				drains = append(drains, ms(time.Duration(i-offAt)*g.gap))
			}
		}
		if !loaded && drained {
			cleanSent++
		}
		if us >= 0 {
			got = append(got, d)
			if loaded {
				load = append(load, d)
			} else if drained {
				clean = append(clean, d)
			}
			if prev >= 0 {
				jitter += max(d-prev, prev-d)
			}
			prev = d
		}
	}
	sent := g.offered - g.paused
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
	hours := (time.Duration(sent) * g.gap).Hours()
	g.mu.Lock()
	st.Extra = map[string]float64{
		"loss_pct":        100 * float64(sent-len(got)) / float64(max(sent, 1)),
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
	if g.shape.bulkOn > 0 {
		if !drained && offAt >= 0 {
			drains = append(drains, -1)
		}
		st.Marks = map[string][]float64{"bulk_drain_ms": drains}
		for name, part := range map[string]struct {
			d    []time.Duration
			sent int
		}{"load": {load, loadSent}, "clean": {clean, cleanSent}} {
			st.Extra[name+"_loss_pct"] = 100 * float64(part.sent-len(part.d)) / float64(max(part.sent, 1))
			if len(part.d) > 0 {
				slices.Sort(part.d)
				pq := func(p float64) float64 { return ms(part.d[int(p*float64(len(part.d)-1))]) }
				st.Extra[name+"_p50_ms"], st.Extra[name+"_p99_ms"], st.Extra[name+"_max_ms"] = pq(0.5), pq(0.99), pq(1)
			}
		}
	}
	if g.shape.pause > 0 {
		st.Extra["wake_errors"] = float64(g.wakeErrs)
		st.Marks = map[string][]float64{}
		perSec := int(time.Second / g.gap)
		for _, r := range g.resumes {
			lost := 0
			for i := r.seq; i < min(r.seq+perSec, g.offered); i++ {
				if atomic.LoadInt32(&g.rtt[i]) == -1 {
					lost++
				}
			}
			st.Marks["resume_at"] = append(st.Marks["resume_at"], float64(r.at.UnixNano())/1e9)
			st.Marks["resume_first_echo_ms"] = append(st.Marks["resume_first_echo_ms"], ms(r.firstEcho))
			st.Marks["resume_gap_ms"] = append(st.Marks["resume_gap_ms"], ms(r.gap))
			st.Marks["resume_lost_1s"] = append(st.Marks["resume_lost_1s"], float64(lost))
		}
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
		ticks := 0
		for i := from; i < to; i++ {
			us := atomic.LoadInt32(&g.rtt[i])
			if us == tickPaused {
				continue
			}
			ticks++
			if us >= 0 {
				w = append(w, time.Duration(us)*time.Microsecond)
			}
		}
		gw := gameWindow{Minute: from / perMin, Loss: 100 * float64(ticks-len(w)) / float64(max(ticks, 1))}
		if len(w) > 0 {
			slices.Sort(w)
			gw.P50, gw.P99, gw.Max = ms(w[len(w)/2]), ms(w[int(0.99*float64(len(w)-1))]), ms(w[len(w)-1])
		}
		windows = append(windows, gw)
	}
	return st, windows
}

// bulk uploads through the proxy for bulkOn after every bulkOff from start,
// until ctx ends: the load of a player who shares the uplink with a backup
// or a video call. It returns the bytes the socket took and the Unix
// seconds of each upload's start and end.
func (p *prober) bulk(ctx context.Context, start time.Time, s gameShape) (moved int64, on, off []float64, errs int, firstErr string) {
	for k := 0; ; k++ {
		from := start.Add(time.Duration(k)*(s.bulkOff+s.bulkOn) + s.bulkOff)
		to := from.Add(s.bulkOn)
		t := time.NewTimer(time.Until(from))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		on = append(on, float64(time.Now().UnixNano())/1e9)
		n, err := p.upload(ctx, to)
		off = append(off, float64(time.Now().UnixNano())/1e9)
		moved += n
		if err != nil && ctx.Err() == nil {
			errs++
			if firstErr == "" {
				firstErr = "bulk upload: " + err.Error()
			}
		}
	}
}

// upload sends one request body to the origin until the deadline, as fast
// as the path takes it.
func (p *prober) upload(ctx context.Context, until time.Time) (int64, error) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	c, err := p.dial(dctx, "tcp", p.o.HTTP)
	cancel()
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	_ = c.SetWriteDeadline(until)
	if _, err := fmt.Fprintf(c, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", p.o.HTTP, int64(1)<<40); err != nil {
		return 0, err
	}
	buf := make([]byte, 32<<10)
	var n int64
	for {
		m, err := c.Write(buf)
		n += int64(m)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && (ctx.Err() != nil || !time.Now().Before(until)) {
				return n, nil
			}
			return n, err
		}
	}
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

func (p *prober) game(n, hz, size int, shape gameShape) stats {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	g := newGameStream(p, p.socks, n, hz, size, shape)
	var ctl *gameStream
	var streams, idle, load sync.WaitGroup
	if p.socks != "" && p.control {
		ctl = newGameStream(p, "", n, hz, size, shape)
		streams.Go(func() { ctl.run(ctx) })
	}
	var idleOK, idleFailed int
	var idleErr string
	idle.Go(func() { idleOK, idleFailed, idleErr = p.idleChannel(ctx) })
	var moved int64
	var bulkOn, bulkOff []float64
	var bulkErrs int
	var bulkErr string
	if shape.bulkOn > 0 {
		// On the stream's own schedule, which starts once its association is open.
		load.Go(func() {
			select {
			case start := <-g.began:
				moved, bulkOn, bulkOff, bulkErrs, bulkErr = p.bulk(ctx, start, shape)
			case <-ctx.Done():
			}
		})
	}
	g.run(ctx)
	streams.Wait()
	cancel()
	idle.Wait()
	load.Wait()

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
	if shape.bulkOn > 0 {
		var busy float64
		for i := range min(len(bulkOn), len(bulkOff)) {
			busy += bulkOff[i] - bulkOn[i]
		}
		st.Extra["bulk_MBps"] = float64(moved) / max(busy, 1e-9) / 1e6
		st.Extra["bulk_errors"] = float64(bulkErrs)
		st.Errors += bulkErrs
		if st.FirstErr == "" {
			st.FirstErr = bulkErr
		}
		if st.Marks == nil {
			st.Marks = map[string][]float64{}
		}
		st.Marks["bulk_on_at"], st.Marks["bulk_off_at"] = bulkOn, bulkOff
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
