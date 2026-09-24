package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// maxDatagrams caps one run, which keeps a few slices of that length per test.
	maxDatagrams = 2_000_000
	// maxTotalRate caps the matrix: every flow runs at -rate at the same time.
	maxTotalRate = 20_000
)

type cellSpec struct {
	port int
	form *form
	size int
}

type probeConfig struct {
	host   netip.Addr
	cells  []cellSpec
	count  int
	rate   float64
	drain  time.Duration
	reuse  bool
	window time.Duration // set in sustain mode
	json   bool
}

func probeMain(args []string) error {
	cfg, err := parseProbe(args, os.Stderr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	out := newPrinter(os.Stdout, cfg.json)

	if cfg.window > 0 {
		c := cfg.cells[0]
		fmt.Fprintf(os.Stderr, "udpshape: sustain %s@%d to %s, %g pps for %s\n",
			c.form.name, c.size, netip.AddrPortFrom(cfg.host, uint16(c.port)), cfg.rate,
			time.Duration(float64(cfg.count)/cfg.rate*float64(time.Second)).Round(time.Second))
		total, err := runSustain(ctx, cfg, out.window)
		out.total(total)
		return interrupted(err)
	}

	n := len(cfg.cells)
	fmt.Fprintf(os.Stderr, "udpshape: %d tests x %d datagrams to %s, %g pps per flow, %g pps in all, about %s\n",
		n, cfg.count, cfg.host, cfg.rate, cfg.rate*float64(n),
		(time.Duration(float64(cfg.count)/cfg.rate*float64(time.Second)) + cfg.drain).Round(100*time.Millisecond))
	rows, err := runMatrix(ctx, cfg)
	out.matrix(rows)
	return interrupted(err)
}

func interrupted(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("interrupted, results above are partial")
	}
	return err
}

func parseProbe(args []string, notes io.Writer) (probeConfig, error) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	to := fs.String("to", "", "server as HOST:PORT[,PORT...] (required)")
	formList := fs.String("forms", "all", "comma-separated forms: "+formNames()+", or all")
	sizeList := fs.String("sizes", "100,500,1200", "comma-separated UDP payload sizes in bytes")
	count := fs.Int("count", 100, "datagrams per test")
	rate := fs.Float64("rate", 64, "datagrams per second in each flow")
	drain := fs.Duration("drain", 2*time.Second, "how long to wait for replies after the last send")
	reuse := fs.Bool("reuse", false, "send every test from one socket instead of a fresh source port each")
	asJSON := fs.Bool("json", false, "print JSON lines")
	sustain := fs.String("sustain", "", "send one flow of FORM@SIZE instead of the matrix")
	duration := fs.Duration("duration", 60*time.Second, "length of the -sustain flow")
	window := fs.Duration("window", 5*time.Second, "report the -sustain flow per window of this length")
	if err := fs.Parse(args); err != nil {
		return probeConfig{}, flagError(err)
	}
	if fs.NArg() > 0 {
		return probeConfig{}, usagef("probe: unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if *to == "" {
		return probeConfig{}, usagef("probe: -to is required")
	}
	host, ports, err := parseHostPorts(*to)
	if err != nil {
		return probeConfig{}, err
	}
	if host == "" {
		return probeConfig{}, usagef("probe: -to needs a host")
	}
	if *rate <= 0 || *rate > 10000 || math.IsNaN(*rate) {
		return probeConfig{}, usagef("probe: -rate must be above 0 and at most 10000")
	}
	if *drain <= 0 {
		return probeConfig{}, usagef("probe: -drain must be positive")
	}
	cfg := probeConfig{rate: *rate, drain: *drain, reuse: *reuse, json: *asJSON}

	if *sustain != "" {
		for _, name := range []string{"forms", "sizes", "count", "reuse"} {
			if set[name] {
				return probeConfig{}, usagef("probe: -%s does not apply to -sustain", name)
			}
		}
		if len(ports) != 1 {
			return probeConfig{}, usagef("probe: -sustain measures one flow, give -to one port")
		}
		name, digits, ok := strings.Cut(*sustain, "@")
		fm := formByName(name)
		size, err := strconv.Atoi(digits)
		if !ok || fm == nil || err != nil {
			return probeConfig{}, usagef("probe: -sustain wants FORM@SIZE with a form from: %s", formNames())
		}
		if size, err = fm.wire(size); err != nil {
			return probeConfig{}, usagef("probe: -sustain: %v", err)
		}
		if *window <= 0 || *duration < *window {
			return probeConfig{}, usagef("probe: -window must be positive and -duration at least one window")
		}
		if window.Seconds()**rate < 1 {
			return probeConfig{}, usagef("probe: at -rate %g a %s window holds no datagram", *rate, *window)
		}
		cfg.count = int(math.Round(duration.Seconds() * *rate))
		cfg.window = *window
		cfg.cells = []cellSpec{{port: ports[0], form: fm, size: size}}
	} else {
		for _, name := range []string{"duration", "window"} {
			if set[name] {
				return probeConfig{}, usagef("probe: -%s applies only to -sustain", name)
			}
		}
		if *count < 1 {
			return probeConfig{}, usagef("probe: -count must be positive")
		}
		fl, err := parseForms(*formList)
		if err != nil {
			return probeConfig{}, err
		}
		sizes, err := parseSizes(*sizeList)
		if err != nil {
			return probeConfig{}, err
		}
		for _, fm := range fl {
			for _, want := range sizes {
				size, err := fm.wire(want)
				if err != nil {
					_, _ = fmt.Fprintf(notes, "udpshape: skip %s@%d: %v\n", fm.name, want, err)
					continue
				}
				for _, p := range ports {
					cfg.cells = append(cfg.cells, cellSpec{port: p, form: fm, size: size})
				}
			}
		}
		if len(cfg.cells) == 0 {
			return probeConfig{}, usagef("probe: no form fits any of the sizes")
		}
		cfg.count = *count
		slices.SortStableFunc(cfg.cells, func(a, b cellSpec) int { return a.port - b.port })
	}
	if total := cfg.rate * float64(len(cfg.cells)); total > maxTotalRate {
		return probeConfig{}, usagef("probe: %d flows at %g pps are %g pps in all, at most %d; lower -rate or the matrix",
			len(cfg.cells), cfg.rate, total, maxTotalRate)
	}
	if len(cfg.cells)*cfg.count > maxDatagrams {
		return probeConfig{}, usagef("probe: %d datagrams in one run, at most %d", len(cfg.cells)*cfg.count, maxDatagrams)
	}

	cfg.host, err = resolve(host)
	return cfg, err
}

func resolve(host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0], nil
}

// cell is one test: a port, a form and a size, with a token of its own.
type cell struct {
	cellSpec
	token    [8]byte
	conn     *net.UDPConn
	srcPort  int
	dst      netip.AddrPort
	fl       *flow
	sent     []atomic.Int64 // send time since the run started + 1; 0 is not sent
	sendErrs atomic.Int64

	mu      sync.Mutex
	got     []bool
	rtt     []time.Duration
	countAt []uint32
	mangled int
}

// record takes one reply and reports whether it was the first for its seq.
func (c *cell) record(t trailer, n int, at time.Duration) bool {
	seq := int(t.seq)
	if seq >= len(c.sent) {
		return false
	}
	sentAt := c.sent[seq].Load()
	if sentAt == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n != c.size {
		c.mangled++
		return false
	}
	if c.got[seq] {
		return false
	}
	c.got[seq] = true
	c.rtt[seq] = at - time.Duration(sentAt-1)
	c.countAt[seq] = t.count
	return true
}

type tally struct {
	sent, replies int
	maxCount      uint32
	rtts          []time.Duration
}

func (c *cell) tally(lo, hi int) tally {
	c.mu.Lock()
	defer c.mu.Unlock()
	var t tally
	for i := lo; i < hi; i++ {
		if c.sent[i].Load() != 0 {
			t.sent++
		}
		if c.got[i] {
			t.replies++
			t.maxCount = max(t.maxCount, c.countAt[i])
			t.rtts = append(t.rtts, c.rtt[i])
		}
	}
	return t
}

type run struct {
	cfg     probeConfig
	cells   []*cell
	tokens  map[[8]byte]*cell
	conns   []*net.UDPConn
	start   time.Time
	pending atomic.Int64
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// open makes the sockets and starts listening for replies. Each test gets a
// socket of its own unless cfg.reuse, and with one shared socket the tests of
// a form share its flow too, as one session sending several sizes would.
func open(ctx context.Context, cfg probeConfig) (*run, error) {
	network := "udp4"
	if cfg.host.Is6() {
		network = "udp6"
	}
	var lc net.ListenConfig
	listen := func() (*net.UDPConn, error) {
		pc, err := lc.ListenPacket(ctx, network, ":0")
		if err != nil {
			return nil, err
		}
		c := pc.(*net.UDPConn)
		_ = c.SetReadBuffer(1 << 20)
		return c, nil
	}

	r := &run{cfg: cfg, tokens: map[[8]byte]*cell{}, done: make(chan struct{})}
	flows := map[byte]*flow{}
	for _, s := range cfg.cells {
		c := &cell{cellSpec: s, dst: netip.AddrPortFrom(cfg.host, uint16(s.port))}
		for {
			fill(c.token[:])
			if r.tokens[c.token] == nil {
				break
			}
		}
		if !cfg.reuse || len(r.conns) == 0 {
			conn, err := listen()
			if err != nil {
				r.close()
				return nil, err
			}
			r.conns = append(r.conns, conn)
		}
		c.conn = r.conns[len(r.conns)-1]
		c.srcPort = int(c.conn.LocalAddr().(*net.UDPAddr).AddrPort().Port())
		c.fl = newFlow()
		if cfg.reuse {
			if flows[s.form.id] == nil {
				flows[s.form.id] = c.fl
			}
			c.fl = flows[s.form.id]
		}
		c.sent = make([]atomic.Int64, cfg.count)
		c.got = make([]bool, cfg.count)
		c.rtt = make([]time.Duration, cfg.count)
		c.countAt = make([]uint32, cfg.count)
		r.cells = append(r.cells, c)
		r.tokens[c.token] = c
	}
	r.pending.Store(int64(len(r.cells) * cfg.count))
	r.start = time.Now()
	for _, conn := range r.conns {
		r.wg.Add(1)
		go r.receive(conn)
	}
	return r, nil
}

// send paces the whole run. Every round sends datagram seq of every test in
// a fresh random order, spread evenly over one interval of the flow rate, so
// each flow runs at cfg.rate and no form owns the start or the end of the run.
func (r *run) send(ctx context.Context) error {
	n := len(r.cells)
	step := float64(time.Second) / r.cfg.rate / float64(n)
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	buf := make([]byte, maxDatagram)
	slot := 0
	for seq := 0; seq < r.cfg.count; seq++ {
		rand.Shuffle(n, func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, i := range order {
			if err := sleepUntil(ctx, r.start.Add(time.Duration(float64(slot)*step))); err != nil {
				return err
			}
			slot++
			c := r.cells[i]
			p := buf[:c.size]
			st := c.fl.next()
			c.form.build(p, &st, nil, trailer{token: c.token, form: c.form.id, seq: uint32(seq)})
			c.sent[seq].Store(int64(time.Since(r.start)) + 1)
			if _, err := c.conn.WriteToUDPAddrPort(p, c.dst); err != nil {
				c.sent[seq].Store(0)
				c.sendErrs.Add(1)
				r.settle()
			}
		}
	}
	return nil
}

func sleepUntil(ctx context.Context, t time.Time) error {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *run) receive(conn *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, 1<<16)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		at := time.Since(r.start)
		t, ok := readTrailer(buf[:n])
		if !ok || !t.reply {
			continue
		}
		c := r.tokens[t.token]
		if c == nil || c.conn != conn || c.form.id != t.form ||
			netip.AddrPortFrom(src.Addr().Unmap(), src.Port()) != c.dst {
			continue
		}
		if c.record(t, n, at) {
			r.settle()
		}
	}
}

// settle marks one datagram as answered or lost to a send error; the run can
// stop draining once every datagram is settled.
func (r *run) settle() {
	if r.pending.Add(-1) == 0 {
		r.once.Do(func() { close(r.done) })
	}
}

func (r *run) wait(ctx context.Context, drain time.Duration) {
	t := time.NewTimer(drain)
	defer t.Stop()
	select {
	case <-r.done:
	case <-t.C:
	case <-ctx.Done():
	}
	r.close()
}

func (r *run) close() {
	for _, c := range r.conns {
		_ = c.Close()
	}
	r.wg.Wait()
}

func runMatrix(ctx context.Context, cfg probeConfig) ([]row, error) {
	r, err := open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	err = r.send(ctx)
	r.wait(ctx, cfg.drain)
	rows := make([]row, 0, len(r.cells))
	for _, c := range r.cells {
		rows = append(rows, r.row(c, c.tally(0, cfg.count)))
	}
	return rows, err
}

// runSustain sends one flow and emits a row per window once the window's
// replies have had the drain time to arrive. The server's count is
// cumulative, so a window's uplink is the growth of that count; a window with
// no replies cannot say what reached the server, and the next window that
// has replies reports uplink over both.
func runSustain(ctx context.Context, cfg probeConfig, emit func(row)) (row, error) {
	r, err := open(ctx, cfg)
	if err != nil {
		return row{}, err
	}
	c := r.cells[0]
	sendErr := make(chan error, 1)
	go func() { sendErr <- r.send(ctx) }()

	var known, runMax uint32
	since, spanSent := 0, 0
	per := cfg.window.Seconds() * cfg.rate
	for w, lo := 0, 0; lo < cfg.count; w++ {
		hi := min(cfg.count, int(math.Ceil(float64(w+1)*per-1e-9)))
		if sleepUntil(ctx, r.start.Add(time.Duration(w+1)*cfg.window+cfg.drain)) != nil {
			break
		}
		t := c.tally(lo, hi)
		spanSent += t.sent
		runMax = max(runMax, t.maxCount)
		out := r.row(c, t)
		out.ServerReceived, out.UplinkPct, out.DownlinkPct = nil, nil, nil
		out.Mangled, out.SendErrors = 0, 0
		out.Window = &w
		from := (time.Duration(w) * cfg.window).Seconds()
		out.FromS = &from
		if t.replies > 0 {
			srv := int(runMax - known)
			out.ServerReceived = &srv
			out.UplinkPct = pct(srv, spanSent)
			out.DownlinkPct = pct(t.replies, srv)
			if since < w {
				out.UplinkSince = &since
			}
			known, since, spanSent = runMax, w+1, 0
		}
		emit(out)
		lo = hi
	}
	err = <-sendErr
	r.close()
	return r.row(c, c.tally(0, cfg.count)), err
}

// row is one line of output. Pointers are figures that may be unknown: with
// no replies at all the run cannot tell uplink loss from downlink loss.
type row struct {
	Time           string   `json:"time"`
	Target         string   `json:"target"`
	Port           int      `json:"port"`
	Form           string   `json:"form"`
	Size           int      `json:"size"`
	Window         *int     `json:"window,omitempty"`
	FromS          *float64 `json:"from_s,omitempty"`
	Sent           int      `json:"sent"`
	ServerReceived *int     `json:"server_received"`
	Replies        int      `json:"replies"`
	UplinkPct      *float64 `json:"uplink_pct"`
	DownlinkPct    *float64 `json:"downlink_pct"`
	RTTp50         *float64 `json:"rtt_p50_ms"`
	RTTp95         *float64 `json:"rtt_p95_ms"`
	UplinkSince    *int     `json:"uplink_since_window,omitempty"`
	Mangled        int      `json:"mangled,omitempty"`
	SendErrors     int      `json:"send_errors,omitempty"`
	SrcPort        int      `json:"src_port"`
	Token          string   `json:"token"`
}

func (r *run) row(c *cell, t tally) row {
	out := row{
		Time:       stamp(r.start),
		Target:     r.cfg.host.String(),
		Port:       c.port,
		Form:       c.form.name,
		Size:       c.size,
		Sent:       t.sent,
		Replies:    t.replies,
		SendErrors: int(c.sendErrs.Load()),
		SrcPort:    c.srcPort,
		Token:      hex.EncodeToString(c.token[:]),
	}
	c.mu.Lock()
	out.Mangled = c.mangled
	c.mu.Unlock()
	if t.replies > 0 {
		srv := int(t.maxCount)
		out.ServerReceived = &srv
		out.UplinkPct = pct(srv, t.sent)
		out.DownlinkPct = pct(t.replies, srv)
	}
	out.RTTp50, out.RTTp95 = percentile(t.rtts, 0.50), percentile(t.rtts, 0.95)
	return out
}

func pct(n, of int) *float64 {
	if of == 0 {
		return nil
	}
	v := math.Round(1000*float64(n)/float64(of)) / 10
	return &v
}

func percentile(d []time.Duration, p float64) *float64 {
	if len(d) == 0 {
		return nil
	}
	s := slices.Clone(d)
	slices.Sort(s)
	i := max(int(math.Ceil(p*float64(len(s))))-1, 0)
	v := math.Round(float64(s[i])/1e4) / 100
	return &v
}

type printer struct {
	w      io.Writer
	json   *json.Encoder
	header bool
}

func newPrinter(w io.Writer, asJSON bool) *printer {
	p := &printer{w: w}
	if asJSON {
		p.json = json.NewEncoder(w)
	}
	return p
}

const (
	matrixFmt = "%-6v %-12v %5v %6v %8v %7v %6v %6v %8v %8v%s\n"
	windowFmt = "%-6v %6v %6v %8v %7v %6v %6v %8v %8v%s\n"
)

func (p *printer) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(p.w, format, a...)
}

func (p *printer) matrix(rows []row) {
	if p.json == nil && len(rows) > 0 {
		p.printf(matrixFmt, "port", "form", "size", "sent", "srv_recv", "replies", "up%", "down%", "rtt_p50", "rtt_p95", "")
	}
	for _, r := range rows {
		if p.json != nil {
			_ = p.json.Encode(r)
			continue
		}
		p.printf(matrixFmt, r.Port, r.Form, r.Size, r.Sent, orQ(r.ServerReceived), r.Replies,
			fnum(r.UplinkPct, 1, "?"), fnum(r.DownlinkPct, 1, "?"), fnum(r.RTTp50, 2, "-"), fnum(r.RTTp95, 2, "-"), notes(r))
	}
}

func (p *printer) window(r row) {
	if p.json != nil {
		_ = p.json.Encode(r)
		return
	}
	if !p.header {
		p.header = true
		p.printf("%s@%d to %s:%d from port %d\n", r.Form, r.Size, r.Target, r.Port, r.SrcPort)
		p.printf(windowFmt, "window", "from_s", "sent", "srv_recv", "replies", "up%", "down%", "rtt_p50", "rtt_p95", "")
	}
	p.printf(windowFmt, *r.Window, fnum(r.FromS, 1, ""), r.Sent, orQ(r.ServerReceived), r.Replies,
		fnum(r.UplinkPct, 1, "?"), fnum(r.DownlinkPct, 1, "?"), fnum(r.RTTp50, 2, "-"), fnum(r.RTTp95, 2, "-"), notes(r))
}

func (p *printer) total(r row) {
	if r.Token == "" {
		return
	}
	if p.json == nil {
		p.printf("\n")
	}
	p.matrix([]row{r})
}

func notes(r row) string {
	var s string
	if r.UplinkSince != nil {
		s += fmt.Sprintf(" up since window %d", *r.UplinkSince)
	}
	if r.Mangled > 0 {
		s += fmt.Sprintf(" mangled=%d", r.Mangled)
	}
	if r.SendErrors > 0 {
		s += fmt.Sprintf(" send_errors=%d", r.SendErrors)
	}
	return s
}

func orQ(v *int) string {
	if v == nil {
		return "?"
	}
	return strconv.Itoa(*v)
}

func fnum(v *float64, prec int, unknown string) string {
	if v == nil {
		return unknown
	}
	return strconv.FormatFloat(*v, 'f', prec, 64)
}
