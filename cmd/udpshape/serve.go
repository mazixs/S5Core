package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func serveMain(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "UDP ports to listen on, [HOST]:PORT[,PORT...] (required)")
	logPath := fs.String("log", "", "append JSON lines to this file instead of stdout")
	allow := fs.String("allow", "", "answer only these sources, CIDR or IP, comma-separated")
	maxTokens := fs.Int("max-tokens", 4096, "tests tracked at once; new ones are refused beyond this")
	ttl := fs.Duration("ttl", 10*time.Minute, "forget a test after it has been idle this long")
	if err := fs.Parse(args); err != nil {
		return flagError(err)
	}
	if fs.NArg() > 0 {
		return usagef("serve: unexpected argument %q", fs.Arg(0))
	}
	if *listen == "" {
		return usagef("serve: -listen is required")
	}
	host, ports, err := parseHostPorts(*listen)
	if err != nil {
		return err
	}
	if *maxTokens < 1 || *maxTokens > 1<<20 {
		return usagef("serve: -max-tokens must be 1-%d", 1<<20)
	}
	if *ttl < time.Second {
		return usagef("serve: -ttl must be at least 1s")
	}
	prefixes, err := parsePrefixes(*allow)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	log := &logger{enc: json.NewEncoder(out)}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	conns := make([]*net.UDPConn, 0, len(ports))
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for _, p := range ports {
		pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err != nil {
			return err
		}
		c := pc.(*net.UDPConn)
		_ = c.SetReadBuffer(4 << 20)
		conns = append(conns, c)
	}

	s := &server{allow: prefixes, table: newTable(*maxTokens, *ttl, log)}
	var wg sync.WaitGroup
	for _, c := range conns {
		log.write(event{Time: stamp(time.Now()), Event: "listen", Addr: c.LocalAddr().String()})
		wg.Go(func() { s.serve(c) })
	}
	go s.table.sweep(ctx)

	<-ctx.Done()
	for _, c := range conns {
		_ = c.Close()
	}
	wg.Wait()
	s.table.flush(time.Now())
	return nil
}

type server struct {
	allow []netip.Prefix
	table *table
}

func (s *server) serve(conn *net.UDPConn) {
	port := int(conn.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	in, out := make([]byte, 1<<16), make([]byte, 1<<16)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(in)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if p := s.answer(in[:n], src, port, out, time.Now()); p != nil {
			_, _ = conn.WriteToUDPAddrPort(p, src)
		}
	}
}

// answer builds the reply to one datagram in out, or returns nil. The reply
// is exactly as long as the request, so the server amplifies nothing, and a
// reply is never answered, so two servers cannot bounce datagrams forever.
func (s *server) answer(req []byte, src netip.AddrPort, port int, out []byte, now time.Time) []byte {
	t, ok := readTrailer(req)
	if !ok || t.reply {
		return nil
	}
	fm := formByID(t.form)
	if len(req) < fm.min || !allowed(s.allow, src.Addr()) {
		return nil
	}
	count, fl, ok := s.table.hit(key{t.token, t.form}, src, port, len(req), now)
	if !ok {
		return nil
	}
	p := out[:len(req)]
	t.reply, t.count = true, count
	fm.build(p, &fl, req, t)
	return p
}

func allowed(prefixes []netip.Prefix, a netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// key identifies a test by its token alone, not by source address: a mobile
// NAT that rebinds mid-flow would otherwise restart the count, and the count
// is the uplink figure. The token is 64 random bits, so it is not guessable.
type key struct {
	token [8]byte
	form  byte
}

type entry struct {
	src         netip.AddrPort
	port, size  int
	count       uint32
	moves       int
	first, last time.Time
	fl          flow
}

// table counts datagrams per test. It is bounded: when it is full, idle
// entries are dropped and new tests are refused rather than evicting live
// ones, so a flood shows up as silence instead of as quietly wrong counts.
type table struct {
	mu      sync.Mutex
	m       map[key]*entry
	max     int
	ttl     time.Duration
	log     *logger
	refused int
	warned  time.Time
}

func newTable(limit int, ttl time.Duration, log *logger) *table {
	return &table{m: make(map[key]*entry), max: limit, ttl: ttl, log: log}
}

// hit counts one datagram and returns the count and the flow state its reply
// is built with.
func (t *table) hit(k key, src netip.AddrPort, port, size int, now time.Time) (uint32, flow, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[k]
	if e == nil {
		if len(t.m) >= t.max {
			t.expire(now, false)
		}
		if len(t.m) >= t.max {
			t.refused++
			if now.Sub(t.warned) >= time.Minute {
				t.warned = now
				t.log.write(event{Time: stamp(now), Event: "full", Tokens: len(t.m), Refused: t.refused})
			}
			return 0, flow{}, false
		}
		e = &entry{src: src, port: port, size: size, first: now, fl: *newFlow()}
		t.m[k] = e
		t.log.write(t.event("new", k, e, now))
	}
	if e.src != src {
		e.src = src
		e.moves++
	}
	e.count++
	e.last = now
	return e.count, e.fl.next(), true
}

// expire drops the entries idle for the ttl, or all of them, and logs each.
// The caller holds the lock.
func (t *table) expire(now time.Time, all bool) {
	for k, e := range t.m {
		if all || now.Sub(e.last) >= t.ttl {
			t.log.write(t.event("done", k, e, now))
			delete(t.m, k)
		}
	}
}

func (t *table) flush(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expire(now, true)
}

func (t *table) sweep(ctx context.Context) {
	tick := time.NewTicker(min(max(t.ttl/10, time.Second), time.Minute))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			t.mu.Lock()
			t.expire(now, false)
			t.mu.Unlock()
		}
	}
}

func (t *table) event(name string, k key, e *entry, now time.Time) event {
	ev := event{
		Time:  stamp(now),
		Event: name,
		Port:  e.port,
		Src:   netip.AddrPortFrom(e.src.Addr().Unmap(), e.src.Port()).String(),
		Token: hex.EncodeToString(k.token[:]),
		Form:  formByID(k.form).name,
		Size:  e.size,
	}
	if name == "done" {
		ev.Count = e.count
		ev.SrcChanges = e.moves
		ev.Seconds = e.last.Sub(e.first).Seconds()
	}
	return ev
}

type event struct {
	Time       string  `json:"time"`
	Event      string  `json:"event"`
	Addr       string  `json:"addr,omitempty"`
	Port       int     `json:"port,omitempty"`
	Src        string  `json:"src,omitempty"`
	Token      string  `json:"token,omitempty"`
	Form       string  `json:"form,omitempty"`
	Size       int     `json:"size,omitempty"`
	Count      uint32  `json:"count,omitempty"`
	SrcChanges int     `json:"src_changes,omitempty"`
	Seconds    float64 `json:"seconds,omitempty"`
	Tokens     int     `json:"tokens,omitempty"`
	Refused    int     `json:"refused,omitempty"`
}

type logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (l *logger) write(e event) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

func stamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
