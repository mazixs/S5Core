package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type stats struct {
	N        int                `json:"n"`
	Errors   int                `json:"errors"`
	P50      float64            `json:"p50_ms"`
	P90      float64            `json:"p90_ms"`
	P99      float64            `json:"p99_ms"`
	Max      float64            `json:"max_ms"`
	MBps     float64            `json:"mbps,omitempty"`
	SlowPct  float64            `json:"slow_pct,omitempty"`
	Bytes    int64              `json:"bytes,omitempty"`
	Seconds  float64            `json:"seconds,omitempty"`
	Aborted  string             `json:"aborted,omitempty"`
	Extra    map[string]float64 `json:"extra,omitempty"`
	FirstErr string             `json:"first_error,omitempty"`
	Series   []gameWindow       `json:"series,omitempty"`
}

// sample collects one metric of a scenario. An operation that fails because
// the scenario ran out of budget is cut, not failed: it says nothing about the
// tunnel, and the scenario is reported as aborted anyway.
type sample struct {
	mu    sync.Mutex
	ctx   context.Context
	slow  time.Duration
	d     []time.Duration
	errs  int
	cut   int
	inRow int
	err   string
}

func (p *prober) sample() *sample { return &sample{ctx: p.ctx, slow: p.slow} }

func (s *sample) add(d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.ctx != nil && s.ctx.Err() != nil {
			s.cut++
			return
		}
		s.errs++
		s.inRow++
		if s.err == "" {
			s.err = err.Error()
		}
		return
	}
	s.inRow = 0
	s.d = append(s.d, d)
}

// miss is a datagram that did not come back: not an error, but a dead
// association shows up as nothing but misses.
func (s *sample) miss() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inRow++
}

func (s *sample) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d, s.errs, s.cut, s.inRow, s.err = nil, 0, 0, 0, ""
}

func (s *sample) failing() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inRow
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (s *sample) stats() stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := stats{N: len(s.d), Errors: s.errs, FirstErr: s.err}
	if s.cut > 0 {
		st.Extra = map[string]float64{"cut": float64(s.cut)}
	}
	if len(s.d) == 0 {
		return st
	}
	d := slices.Clone(s.d)
	slices.Sort(d)
	q := func(p float64) float64 { return ms(d[int(p*float64(len(d)-1))]) }
	st.P50, st.P90, st.P99, st.Max = q(0.5), q(0.9), q(0.99), ms(d[len(d)-1])
	// Share of samples that paid a retransmission timeout: p99 under loss only says whether one landed in the top 1%.
	if s.slow > 0 {
		cut := d[len(d)/2] + s.slow
		st.SlowPct = 100 * float64(len(d)-sort.Search(len(d), func(i int) bool { return d[i] > cut })) / float64(len(d))
	}
	return st
}

type prober struct {
	socks    string
	o        *origin
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	maxInRow int
	slow     time.Duration
	control  bool

	ctx    context.Context
	cancel context.CancelFunc
	why    atomic.Pointer[string]
}

// begin opens the budget of one scenario.
func (p *prober) begin(budget time.Duration) {
	p.ctx, p.cancel = context.WithTimeout(context.Background(), budget)
	p.why.Store(nil)
}

// end closes the budget and says why the scenario stopped early, if it did.
func (p *prober) end() string {
	timedOut := p.ctx.Err() != nil
	p.cancel()
	if w := p.why.Load(); w != nil {
		return *w
	}
	if timedOut {
		return "timeout"
	}
	return ""
}

func (p *prober) stop(why string) {
	p.why.CompareAndSwap(nil, &why)
	p.cancel()
}

// next says whether a scenario loop may run one more operation: not past the
// budget and not after maxInRow failures in a row on s.
func (p *prober) next(s *sample) bool {
	if p.ctx.Err() != nil {
		return false
	}
	if p.maxInRow > 0 && s.failing() >= p.maxInRow {
		p.stop("errors")
		return false
	}
	return true
}

// sleep waits d or until the scenario is over and says whether it waited it out.
func (p *prober) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-p.ctx.Done():
		return false
	}
}

// web is one way to speak HTTP over TCP: "http" (HTTP/1.1), "https"
// (HTTP/1.1 over TLS 1.3) or "h2" (HTTP/2 over TLS 1.3).
type web struct {
	kind, addr string
}

func (p *prober) web(kind string) web {
	if kind == "http" {
		return web{kind, p.o.HTTP}
	}
	return web{kind, p.o.HTTPS}
}

func (w web) url(path string) string {
	if w.kind == "http" {
		return "http://" + w.addr + path
	}
	return "https://" + w.addr + path
}

func (p *prober) httpClient(reuse bool, conns int) *http.Client {
	return p.client(p.web("http"), reuse, conns, nil)
}

// client builds a client for w. With TLS there is no session cache, so every
// new connection is a full handshake; setup records the SOCKS5 connect plus
// the TLS handshake of each one.
func (p *prober) client(w web, reuse bool, conns int, setup *sample) *http.Client {
	tr := &http.Transport{DialContext: p.dial, DisableKeepAlives: !reuse, MaxIdleConnsPerHost: conns, ForceAttemptHTTP2: w.kind == "h2"}
	if w.kind != "http" {
		protos := []string{"http/1.1"}
		if w.kind == "h2" {
			protos = []string{"h2"}
		}
		host, _, _ := net.SplitHostPort(w.addr)
		cfg := &tls.Config{RootCAs: p.o.roots, MinVersion: tls.VersionTLS13, NextProtos: protos, ServerName: host}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			start := time.Now()
			c, err := p.dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(c, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = c.Close()
				return nil, err
			}
			if setup != nil {
				setup.add(time.Since(start), nil)
			}
			return tc, nil
		}
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}

// get returns time to first byte and to the end of a verified body.
func get(ctx context.Context, c *http.Client, url string, want []byte) (ttfb, total time.Duration, err error) {
	start := time.Now()
	var first time.Time
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { first = time.Now() }})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, err
	}
	total = time.Since(start)
	if resp.StatusCode != 200 || !bytes.Equal(body, want) {
		return 0, 0, fmt.Errorf("status %d, %d bytes", resp.StatusCode, len(body))
	}
	if first.IsZero() {
		first = time.Now()
	}
	return first.Sub(start), total, nil
}

func post(ctx context.Context, c *http.Client, url string, body []byte) (time.Duration, error) {
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 || string(got) != strconv.Itoa(len(body)) {
		return 0, fmt.Errorf("status %d, server saw %s bytes", resp.StatusCode, got)
	}
	return time.Since(start), nil
}

// h3 builds an HTTP/3 client whose every QUIC connection rides its own UDP
// association; dialMs records the association plus the QUIC handshake.
func (p *prober) h3(dialMs *sample) (*http.Client, *http3.Transport) {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: p.o.roots, MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 10 * time.Second},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			start := time.Now()
			pc, err := listenPacket(ctx, p.socks)
			if err != nil {
				return nil, err
			}
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			conn, err := quic.Dial(ctx, pc, ua, tlsCfg, cfg)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			if dialMs != nil {
				dialMs.add(time.Since(start), nil)
			}
			go func() { <-conn.Context().Done(); _ = pc.Close() }()
			return conn, nil
		},
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, tr
}

// opCtx bounds one operation: 60 s, and never past the scenario budget.
func (p *prober) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(p.ctx, 60*time.Second)
}

func (p *prober) tcpConnect(n int) stats {
	s := p.sample()
	msg := []byte("s5core-matrix-tcp-connect-probe!")
	for range n {
		if !p.next(s) {
			break
		}
		ctx, cancel := p.opCtx()
		start := time.Now()
		c, err := p.dial(ctx, "tcp", p.o.TCPEcho)
		if err == nil {
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			_, err = c.Write(msg)
			if err == nil {
				_, err = io.ReadFull(c, make([]byte, len(msg)))
			}
			stop()
			_ = c.Close()
		}
		s.add(time.Since(start), err)
		cancel()
	}
	st := s.stats()
	st.Bytes = int64(2 * st.N * len(msg))
	return st
}

func (p *prober) tcpEcho(n, size int) stats {
	s := p.sample()
	ctx, cancel := p.opCtx()
	c, err := p.dial(ctx, "tcp", p.o.TCPEcho)
	cancel()
	if err != nil {
		s.add(0, err)
		return s.stats()
	}
	defer func() { _ = c.Close() }()
	defer context.AfterFunc(p.ctx, func() { _ = c.Close() })()
	msg, buf := bytes.Repeat([]byte{0x42}, size), make([]byte, size)
	for range n {
		if !p.next(s) {
			break
		}
		start := time.Now()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err := c.Write(msg)
		if err == nil {
			_, err = io.ReadFull(c, buf)
		}
		s.add(time.Since(start), err)
		if err != nil {
			break
		}
	}
	st := s.stats()
	st.Bytes = int64(2 * st.N * size)
	return st
}

// protoCheck fails unless the origin saw the protocol w stands for: a
// transport that quietly fell back to HTTP/1.1 would measure the wrong thing.
func (p *prober) protoCheck(c *http.Client, w web) error {
	want := map[string]string{"http": "HTTP/1.1", "https": "HTTP/1.1", "h2": "HTTP/2.0"}[w.kind]
	ctx, cancel := p.opCtx()
	defer cancel()
	_, _, err := get(ctx, c, w.url("/proto"), []byte(want))
	return err
}

func (p *prober) webSmall(kind string, n int, reuse bool) stats {
	ttfb, total, setup := p.sample(), p.sample(), p.sample()
	w := p.web(kind)
	c := p.client(w, reuse, 1, setup)
	defer c.CloseIdleConnections()
	if err := p.protoCheck(c, w); err != nil {
		total.add(0, fmt.Errorf("protocol check: %w", err))
		return total.stats()
	}
	setup.reset()
	url := w.url("/small")
	for range n {
		if !p.next(total) {
			break
		}
		ctx, cancel := p.opCtx()
		f, t, err := get(ctx, c, url, smallBody)
		cancel()
		ttfb.add(f, err)
		total.add(t, err)
	}
	st := total.stats()
	tf := ttfb.stats()
	st.Extra = merge(st.Extra, map[string]float64{"ttfb_p50_ms": tf.P50, "ttfb_p99_ms": tf.P99})
	if su := setup.stats(); su.N > 0 {
		st.Extra["handshake_p50_ms"], st.Extra["handshake_p99_ms"] = su.P50, su.P99
	}
	st.Bytes = int64(st.N * len(smallBody))
	return st
}

func merge(a, b map[string]float64) map[string]float64 {
	if a == nil {
		return b
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}

func (p *prober) webLarge(kind string, n int, upload bool) stats {
	s := p.sample()
	w := p.web(kind)
	c := p.client(w, true, 1, nil)
	defer c.CloseIdleConnections()
	var sum time.Duration
	for range n {
		if !p.next(s) {
			break
		}
		ctx, cancel := p.opCtx()
		var t time.Duration
		var err error
		if upload {
			t, err = post(ctx, c, w.url("/upload"), largeBody)
		} else {
			_, t, err = get(ctx, c, w.url("/large"), largeBody)
		}
		cancel()
		s.add(t, err)
		sum += t
	}
	st := s.stats()
	if st.N > 0 {
		st.MBps = float64(st.N*largeSize) / sum.Seconds() / 1e6
	}
	st.Bytes = int64(st.N * largeSize)
	return st
}

// h2Shared measures small requests multiplexed on the same HTTP/2 connection
// as a download that never pauses, which is what a browser does with one
// origin: the small answers queue behind the bulk in every buffer on the way.
func (p *prober) h2Shared(n int) stats {
	w := p.web("h2")
	c := p.client(w, true, 1, nil)
	defer c.CloseIdleConnections()
	if err := p.protoCheck(c, w); err != nil {
		s := p.sample()
		s.add(0, fmt.Errorf("protocol check: %w", err))
		return s.stats()
	}
	return p.underLoadOn(c, w.url("/large"), func() stats {
		ttfb, total := p.sample(), p.sample()
		for range n {
			if !p.next(total) {
				break
			}
			ctx, cancel := p.opCtx()
			f, t, err := get(ctx, c, w.url("/small"), smallBody)
			cancel()
			ttfb.add(f, err)
			total.add(t, err)
		}
		st := total.stats()
		tf := ttfb.stats()
		st.Extra = merge(st.Extra, map[string]float64{"ttfb_p50_ms": tf.P50, "ttfb_p99_ms": tf.P99})
		st.Bytes = int64(st.N * len(smallBody))
		return st
	})
}

func (p *prober) h3Small(n int, reuse bool) stats {
	ttfb, total, dial := p.sample(), p.sample(), p.sample()
	url := "https://" + p.o.H3 + "/small"
	c, tr := p.h3(dial)
	for i := range n {
		if !p.next(total) {
			break
		}
		if !reuse && i > 0 {
			_ = tr.Close()
			c, tr = p.h3(dial)
		}
		ctx, cancel := p.opCtx()
		f, t, err := get(ctx, c, url, smallBody)
		cancel()
		ttfb.add(f, err)
		total.add(t, err)
	}
	_ = tr.Close()
	st := total.stats()
	tf, dl := ttfb.stats(), dial.stats()
	st.Extra = merge(st.Extra, map[string]float64{"ttfb_p50_ms": tf.P50, "ttfb_p99_ms": tf.P99, "handshake_p50_ms": dl.P50, "handshake_p99_ms": dl.P99})
	st.Bytes = int64(st.N * len(smallBody))
	return st
}

func (p *prober) h3Large(n int, upload bool) stats {
	s := p.sample()
	c, tr := p.h3(nil)
	defer func() { _ = tr.Close() }()
	var sum time.Duration
	for range n {
		if !p.next(s) {
			break
		}
		ctx, cancel := p.opCtx()
		var t time.Duration
		var err error
		if upload {
			t, err = post(ctx, c, "https://"+p.o.H3+"/upload", largeBody)
		} else {
			_, t, err = get(ctx, c, "https://"+p.o.H3+"/large", largeBody)
		}
		cancel()
		s.add(t, err)
		sum += t
	}
	st := s.stats()
	if st.N > 0 {
		st.MBps = float64(st.N*largeSize) / sum.Seconds() / 1e6
	}
	st.Bytes = int64(st.N * largeSize)
	return st
}

// udpRTT is a ping-pong: one datagram in flight, a reply later than the
// timeout counts as lost.
func (p *prober) udpRTT(n, size int) stats {
	s := p.sample()
	ctx, cancel := p.opCtx()
	pc, err := listenPacket(ctx, p.socks)
	cancel()
	if err != nil {
		s.add(0, err)
		return s.stats()
	}
	defer func() { _ = pc.Close() }()
	dst, _ := net.ResolveUDPAddr("udp", p.o.UDPEcho)
	msg, buf := make([]byte, size), make([]byte, 65535)
	lost, sent := 0, 0
	for i := range n {
		if !p.next(s) {
			break
		}
		sent++
		binary.BigEndian.PutUint64(msg, uint64(i))
		start := time.Now()
		if _, err := pc.WriteTo(msg, dst); err != nil {
			s.add(0, err)
			continue
		}
		deadline := start.Add(time.Second)
		for {
			_ = pc.SetReadDeadline(deadline)
			m, _, err := pc.ReadFrom(buf)
			if err != nil {
				lost++
				s.miss()
				break
			}
			if m == size && binary.BigEndian.Uint64(buf) == uint64(i) {
				s.add(time.Since(start), nil)
				break
			}
		}
	}
	st := s.stats()
	st.Extra = merge(st.Extra, map[string]float64{"loss_pct": 100 * float64(lost) / float64(max(sent, 1))})
	st.Bytes = int64(2 * st.N * size)
	return st
}

// udpStream sends paced datagrams and matches the echoes by sequence number.
func (p *prober) udpStream(n, size int, mbit float64) stats {
	s := p.sample()
	ctx, cancel := p.opCtx()
	pc, err := listenPacket(ctx, p.socks)
	cancel()
	if err != nil {
		s.add(0, err)
		return s.stats()
	}
	defer func() { _ = pc.Close() }()
	dst, _ := net.ResolveUDPAddr("udp", p.o.UDPEcho)
	gap := time.Duration(float64(size*8) / (mbit * 1e6) * float64(time.Second))
	sent := make([]int64, n)
	var got, reordered, dup atomic.Int64
	seen := make([]bool, n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		last := -1
		for {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			m, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if m != size {
				continue
			}
			seq := int(binary.BigEndian.Uint64(buf))
			if seq < 0 || seq >= n {
				continue
			}
			if seen[seq] {
				dup.Add(1)
				continue
			}
			seen[seq] = true
			got.Add(1)
			if seq < last {
				reordered.Add(1)
			}
			last = max(last, seq)
			s.add(time.Duration(time.Now().UnixNano()-atomic.LoadInt64(&sent[seq])), nil)
		}
	}()
	msg := make([]byte, size)
	start := time.Now()
	offered := 0
	for i := range n {
		if d := time.Until(start.Add(time.Duration(i) * gap)); d > 0 && !p.sleep(d) {
			break
		}
		if p.ctx.Err() != nil {
			break
		}
		binary.BigEndian.PutUint64(msg, uint64(i))
		atomic.StoreInt64(&sent[i], time.Now().UnixNano())
		_, _ = pc.WriteTo(msg, dst)
		offered++
	}
	elapsed := time.Since(start)
	<-done
	st := s.stats()
	st.MBps = float64(got.Load()) * float64(size) / elapsed.Seconds() / 1e6
	st.Extra = merge(st.Extra, map[string]float64{"loss_pct": 100 * float64(int64(offered)-got.Load()) / float64(max(offered, 1)), "reordered": float64(reordered.Load()), "duplicates": float64(dup.Load()), "offered_mbit": mbit})
	st.Bytes = 2 * got.Load() * int64(size)
	return st
}

// underLoad measures fn while another connection of the given kind downloads
// without pause.
func (p *prober) underLoad(kind string, fn func() stats) stats {
	w := p.web(kind)
	c := p.client(w, true, 1, nil)
	defer c.CloseIdleConnections()
	return p.underLoadOn(c, w.url("/large"), fn)
}

// underLoadOn measures fn while c downloads url without pause. background_MBps
// counts completed bodies only, so a run of fn shorter than one body reads 0.
func (p *prober) underLoadOn(c *http.Client, url string, fn func() stats) stats {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bulkErr atomic.Value
	var bulkBytes atomic.Int64
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctx, cancel := p.opCtx()
			_, _, err := get(ctx, c, url, largeBody)
			cancel()
			if err != nil {
				if p.ctx.Err() == nil {
					bulkErr.Store(err.Error())
				}
				return
			}
			bulkBytes.Add(largeSize)
		}
	})
	p.sleep(200 * time.Millisecond)
	start, from := time.Now(), bulkBytes.Load()
	st := fn()
	elapsed, moved := time.Since(start), bulkBytes.Load()-from
	close(stop)
	wg.Wait()
	if st.Extra == nil {
		st.Extra = map[string]float64{}
	}
	st.Extra["background_MBps"] = float64(moved) / elapsed.Seconds() / 1e6
	st.Bytes += bulkBytes.Load()
	if e, ok := bulkErr.Load().(string); ok {
		st.Errors++
		if st.FirstErr == "" {
			st.FirstErr = "background: " + e
		} else {
			st.FirstErr = errors.Join(errors.New(st.FirstErr), errors.New("background: "+e)).Error()
		}
	}
	return st
}
