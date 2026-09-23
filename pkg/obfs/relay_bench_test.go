//go:build unix

package obfs

import (
	"bytes"
	"io"
	"net"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Relay benchmarks: a tunnel over loopback TCP with the server copying to a
// target socket the way internal/relay does, so a change to the frame path
// shows its price in throughput and CPU per GiB on every PR.
//
// They run the client, the server and the target in one process. That is
// right for CPU and throughput and wrong for latency under load: one runtime
// schedules both ends, and the yield in Read/Write looked removable here
// while the process-level stand showed mixed p99 growing 4-80x without it
// (docs/benchmarks/yield.md). Latency claims go through
// scripts/performance-ab.py, not BenchmarkRelayMixedSmall.

const relayChunk = 32 * 1024

type relayTunnel struct {
	cli, srv   net.Conn
	target     net.Conn // the server's socket to the target
	targetPeer net.Conn // the target itself
}

func loopbackPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	return c, <-accepted
}

func newRelayTunnel(tb testing.TB) *relayTunnel {
	tb.Helper()
	cfg := Config{PSK: []byte("01234567890123456789012345678901"), MaxPadding: 256, MTU: 1400,
		KeepaliveMin: 10 * time.Second, KeepaliveMax: 20 * time.Second}
	a, b := loopbackPair(tb)
	cli, err := NewClientConn(a, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	srv, err := NewServerConn(b, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	t, tp := loopbackPair(tb)
	rt := &relayTunnel{cli: cli, srv: srv, target: t, targetPeer: tp}
	tb.Cleanup(rt.close)
	return rt
}

func (t *relayTunnel) close() {
	for _, c := range []net.Conn{t.cli, t.srv, t.target, t.targetPeer} {
		_ = c.Close()
	}
}

// open lets the server read the prologue, which it needs before it can send.
func (t *relayTunnel) open(tb testing.TB) {
	tb.Helper()
	if _, err := t.cli.Write([]byte{1}); err != nil {
		tb.Fatal(err)
	}
	if _, err := io.ReadFull(t.srv, make([]byte, 1)); err != nil {
		tb.Fatal(err)
	}
}

// relayCopy is internal/relay's copy: a 32 KiB buffer, no ReaderFrom/WriterTo.
func relayCopy(dst io.Writer, src io.Reader) {
	_, _ = io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, relayChunk))
}

func processCPU() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func reportCPUPerGiB(b *testing.B, since time.Duration, total int64) {
	b.ReportMetric((processCPU()-since).Seconds()/float64(total)*(1<<30), "cpu-s/GiB")
}

// Application -> client -> server -> relay -> target.
func BenchmarkRelayUpload(b *testing.B) {
	t := newRelayTunnel(b)
	go relayCopy(t.target, t.srv)
	payload := bytes.Repeat([]byte{0x5a}, relayChunk)
	total := int64(b.N) * relayChunk
	done := make(chan struct{})
	go func() { _, _ = io.CopyN(io.Discard, t.targetPeer, total); close(done) }()
	b.SetBytes(relayChunk)
	start := processCPU()
	b.ResetTimer()
	for range b.N {
		if _, err := t.cli.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-done
	b.StopTimer()
	reportCPUPerGiB(b, start, total)
}

// Target -> relay -> server -> client -> application.
func BenchmarkRelayDownload(b *testing.B) {
	t := newRelayTunnel(b)
	t.open(b)
	go relayCopy(t.srv, t.target)
	payload := bytes.Repeat([]byte{0xa5}, relayChunk)
	total := int64(b.N) * relayChunk
	done := make(chan struct{})
	go func() { relayCopy(io.Discard, io.LimitReader(t.cli, total)); close(done) }()
	b.SetBytes(relayChunk)
	start := processCPU()
	b.ResetTimer()
	for range b.N {
		if _, err := t.targetPeer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-done
	b.StopTimer()
	reportCPUPerGiB(b, start, total)
}

// A 200-byte request-response on one tunnel while another carries a
// continuous download. See the file comment before reading latency from it.
func BenchmarkRelayMixedSmall(b *testing.B) {
	bulk := newRelayTunnel(b)
	bulk.open(b)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { relayCopy(bulk.srv, bulk.target) })
	wg.Go(func() { relayCopy(io.Discard, bulk.cli) })
	wg.Go(func() {
		p := bytes.Repeat([]byte{7}, relayChunk)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := bulk.targetPeer.Write(p); err != nil {
				return
			}
		}
	})

	small := newRelayTunnel(b)
	go relayCopy(small.target, small.srv)
	go relayCopy(small.srv, small.target)
	go relayCopy(small.targetPeer, small.targetPeer)
	req, resp := bytes.Repeat([]byte{3}, 200), make([]byte, 200)
	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for range b.N {
		s := time.Now()
		if _, err := small.cli.Write(req); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(small.cli, resp); err != nil {
			b.Fatal(err)
		}
		lat = append(lat, time.Since(s))
	}
	b.StopTimer()
	close(stop)
	bulk.close()
	wg.Wait()
	slices.Sort(lat)
	q := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) }
	b.ReportMetric(q(0.5), "p50-us")
	b.ReportMetric(q(0.99), "p99-us")
}
