package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// loopbackServer runs the server on an ephemeral port and returns the port.
func loopbackServer(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := pc.(*net.UDPConn)
	_ = conn.SetReadBuffer(4 << 20)
	s := &server{table: newTable(4096, time.Minute, nil)}
	var wg sync.WaitGroup
	wg.Go(func() { s.serve(conn) })
	t.Cleanup(func() {
		conn.Close()
		wg.Wait()
	})
	return int(conn.LocalAddr().(*net.UDPAddr).AddrPort().Port())
}

func matrixConfig(t *testing.T, port int, reuse bool) probeConfig {
	t.Helper()
	args := []string{"-to", "127.0.0.1:" + strconv.Itoa(port), "-sizes", "100,1200", "-count", "20", "-rate", "200", "-drain", "3s"}
	if reuse {
		args = append(args, "-reuse")
	}
	cfg, err := parseProbe(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEveryFormCrossesLoopbackBothWays(t *testing.T) {
	port := loopbackServer(t)
	for _, reuse := range []bool{false, true} {
		cfg := matrixConfig(t, port, reuse)
		rows, err := runMatrix(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		// quic-initial has no 100-byte shape, every other form has both sizes.
		if len(rows) != 2*len(forms)-1 {
			t.Fatalf("reuse=%v: %d rows, want %d", reuse, len(rows), 2*len(forms)-1)
		}
		seen := map[string]bool{}
		srcPorts := map[int]bool{}
		for _, r := range rows {
			seen[r.Form] = true
			srcPorts[r.SrcPort] = true
			if r.Sent != 20 || r.Replies != 20 || r.ServerReceived == nil || *r.ServerReceived != 20 ||
				*r.UplinkPct != 100 || *r.DownlinkPct != 100 || r.RTTp50 == nil || r.RTTp95 == nil {
				t.Errorf("reuse=%v %s@%d: sent %d, server %v, replies %d", reuse, r.Form, r.Size, r.Sent, orQ(r.ServerReceived), r.Replies)
			}
		}
		if len(seen) != len(forms) {
			t.Errorf("reuse=%v: forms %v", reuse, seen)
		}
		if want := map[bool]int{false: len(rows), true: 1}[reuse]; len(srcPorts) != want {
			t.Errorf("reuse=%v: %d source ports, want %d", reuse, len(srcPorts), want)
		}
	}
}

func TestASustainedFlowIsReportedPerWindow(t *testing.T) {
	port := loopbackServer(t)
	cfg, err := parseProbe([]string{"-to", "127.0.0.1:" + strconv.Itoa(port), "-sustain", "wg@200",
		"-duration", "600ms", "-window", "200ms", "-rate", "100", "-drain", "300ms"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var windows []row
	total, err := runSustain(context.Background(), cfg, func(r row) { windows = append(windows, r) })
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 3 {
		t.Fatalf("%d windows, want 3", len(windows))
	}
	for _, w := range windows {
		if w.Sent != 20 || w.Replies != 20 || w.ServerReceived == nil || *w.ServerReceived != 20 || *w.UplinkPct != 100 {
			t.Errorf("window %d: sent %d, server %s, replies %d", *w.Window, w.Sent, orQ(w.ServerReceived), w.Replies)
		}
	}
	if total.Sent != 60 || total.Replies != 60 || *total.ServerReceived != 60 {
		t.Errorf("total: sent %d, server %s, replies %d", total.Sent, orQ(total.ServerReceived), total.Replies)
	}
}

func TestProbeFlagsAreChecked(t *testing.T) {
	for _, args := range []string{
		"",
		"-to 127.0.0.1",
		"-to :443",
		"-to 127.0.0.1:443,443",
		"-to 127.0.0.1:443,[::1]:444",
		"-to 127.0.0.1:0",
		"-to 127.0.0.1:443 -rate 0",
		"-to 127.0.0.1:443 -count 0",
		"-to 127.0.0.1:443 -sizes 0",
		"-to 127.0.0.1:443 -sizes 70000",
		"-to 127.0.0.1:443 -forms nosuch",
		"-to 127.0.0.1:443 -forms quic-initial -sizes 100",
		"-to 127.0.0.1:443 -duration 10s",
		"-to 127.0.0.1:443 -sustain wg@200 -forms random",
		"-to 127.0.0.1:443 -sustain wg@200 -count 5",
		"-to 127.0.0.1:443,444 -sustain wg@200",
		"-to 127.0.0.1:443 -sustain quic-initial@100",
		"-to 127.0.0.1:443 -sustain nosuch@100",
		"-to 127.0.0.1:443 -sustain wg",
		"-to 127.0.0.1:443 -sustain wg@200 -window 10ms -rate 50",
		"-to 127.0.0.1:443 -sustain wg@200 -duration 1s -window 5s",
		"-to 127.0.0.1:443 -count 1000000",
		"-to 127.0.0.1:443 -rate 2000",
	} {
		if _, err := parseProbe(strings.Fields(args), io.Discard); err == nil {
			t.Errorf("%q was accepted", args)
		}
	}

	cfg, err := parseProbe(strings.Fields("-to [::1]:443,444 -forms stun,random -sizes 1201,50"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.host != netip.MustParseAddr("::1") || len(cfg.cells) != 8 {
		t.Fatalf("host %v, %d tests", cfg.host, len(cfg.cells))
	}
	if c := cfg.cells[0]; c.port != 443 || c.form.name != "stun" || c.size != 1200 {
		t.Errorf("first test %d %s@%d, want 443 stun@1200", c.port, c.form.name, c.size)
	}
}

// lossyRelay stands between the probe and the server and drops the i-th
// datagram of each client flow, counted from zero, where up or down says so.
func lossyRelay(t *testing.T, server int, up, down func(i int) bool) int {
	t.Helper()
	var lc net.ListenConfig
	listen := func() *net.UDPConn {
		pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return pc.(*net.UDPConn)
	}
	front := listen()
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(server))
	type peer struct {
		back      *net.UDPConn
		ups, down int
	}
	var mu sync.Mutex
	peers := map[netip.AddrPort]*peer{}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 1<<16)
		for {
			n, src, err := front.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			mu.Lock()
			p := peers[src]
			if p == nil {
				p = &peer{back: listen()}
				peers[src] = p
				wg.Go(func() {
					b := make([]byte, 1<<16)
					for {
						n, _, err := p.back.ReadFromUDPAddrPort(b)
						if err != nil {
							return
						}
						mu.Lock()
						i := p.down
						p.down++
						mu.Unlock()
						if !down(i) {
							front.WriteToUDPAddrPort(b[:n], src)
						}
					}
				})
			}
			i := p.ups
			p.ups++
			mu.Unlock()
			if !up(i) {
				p.back.WriteToUDPAddrPort(buf[:n], dst)
			}
		}
	})
	t.Cleanup(func() {
		front.Close()
		mu.Lock()
		for _, p := range peers {
			p.back.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return int(front.LocalAddr().(*net.UDPAddr).AddrPort().Port())
}

// Loss on the way up and loss on the way down are told apart: the server's
// count carries the first, the replies that arrive the second.
func TestUplinkAndDownlinkLossAreToldApart(t *testing.T) {
	relay := lossyRelay(t, loopbackServer(t),
		func(i int) bool { return i%4 == 3 }, // 5 of 20 lost up
		func(i int) bool { return i%5 == 1 }, // 3 of the 15 replies lost down
	)
	cfg, err := parseProbe(strings.Fields("-to 127.0.0.1:"+strconv.Itoa(relay)+
		" -forms random,dtls,quic-initial -sizes 1200 -count 20 -rate 200 -drain 300ms"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := runMatrix(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Sent != 20 || r.ServerReceived == nil || *r.ServerReceived != 15 || r.Replies != 12 ||
			*r.UplinkPct != 75 || *r.DownlinkPct != 80 {
			t.Errorf("%s: sent %d, server %s, replies %d, up %s%%, down %s%%", r.Form, r.Sent, orQ(r.ServerReceived),
				r.Replies, fnum(r.UplinkPct, 1, "?"), fnum(r.DownlinkPct, 1, "?"))
		}
	}
}

// A path that cuts a flow after 30 datagrams shows up as a window at half
// delivery and then windows that know nothing, not as 50% spread evenly.
func TestASustainedFlowShowsWhereAPathCutsIt(t *testing.T) {
	relay := lossyRelay(t, loopbackServer(t), func(i int) bool { return i >= 30 }, func(int) bool { return false })
	cfg, err := parseProbe([]string{"-to", "127.0.0.1:" + strconv.Itoa(relay), "-sustain", "dtls@300",
		"-duration", "600ms", "-window", "200ms", "-rate", "100", "-drain", "300ms"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var windows []row
	total, err := runSustain(context.Background(), cfg, func(r row) { windows = append(windows, r) })
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 3 {
		t.Fatalf("%d windows", len(windows))
	}
	want := []struct {
		srv, replies int
		up           float64
	}{{20, 20, 100}, {10, 10, 50}}
	for i, w := range want {
		got := windows[i]
		if got.ServerReceived == nil || *got.ServerReceived != w.srv || got.Replies != w.replies || *got.UplinkPct != w.up {
			t.Errorf("window %d: server %s, replies %d, up %s%%", i, orQ(got.ServerReceived), got.Replies, fnum(got.UplinkPct, 1, "?"))
		}
	}
	if last := windows[2]; last.Replies != 0 || last.ServerReceived != nil || last.UplinkPct != nil {
		t.Errorf("window 2 after the cut: server %s, replies %d", orQ(last.ServerReceived), last.Replies)
	}
	if total.Sent != 60 || *total.ServerReceived != 30 || *total.UplinkPct != 50 || *total.DownlinkPct != 100 {
		t.Errorf("total: sent %d, server %s, up %s%%", total.Sent, orQ(total.ServerReceived), fnum(total.UplinkPct, 1, "?"))
	}
}
