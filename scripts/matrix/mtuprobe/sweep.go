package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sweepResult struct {
	Size    int                         `json:"size"`
	Mode    string                      `json:"mode"`
	Sent    int                         `json:"sent"`
	SendErr int                         `json:"send_errors,omitempty"`
	Up      int                         `json:"up"`
	UpBad   int                         `json:"up_bad,omitempty"`
	Asked   int                         `json:"asked"`
	Down    int                         `json:"down"`
	DownBad int                         `json:"down_bad,omitempty"`
	Kernel  map[string]map[string]int64 `json:"kernel,omitempty"`
	Metrics map[string]float64          `json:"metrics,omitempty"`
}

type sweepOut struct {
	Echo         string        `json:"echo"`
	SocksHeader  int           `json:"socks_header"`
	N            int           `json:"n"`
	GapUs        int64         `json:"gap_us"`
	WarmupMs     int64         `json:"warmup_ms,omitempty"`
	WarmupFailed bool          `json:"warmup_failed,omitempty"`
	ClosedAt     int           `json:"association_closed_at_size,omitempty"`
	Warmup       sweepResult   `json:"warmup"`
	Results      []sweepResult `json:"results"`
}

// replies counts the answers of the echo by run and size.
type replies struct {
	mu  sync.Mutex
	got map[countKey]*[2]int
}

func (r *replies) add(b []byte) {
	kind, run, size, _, ok := header(b)
	if !ok || kind != kindBack {
		return
	}
	r.mu.Lock()
	c := r.got[countKey{run, size}]
	if c == nil {
		c = new([2]int)
		r.got[countKey{run, size}] = c
	}
	if len(b) == size {
		c[0]++
	} else {
		c[1]++
	}
	r.mu.Unlock()
}

func (r *replies) at(run uint32, size int) (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.got[countKey{run, size}]; c != nil {
		return c[0], c[1]
	}
	return 0, 0
}

func runSweep(args []string) {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	socks := fs.String("socks", "", "SOCKS5 address of s5client; empty skips the tunnel")
	echo := fs.String("echo", "", "UDP address of the echo")
	bind := fs.String("bind", "", "local IP of the direct socket")
	mgmt := fs.String("mgmt", "", "base URL of the echo's counts")
	metrics := fs.String("metrics", "", "URL of the server metrics")
	netns := fs.String("netns", "A=self", "namespaces whose counters to read: name=pid,...")
	sizes := fs.String("sizes", "1200:1452:4", "first:last:step of the payload size")
	n := fs.Int("n", 200, "datagrams per size, each direction")
	gap := fs.Duration("gap", 500*time.Microsecond, "pause between pairs of datagrams")
	wait := fs.Duration("wait", 400*time.Millisecond, "wait after the last datagram of a size")
	warm := fs.Duration("warmup", 15*time.Second, "longest wait for native in both directions")
	modes := fs.String("modes", "tunnel,direct", "what to measure at each size")
	out := fs.String("out", "", "JSON output")
	must(fs.Parse(args))

	var lo, hi, step int
	if _, err := fmt.Sscanf(strings.ReplaceAll(*sizes, ":", " "), "%d %d %d", &lo, &hi, &step); err != nil || step <= 0 {
		panic("bad -sizes")
	}
	target, err := net.ResolveUDPAddr("udp", *echo)
	must(err)
	h := parseHosts(*netns)
	head := socksHeader(target)
	rep := &replies{got: map[countKey]*[2]int{}}
	res := sweepOut{Echo: *echo, N: *n, GapUs: gap.Microseconds()}
	base := rand.Uint32() &^ 0xff
	runs := map[string]uint32{"tunnel": base + 1, "direct": base + 2}

	var tun *socksUDP
	var closed <-chan struct{}
	var direct *net.UDPConn
	for _, m := range strings.Split(*modes, ",") {
		switch m {
		case "tunnel":
			tun, err = associate(*socks)
			must(err)
			closed = tun.closed()
			res.SocksHeader = len(head)
			go func() {
				b := make([]byte, 65535)
				for {
					d, err := tun.recv(b)
					if err != nil {
						return
					}
					rep.add(d)
				}
			}()
		case "direct":
			direct, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(*bind)})
			must(err)
			_ = direct.SetReadBuffer(8 << 20)
			_ = direct.SetWriteBuffer(8 << 20)
			go func() {
				b := make([]byte, 65535)
				for {
					n, _, err := direct.ReadFromUDP(b)
					if err != nil {
						return
					}
					rep.add(b[:n])
				}
			}()
		}
	}

	payload := make([]byte, 65535)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	ask := make([]byte, 32)
	wire := make([]byte, 0, 65535+32)
	send := func(mode string, b []byte) error {
		if mode == "tunnel" {
			return tun.send(wire, head, b)
		}
		_, err := direct.WriteToUDP(b, target)
		return err
	}
	// One size of one mode: n datagrams up and n requests for one down, paced.
	measure := func(mode string, run uint32, size, count int) sweepResult {
		r := sweepResult{Size: size, Mode: mode}
		k0 := h.read()
		var m0 map[string]float64
		if mode == "tunnel" {
			m0 = scrape(*metrics)
		}
		start := time.Now()
		for i := 0; i < count; i++ {
			putHeader(payload, kindUp, run, size, uint32(i))
			if send(mode, payload[:size]) != nil {
				r.SendErr++
			}
			putHeader(ask, kindAsk, run, size, uint32(i))
			if send(mode, ask) != nil {
				r.SendErr++
			}
			r.Sent++
			if d := time.Until(start.Add(time.Duration(i+1) * *gap)); d > 0 {
				time.Sleep(d)
			}
		}
		time.Sleep(*wait)
		r.Kernel = kernelDelta(k0, h.read())
		if mode == "tunnel" {
			r.Metrics = metricDelta(m0, scrape(*metrics))
		}
		return r
	}

	if tun != nil {
		// Native carries application datagrams only once a probe is answered,
		// and the server answers natively once the client says it hears it.
		start := time.Now()
		m0 := scrape(*metrics)
		warmRun := base + 3
		for i := 0; ; i++ {
			putHeader(ask, kindAsk, warmRun, 64, uint32(i))
			_ = tun.send(wire, head, ask)
			time.Sleep(20 * time.Millisecond)
			if i%5 == 4 {
				d := metricDelta(m0, scrape(*metrics))
				if metric(d, "s5core_native_udp_datagrams_total", `direction="from_client"`, `path="native"`) > 0 &&
					metric(d, "s5core_native_udp_datagrams_total", `direction="to_client"`, `path="native"`) > 0 {
					break
				}
			}
			if time.Since(start) > *warm {
				res.WarmupFailed = true
				break
			}
		}
		res.Warmup = measure("tunnel", warmRun, 64, 50)
		res.WarmupMs = time.Since(start).Milliseconds()
	}

	for size := lo; size <= hi; size += step {
		for _, mode := range strings.Split(*modes, ",") {
			if mode == "tunnel" && res.ClosedAt == 0 {
				select {
				case <-closed:
					res.ClosedAt = size
				default:
				}
			}
			res.Results = append(res.Results, measure(mode, runs[mode], size, *n))
		}
	}
	time.Sleep(500 * time.Millisecond)
	counts := map[uint32]map[string]count{}
	for _, run := range runs {
		counts[run] = fetchCounts(*mgmt, run)
	}
	for i := range res.Results {
		r := &res.Results[i]
		c := counts[runs[r.Mode]][strconv.Itoa(r.Size)]
		r.Up, r.UpBad, r.Asked = c.Up, c.UpBad, c.Asked
		r.Down, r.DownBad = rep.at(runs[r.Mode], r.Size)
	}
	if tun != nil {
		c := fetchCounts(*mgmt, base+3)["64"]
		res.Warmup.Up, res.Warmup.Asked = c.Up, c.Asked
		res.Warmup.Down, res.Warmup.DownBad = rep.at(base+3, 64)
		tun.Close()
	}
	writeJSON(*out, res)
}

func fetchCounts(base string, run uint32) map[string]count {
	resp, err := httpc.Get(fmt.Sprintf("%s/count?run=%d", base, run))
	if err != nil {
		fmt.Fprintln(os.Stderr, "counts:", err)
		return nil
	}
	defer resp.Body.Close()
	out := map[string]count{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
